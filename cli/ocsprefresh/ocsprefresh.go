// Package ocsprefresh implements the ocsprefresh command.
package ocsprefresh

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/cli"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/google/certificate-transparency/go"
)

// Usage text of 'cfssl ocsprefresh'
var ocsprefreshUsageText = `cfssl ocsprefresh -- refreshes the ocsp_responses table
with new OCSP responses for all known unexpired certificates

Usage of ocsprefresh:
        cfssl ocsprefresh -db-config db-config -ca cert -responder cert -responder-key key [-interval 96h]

Flags:
`

// Flags of 'cfssl ocsprefresh'
var ocsprefreshFlags = []string{"ca", "responder", "responder-key", "db-config", "interval"}

// sctExtOid is the OID of the OCSP Stapling SCT extension (see section 3.3. of RFC 6962).
var sctExtOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}

// ocsprefreshMain is the main CLI of OCSP refresh functionality.
func ocsprefreshMain(args []string, c cli.Config) error {
	if c.DBConfigFile == "" {
		return errors.New("need DB config file (provide with -db-config)")
	}

	if c.ResponderFile == "" {
		return errors.New("need responder certificate (provide with -responder)")
	}

	if c.ResponderKeyFile == "" {
		return errors.New("need responder key (provide with -responder-key)")
	}

	if c.CAFile == "" {
		return errors.New("need CA certificate (provide with -ca)")
	}

	s, err := SignerFromConfig(c)
	if err != nil {
		log.Critical("Unable to create OCSP signer: ", err)
		return err
	}

	db, err := dbconf.DBFromConfig(c.DBConfigFile)
	if err != nil {
		return err
	}

	dbAccessor := sql.NewAccessor(db)
	certs, err := dbAccessor.GetUnexpiredCertificates()
	if err != nil {
		return err
	}

	// Set an expiry timestamp for all certificates refreshed in this batch
	ocspExpiry := time.Now().Add(c.Interval)
	for _, certRecord := range certs {
		cert, err := helpers.ParseCertificatePEM([]byte(certRecord.PEM))
		if err != nil {
			log.Critical("Unable to parse certificate: ", err)
			return err
		}

		// Gather the certificate's SCTs for stapling to the OCSP response.
		sctRecords, err := dbAccessor.GetSCT(certRecord.Serial, certRecord.AKI)
		if err != nil {
			return err
		}

		var sctExtension []pkix.Extension
		if len(sctRecords) != 0 {
			serializedSCTList, err := serializeSCTRecords(sctRecords)
			if err != nil {
				log.Critical(err)
				return err
			}
			sctExtension = []pkix.Extension{{
				Id:       sctExtOid,
				Critical: false,
				Value:    serializedSCTList,
			}}
		}

		req := ocsp.SignRequest{
			Certificate: cert,
			Status:      certRecord.Status,
			Extensions:  sctExtension,
		}

		if certRecord.Status == "revoked" {
			req.Reason = int(certRecord.Reason)
			req.RevokedAt = certRecord.RevokedAt
		}

		resp, err := s.Sign(req)
		if err != nil {
			log.Critical("Unable to sign OCSP response: ", err)
			return err
		}

		err = dbAccessor.UpsertOCSP(cert.SerialNumber.String(), hex.EncodeToString(cert.AuthorityKeyId), string(resp), ocspExpiry)
		if err != nil {
			log.Critical("Unable to save OCSP response: ", err)
			return err
		}
	}

	return nil
}

// SignerFromConfig creates a signer from a cli.Config as a helper for cli and serve
func SignerFromConfig(c cli.Config) (ocsp.Signer, error) {
	//if this is called from serve then we need to use the specific responder key file
	//fallback to key for backwards-compatibility
	k := c.ResponderKeyFile
	if k == "" {
		k = c.KeyFile
	}
	return ocsp.NewSignerFromFile(c.CAFile, c.ResponderFile, k, time.Duration(c.Interval))
}

// serializeSCTRecords converts a slice of certdb.SCTRecords into an ASN.1
// encoded SCT list.
func serializeSCTRecords(sctRecords []certdb.SCTRecord) ([]byte, error) {
	var scts []ct.SignedCertificateTimestamp

	for _, sctRecord := range sctRecords {
		serializedSCT, err := hex.DecodeString(sctRecord.Body)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.Unknown,
				fmt.Errorf("failed to deserialize SCT: %s", err))
		}
		sct, err := ct.DeserializeSCT(bytes.NewReader(serializedSCT))
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.SCTListDecodeFailed,
				fmt.Errorf("failed to deserialize SCT: %s", err))
		}
		sctCopy := *sct
		scts = append(scts, sctCopy)
	}

	serializedSCTList, err := helpers.SerializeSCTList(scts)
	if err != nil {
		return nil, err
	}

	return serializedSCTList, nil
}

// Command assembles the definition of Command 'ocsprefresh'
var Command = &cli.Command{UsageText: ocsprefreshUsageText, Flags: ocsprefreshFlags, Main: ocsprefreshMain}
