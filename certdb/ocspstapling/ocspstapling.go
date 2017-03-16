// Package ocspstapling implements OCSP stapling of Signed Certificate
// Timestamps (SCTs) into OCSP responses in a database. See RFC 6962.
package ocspstapling

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cloudflare/cfssl/certdb"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/google/certificate-transparency/go"
	"golang.org/x/crypto/ocsp"
)

// OID of the SCT extension
var sctExtOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// StapleSCTList inserts a list of Signed Certificate Timestamps into all OCSP
// responses in a database wrapped by a given certdb.Accessor.
//
// NOTE: This function is patterned after the exported Sign method in
// https://github.com/cloudflare/cfssl/blob/master/signer/local/local.go
func StapleSCTList(acc certdb.Accessor, serial, aki string, scts []ct.SignedCertificateTimestamp, issuer *x509.Certificate, priv crypto.Signer) error {
	// Grab all OCSP records that match serial and aki
	ocspRecs, err := acc.GetOCSP(serial, aki)
	if err != nil {
		return err
	}

	if len(ocspRecs) == 0 {
		// { OCSPRecord does not exist }
		return cferr.Wrap(cferr.CertStoreError, cferr.RecordNotFound, errors.New("empty OCSPRecord"))
	}

	// Add the SCTs to each ocsp response
	for _, rec := range ocspRecs {
		der, err := base64.StdEncoding.DecodeString(rec.Body)
		if err != nil {
			return cferr.Wrap(cferr.CertificateError, cferr.DecodeFailed,
				errors.New("failed to decode Base64-encoded OCSP response"))
		}

		response, err := ocsp.ParseResponse(der, nil)
		if err != nil {
			return cferr.Wrap(cferr.CertificateError, cferr.ParseFailed,
				errors.New("failed to parse DER-encoded OCSP response"))
		}

		// Serialize the list of SCTs
		serializedSCTList, err := helpers.SerializeSCTList(scts)
		if err != nil {
			return cferr.Wrap(cferr.CTError, cferr.Unknown,
				errors.New("failed to serialize SCT list"))
		}

		serializedSCTList, err = asn1.Marshal(serializedSCTList)
		if err != nil {
			return cferr.Wrap(cferr.CTError, cferr.Unknown,
				errors.New("failed to serialize SCT list"))
		}

		// Add the SCT list to a new extension
		sctExtension := pkix.Extension{
			Id:       sctExtOid,
			Critical: false,
			Value:    serializedSCTList,
		}

		// Find the SCTListExtension in the ocsp response
		var idxExt int
		for _, ext := range response.Extensions {
			if ext.Id.Equal(sctExtOid) {
				break
			}
			idxExt++
		}

		newExtensions := response.Extensions
		if idxExt >= len(response.Extensions) {
			// { there's no SCT extension in response.Extensions }
			newExtensions = append(newExtensions, sctExtension)
		}

		// Write updated extensions to replace existing extensions in
		// response when re-marshalling
		fmt.Println(response.Certificate) // TODO: DELETE ME
		template := ocsp.Response{
			Status:          response.Status,
			SerialNumber:    response.Certificate.SerialNumber,
			ThisUpdate:      response.ThisUpdate,
			NextUpdate:      response.NextUpdate,
			Certificate:     response.Certificate,
			ExtraExtensions: newExtensions,
			IssuerHash:      response.IssuerHash,
		}

		// Re-sign response to generate the new DER-encoded response
		der, err = ocsp.CreateResponse(issuer, response.Certificate, template, priv)

		if err != nil {
			return cferr.Wrap(cferr.CTError, cferr.Unknown,
				errors.New("failed to sign new OCSP response"))
		}

		body := base64.StdEncoding.EncodeToString(der)
		err = acc.UpdateOCSP(serial, aki, body, rec.Expiry)

		if err != nil {
			return err
		}
	}

	return nil
}
