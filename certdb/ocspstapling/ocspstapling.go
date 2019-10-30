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

	"github.com/cloudflare/cfssl/certdb"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/ocsp"
)

// sctExtOid is the OID of the OCSP Stapling SCT extension (see section 3.3. of RFC 6962).
var sctExtOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}

// StapleSCTList inserts a list of Signed Certificate Timestamps into all OCSP
// responses in a database wrapped by a given certdb.Accessor.
//
// NOTE: This function is patterned after the exported Sign method in
// https://github.com/cloudflare/cfssl/blob/master/signer/local/local.go
func StapleSCTList(acc certdb.Accessor, serial, aki string, scts []ct.SignedCertificateTimestamp,
	responderCert, issuer *x509.Certificate, priv crypto.Signer) error {
	ocspRecs, err := acc.GetOCSP(serial, aki)
	if err != nil {
		return err
	}

	if len(ocspRecs) == 0 {
		return cferr.Wrap(cferr.CertStoreError, cferr.RecordNotFound, errors.New("empty OCSPRecord"))
	}

	// This loop adds the SCTs to each OCSP response in ocspRecs.
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

		sctExtension := pkix.Extension{
			Id:       sctExtOid,
			Critical: false,
			Value:    serializedSCTList,
		}

		// This loop finds the SCTListExtension in the ocsp response.
		var idxExt int
		for _, ext := range response.Extensions {
			if ext.Id.Equal(sctExtOid) {
				break
			}
			idxExt++
		}

		newExtensions := make([]pkix.Extension, len(response.Extensions))
		copy(newExtensions, response.Extensions)
		if idxExt >= len(response.Extensions) {
			// No SCT extension was found.
			newExtensions = append(newExtensions, sctExtension)
		} else {
			newExtensions[idxExt] = sctExtension
		}

		// Here we write the updated extensions to replace the old
		// response extensions when re-marshalling.
		newSN := *response.SerialNumber
		template := ocsp.Response{
			Status:          response.Status,
			SerialNumber:    &newSN,
			ThisUpdate:      response.ThisUpdate,
			NextUpdate:      response.NextUpdate,
			Certificate:     response.Certificate,
			ExtraExtensions: newExtensions,
			IssuerHash:      response.IssuerHash,
		}

		// Finally, we re-sign the response to generate the new
		// DER-encoded response.
		der, err = ocsp.CreateResponse(issuer, responderCert, template, priv)
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
