package certdb

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/google/certificate-transparency/go"
	"golang.org/x/crypto/ocsp"
)

// OID of the SCT extension
var sctExtOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// TODO: (?) Write function to retrieve a []ct.SignedCertificateTimestamp. How
// to decide which SCT to return in order to "dynamically select an appropriate
// single SCT to conserve bandwidth"?
// https://www.certificate-transparency.org/faq

// StapleSCTList inserts a list of Signed Certificate Timestamps into all OCSP
// responses in a database wrapped by a given certdb.Accessor.
//
// TODO: Add an error return value.
//
// NOTE: Returns a bool indicating whether the SCT was successfully inserted
// into ALL corresponding OCSPRecords (i.e. one failure results in a return
// value of false).
// NOTE: This function is patterned after the exported Sign method in
// https://github.com/cloudflare/cfssl/blob/master/signer/local/local.go
func StapleSCTList(acc Accessor, serial, aki string, scts []ct.SignedCertificateTimestamp, priv crypto.Signer) error {
	// Grab all OCSP records that match serial and aki
	ocspRecs, err := acc.GetOCSP(serial, aki)
	if err != nil {
		// { There was an error }
		return err
	}

	if len(ocspRecs) == 0 {
		// { OCSPRecord does not exist }
		return cferr.Wrap(cferr.CertStoreError, cferr.RecordNotFound, errors.New("empty OCSPRecord"))
	}

	// Add the SCTs to each ocsp response
	for _, rec := range ocspRecs {
		// NOTE: Assuming that rec.Body is in base64-encoded DER form
		// based on
		// https://github.com/cloudflare/cfssl/blob/master/ocsp/responder.go#L54
		der, err := base64.StdEncoding.DecodeString(rec.Body)
		if err != nil {
			// { decoding error }
			return cferr.Wrap(cferr.CertificateError, cferr.DecodeFailed,
				errors.New("failed to decode Base64-encoded OCSP response"))
		}

		response, err := ocsp.ParseResponse(der, nil)
		if err != nil {
			// { parsing error }
			return cferr.Wrap(cferr.CertificateError, cferr.ParseFailed,
				errors.New("failed to parse DER-encoded OCSP response"))
		}

		// Serialize the list of SCTs
		serializedSCTList, err := helpers.SerializeSCTList(scts)
		if err != nil {
			// { serializing error }
			return cferr.Wrap(cferr.CTError, cferr.Unknown,
				errors.New("failed to serialize SCT list"))
		}

		serializedSCTList, err = asn1.Marshal(serializedSCTList)
		if err != nil {
			// { serializing error }
			return cferr.Wrap(cferr.CTError, cferr.Unknown,
				errors.New("failed to serialize SCT list"))
		}

		// Add the SCT list to a new extension
		//
		// The body of the extension should be a
		// SignedCertificateTimestampList ::= OCTET STRING (see RFC
		// 6962 sec 3.3)
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

		if idxExt < len(response.Extensions) {
			// { there's an existing SCT extension in response.Extensions }
			// Replace the old extension in the OCSP response
			response.Extensions[idxExt] = sctExtension
		} else {
			// { there's no SCT extension in response.Extensions }
			response.Extensions = append(response.Extensions, sctExtension)
		}

		// Write updated extensions to replace existing extensions in
		// response when re-marshalling
		response.ExtraExtensions = response.Extensions

		// Re-sign response to generate the new DER-encoded response
		der, err = ocsp.CreateResponse(nil, response.Certificate, *response, priv)

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
