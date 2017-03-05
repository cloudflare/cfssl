package certdb

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
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
func StapleSCTList(acc Accessor, serial, aki string, scts []ct.SignedCertificateTimestamp) bool {
	// Grab all OCSP records that match serial and aki
	ocspRecs, err := acc.GetOCSP(serial, aki)
	if err != nil || len(ocspRecs) == 0 {
		// { There was an error or the OCSPRecord does not exist }
		return false
	}

	// Add the SCTs to each ocsp response
	for _, rec := range ocspRecs {
		// NOTE: Assuming that rec.Body is in base64-encoded DER form
		// based on
		// https://github.com/cloudflare/cfssl/blob/master/ocsp/responder.go#L54
		der, err := base64.StdEncoding.DecodeString(rec.Body)
		if err != nil {
			// { decoding error }
			return false
		}

		response, err := ocsp.ParseResponse(der, nil)
		if err != nil {
			// { parsing error }
			return false
		}

		// Find the SCTListExtension in the ocsp response
		var SCTListExtension, ext pkix.Extension
		var idxExt int
		for idxExt, ext = range response.Extensions {
			if ext.Id.Equal(sctExtOid) {
				SCTListExtension = ext
				break
			}
		}

		// Extract the sctList from the extension
		var sctList []ct.SignedCertificateTimestamp
		if SCTListExtension.Value != nil {
			// Extract the SCTList
			var serializedSCTList []byte
			rest := SCTListExtension.Value
			// TODO: Is it correct to pass in the same slice to
			// multiple calls of Unmarshal?
			for len(rest) != 0 {
				rest, err = asn1.Unmarshal(rest, &serializedSCTList)
				if err != nil {
					// { unmarshaling error }
					return false
				}
			}
			desList, err := deserializeSCTList(serializedSCTList)
			if err != nil {
				// { deserializing error }
				return false
			}
			sctList = desList
		}

		// Append the new SCTs to the list
		sctList = append(sctList, scts...)

		// Re-serialize the list of SCTs
		serializedSCTList, err := serializeSCTList(sctList)
		if err != nil {
			// { serializing error }
			return false
		}

		serializedSCTList, err = asn1.Marshal(serializedSCTList)
		if err != nil {
			// { serializing error }
			return false
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

		// Replace the old extension in the OCSP response
		response.Extensions[idxExt] = sctExtension
		der, err = ocsp.CreateResponse(nil, response.Certificate, *response, nil)
		body := base64.StdEncoding.EncodeToString(der)
		err = acc.UpdateOCSP(serial, aki, body, rec.Expiry)
	}

	return true
}

// Copied from
// https://github.com/cloudflare/cfssl/blob/master/signer/local/local.go
// because of dependency cycle
func serializeSCTList(sctList []ct.SignedCertificateTimestamp) ([]byte, error) {
	var buf bytes.Buffer
	for _, sct := range sctList {
		sct, err := ct.SerializeSCT(sct)
		if err != nil {
			return nil, err
		}
		binary.Write(&buf, binary.BigEndian, uint16(len(sct)))
		buf.Write(sct)
	}

	var sctListLengthField = make([]byte, 2)
	binary.BigEndian.PutUint16(sctListLengthField, uint16(buf.Len()))
	return bytes.Join([][]byte{sctListLengthField, buf.Bytes()}, nil), nil
}

func deserializeSCTList(serializedSCTList []byte) ([]ct.SignedCertificateTimestamp, error) {
	var sctList []ct.SignedCertificateTimestamp
	sctReader := bytes.NewReader(serializedSCTList)

	for sctReader.Len() != 0 {
		sct, err := ct.DeserializeSCT(sctReader)
		if err != nil {
			return nil, err
		}
		sctList = append(sctList, *sct)
	}

	return sctList, nil
}
