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

// StapleSCTList inserts a list of Signed Certificate Timestamps into all OCSP
// responses in a database wrapped by a given certdb.Accessor.
//
// TODO: Should acc be passed by pointer or value (does it matter in this
// context)?
// TODO: Should this function take a ct.SignedCertificateTimestamp or just a
// []byte containing that data?
// InsertSCT takes an SCT and staples it to a given OCSP response
// NOTE: Returns a bool indicating whether the SCT was successfully inserted
// into ALL corresponding OCSPRecords (i.e. one failure results in a return
// value of false).
// NOTE: This function is patterned after the exported Sign(...) method in
// https://github.com/cloudflare/cfssl/blob/master/signer/local/local.go
func StapleSCTList(acc Accessor, serial, aki string, scts []ct.SignedCertificateTimestamp) bool {
	// TODO: Get the OCSP response body first, APPEND the provided SCT to
	// the []ct.SignedCertificateTimstamp, encode it as an octet string,
	// and call acc.UpdateOCSP(...) with the new body
	ocspRecs, err := acc.GetOCSP(serial, aki)
	if err != nil || len(ocspRecs) == 0 {
		// { Ther was an error or the OCSPRecord does not exist }
		return false
	}

	// NOTE: Shoud I be grabbing just the 0th record, a particular record,
	// or all of them?
	for _, rec := range ocspRecs {
		// TODO: extract the ocsp request from rec.Body
		// NOTE: I am assuming that rec.Body is in base64-encoded DER
		// form based on
		// https://github.com/cloudflare/cfssl/blob/master/ocsp/responder.go#L54
		der, err := base64.StdEncoding.DecodeString(rec.Body)
		if err != nil {
			// TODO: (?) return a decode error
			return false
		}

		response, err := ocsp.ParseResponse(der, nil)
		if err != nil {
			// TODO: (?) return a parse error
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
					return false
				}
			}
			desList, err := deserializeSCTList(serializedSCTList)
			if err != nil {
				// TODO: (?) return an error?
				return false
			}
			sctList = desList
		}

		// Append the new SCTs to the list
		sctList = append(sctList, scts...)

		// Re-serialize the list of SCTs
		serializedSCTList, err := serializeSCTList(sctList)
		if err != nil {
			// TODO: (?) return an error
			return false
		}

		serializedSCTList, err = asn1.Marshal(serializedSCTList)
		if err != nil {
			// TODO: (?) return error
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

		// replace the old extension in the OCSP response
		response.Extensions[idxExt] = sctExtension
		der, err = ocsp.CreateResponse(nil, response.Certificate, *response, nil)
		body := base64.StdEncoding.EncodeToString(der)
		err = acc.UpdateOCSP(serial, aki, body, rec.Expiry)
	}

	return true
}

// TODO: (?) function to retrieve a []ct.SignedCertificateTimestamp. How to
// decide which SCT to return in order to "dynamically select an appropriate
// single SCT to conserve bandwidth"
// (https://www.certificate-transparency.org/faq)?

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
