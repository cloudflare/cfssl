// +build ctclient

package ctclient

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"crypto/x509"

	"github.com/cloudflare/cfssl/log"
	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"

	cferr "github.com/cloudflare/cfssl/errors"
)

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

func GetSCTList(cert []byte, caCert x509.Certificate, logServers []string) (serializedSCTList []byte, err error) {
	derCert, _ := pem.Decode(cert)
	prechain := []ct.ASN1Cert{derCert.Bytes, caCert.Raw}
	var sctList []ct.SignedCertificateTimestamp

	for _, server := range logServers {
		log.Infof("submitting poisoned precertificate to %s", server)
		var ctclient = client.New(server)
		resp, err := ctclient.AddPreChain(prechain)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.PrecertSubmissionFailed, err)
		}
		sctList = append(sctList, *resp)
	}

	serializedSCTList, err = serializeSCTList(sctList)

	if err != nil {
		return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
	}

	// Serialize again as an octet string before embedding
	serializedSCTList, err = asn1.Marshal(serializedSCTList)
	if err != nil {
		return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
	}
}
