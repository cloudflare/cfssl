// Package local implements certificate signature functionality for CFSSL.
package local

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net"
	"net/mail"

	"database/sql"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
)

// Signer contains a signer that uses the standard library to
// support both ECDSA and RSA CA keys.
type Signer struct {
	ca      *x509.Certificate
	priv    crypto.Signer
	policy  *config.Signing
	sigAlgo x509.SignatureAlgorithm
	db      *sql.DB
}

// NewSigner creates a new Signer directly from a
// private key and certificate, with optional policy.
func NewSigner(priv crypto.Signer, cert *x509.Certificate, sigAlgo x509.SignatureAlgorithm, policy *config.Signing) (*Signer, error) {
	if policy == nil {
		policy = &config.Signing{
			Profiles: map[string]*config.SigningProfile{},
			Default:  config.DefaultConfig()}
	}

	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}

	return &Signer{
		ca:      cert,
		priv:    priv,
		sigAlgo: sigAlgo,
		policy:  policy,
		db:      nil,
	}, nil
}

// NewSignerFromFile generates a new local signer from a caFile
// and a caKey file, both PEM encoded.
func NewSignerFromFile(caFile, caKeyFile string, policy *config.Signing) (*Signer, error) {
	log.Debug("Loading CA: ", caFile)
	ca, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	log.Debug("Loading CA key: ", caKeyFile)
	cakey, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ReadFailed, err)
	}

	parsedCa, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, err
	}

	priv, err := helpers.ParsePrivateKeyPEM(cakey)
	if err != nil {
		log.Debug("Malformed private key %v", err)
		return nil, err
	}

	return NewSigner(priv, parsedCa, signer.DefaultSigAlgo(priv), policy)
}

func (s *Signer) sign(template *x509.Certificate, profile *config.SigningProfile) (cert []byte, err error) {
	err = signer.FillTemplate(template, s.policy.Default, profile)
	if err != nil {
		return
	}

	var initRoot bool
	if s.ca == nil {
		if !template.IsCA {
			err = cferr.New(cferr.PolicyError, cferr.InvalidRequest)
			return
		}
		template.DNSNames = nil
		s.ca = template
		initRoot = true
		template.MaxPathLen = signer.MaxPathLen
	} else if template.IsCA {
		template.MaxPathLen = 1
		template.DNSNames = nil
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, s.ca, template.PublicKey, s.priv)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	}
	if initRoot {
		s.ca, err = x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, err)
		}
	}

	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	log.Infof("signed certificate with serial number %d", template.SerialNumber)
	return
}

// replaceSliceIfEmpty replaces the contents of replaced with newContents if
// the slice referenced by replaced is empty
func replaceSliceIfEmpty(replaced, newContents *[]string) {
	if len(*replaced) == 0 {
		*replaced = *newContents
	}
}

// PopulateSubjectFromCSR has functionality similar to Name, except
// it fills the fields of the resulting pkix.Name with req's if the
// subject's corresponding fields are empty
func PopulateSubjectFromCSR(s *signer.Subject, req pkix.Name) pkix.Name {
	// if no subject, use req
	if s == nil {
		return req
	}

	name := s.Name()

	if name.CommonName == "" {
		name.CommonName = req.CommonName
	}

	replaceSliceIfEmpty(&name.Country, &req.Country)
	replaceSliceIfEmpty(&name.Province, &req.Province)
	replaceSliceIfEmpty(&name.Locality, &req.Locality)
	replaceSliceIfEmpty(&name.Organization, &req.Organization)
	replaceSliceIfEmpty(&name.OrganizationalUnit, &req.OrganizationalUnit)

	return name
}

// OverrideHosts fills template's IPAddresses, EmailAddresses, and DNSNames with the
// content of hosts, if it is not nil.
func OverrideHosts(template *x509.Certificate, hosts []string) {
	if hosts != nil {
		template.IPAddresses = []net.IP{}
		template.EmailAddresses = []string{}
		template.DNSNames = []string{}
	}

	for i := range hosts {
		if ip := net.ParseIP(hosts[i]); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(hosts[i]); err == nil && email != nil {
			template.EmailAddresses = append(template.EmailAddresses, email.Address)
		} else {
			template.DNSNames = append(template.DNSNames, hosts[i])
		}
	}

}

// Sign signs a new certificate based on the PEM-encoded client
// certificate or certificate request with the signing profile,
// specified by profileName.
func (s *Signer) Sign(req signer.SignRequest) (cert []byte, err error) {
	profile, err := signer.Profile(s, req.Profile)
	if err != nil {
		return
	}

	block, _ := pem.Decode([]byte(req.Request))
	if block == nil {
		return nil, cferr.New(cferr.CSRError, cferr.DecodeFailed)
	}

	if block.Type != "CERTIFICATE REQUEST" {
		return nil, cferr.Wrap(cferr.CSRError,
			cferr.BadRequest, errors.New("not a certificate or csr"))
	}

	csrTemplate, err := signer.ParseCertificateRequest(s, block.Bytes)
	if err != nil {
		return nil, err
	}

	// Copy out only the fields from the CSR authorized by policy.
	safeTemplate := x509.Certificate{}
	// If the profile contains no explicit whitelist, assume that all fields
	// should be copied from the CSR.
	if profile.CSRWhitelist == nil {
		safeTemplate = *csrTemplate
	} else {
		if profile.CSRWhitelist.Subject {
			safeTemplate.Subject = csrTemplate.Subject
		}
		if profile.CSRWhitelist.PublicKeyAlgorithm {
			safeTemplate.PublicKeyAlgorithm = csrTemplate.PublicKeyAlgorithm
		}
		if profile.CSRWhitelist.PublicKey {
			safeTemplate.PublicKey = csrTemplate.PublicKey
		}
		if profile.CSRWhitelist.SignatureAlgorithm {
			safeTemplate.SignatureAlgorithm = csrTemplate.SignatureAlgorithm
		}
		if profile.CSRWhitelist.DNSNames {
			safeTemplate.DNSNames = csrTemplate.DNSNames
		}
		if profile.CSRWhitelist.IPAddresses {
			safeTemplate.IPAddresses = csrTemplate.IPAddresses
		}
	}

	OverrideHosts(&safeTemplate, req.Hosts)
	safeTemplate.Subject = PopulateSubjectFromCSR(req.Subject, safeTemplate.Subject)

	// If there is a whitelist, ensure that both the Common Name and SAN DNSNames match
	if profile.NameWhitelist != nil {
		if safeTemplate.Subject.CommonName != "" {
			if profile.NameWhitelist.Find([]byte(safeTemplate.Subject.CommonName)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
			}
		}
		for _, name := range safeTemplate.DNSNames {
			if profile.NameWhitelist.Find([]byte(name)) == nil {
				return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
			}
		}
	}

	if profile.ClientProvidesSerialNumbers {
		if req.Serial == nil {
			fmt.Printf("xx %#v\n", profile)
			return nil, cferr.New(cferr.CertificateError, cferr.MissingSerial)
		}
		safeTemplate.SerialNumber = req.Serial
	} else {
		serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
		if err != nil {
			return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
		}
		safeTemplate.SerialNumber = serialNumber
	}

	if len(req.Extensions) > 0 {
		for _, ext := range req.Extensions {
			oid := asn1.ObjectIdentifier(ext.ID)
			if !profile.ExtensionWhitelist[oid.String()] {
				return nil, cferr.New(cferr.CertificateError, cferr.InvalidRequest)
			}

			rawValue, err := hex.DecodeString(ext.Value)
			if err != nil {
				return nil, cferr.Wrap(cferr.CertificateError, cferr.InvalidRequest, err)
			}

			safeTemplate.ExtraExtensions = append(safeTemplate.ExtraExtensions, pkix.Extension{
				Id:       oid,
				Critical: ext.Critical,
				Value:    rawValue,
			})
		}
	}

	var certTBS = safeTemplate

	if len(profile.CTLogServers) > 0 {
		// Add a poison extension which prevents validation
		var poisonExtension = pkix.Extension{Id: signer.CTPoisonOID, Critical: true, Value: []byte{0x05, 0x00}}
		var poisonedPreCert = certTBS
		poisonedPreCert.ExtraExtensions = append(safeTemplate.ExtraExtensions, poisonExtension)
		cert, err = s.sign(&poisonedPreCert, profile)
		if err != nil {
			return
		}

		derCert, _ := pem.Decode(cert)
		prechain := []ct.ASN1Cert{derCert.Bytes, s.ca.Raw}
		var sctList []ct.SignedCertificateTimestamp

		for _, server := range profile.CTLogServers {
			log.Infof("submitting poisoned precertificate to %s", server)
			var ctclient = client.New(server)
			var resp *ct.SignedCertificateTimestamp
			resp, err = ctclient.AddPreChain(prechain)
			if err != nil {
				return nil, cferr.Wrap(cferr.CTError, cferr.PrecertSubmissionFailed, err)
			}
			sctList = append(sctList, *resp)
		}

		var serializedSCTList []byte
		serializedSCTList, err = serializeSCTList(sctList)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
		}

		// Serialize again as an octet string before embedding
		serializedSCTList, err = asn1.Marshal(serializedSCTList)
		if err != nil {
			return nil, cferr.Wrap(cferr.CTError, cferr.Unknown, err)
		}

		var SCTListExtension = pkix.Extension{Id: signer.SCTListOID, Critical: false, Value: serializedSCTList}
		certTBS.ExtraExtensions = append(certTBS.ExtraExtensions, SCTListExtension)
	}
	var signedCert []byte
	signedCert, err = s.sign(&certTBS, profile)
	if err != nil {
		return nil, err
	}

	if s.db != nil {
		var certRecord = &certdb.CertificateRecord{
			Serial:    certTBS.SerialNumber.String(),
			CALabel:   req.Label,
			Status:    "",
			Reason:    0,
			ExpiresAt: certTBS.NotAfter,
			RevokedAt: nil,
			PEM:       string(signedCert),
		}

		err = certRecord.Insert(s.db)
		if err != nil {
			return nil, err
		}
	}

	return signedCert, nil
}

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

// Info return a populated info.Resp struct or an error.
func (s *Signer) Info(req info.Req) (resp *info.Resp, err error) {
	cert, err := s.Certificate(req.Label, req.Profile)
	if err != nil {
		return
	}

	profile, err := signer.Profile(s, req.Profile)
	if err != nil {
		return
	}

	resp = new(info.Resp)
	if cert.Raw != nil {
		resp.Certificate = string(bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	}
	resp.Usage = profile.Usage
	resp.ExpiryString = profile.ExpiryString

	return
}

// SigAlgo returns the RSA signer's signature algorithm.
func (s *Signer) SigAlgo() x509.SignatureAlgorithm {
	return s.sigAlgo
}

// Certificate returns the signer's certificate.
func (s *Signer) Certificate(label, profile string) (*x509.Certificate, error) {
	cert := *s.ca
	return &cert, nil
}

// SetPolicy sets the signer's signature policy.
func (s *Signer) SetPolicy(policy *config.Signing) {
	s.policy = policy
}

// SetDB sets the signer's cert db
func (s *Signer) SetDB(db *sql.DB) {
	s.db = db
}

// Policy returns the signer's policy.
func (s *Signer) Policy() *config.Signing {
	return s.policy
}
