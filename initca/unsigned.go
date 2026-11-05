package initca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// idAlgUnsigned is id-alg-unsigned, the signature algorithm of an unsigned
// certificate (RFC 9925, Section 3.1).
var idAlgUnsigned = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 36}

const (
	// serialNumberLength is the maximum serial number length in octets
	// (RFC 5280, Section 4.1.2.2).
	serialNumberLength = 20

	// maxSerialNumberAttempts bounds how often a zero serial number is
	// drawn again. Only a broken random source produces zero repeatedly.
	maxSerialNumberAttempts = 8
)

// NewUnsigned generates a key pair as described by req.KeyRequest and returns
// an RFC 9925 unsigned root certificate for its public key, together with the
// PEM-encoded private key.
//
// rawSubject must be the DER encoding of an X.501 Name. It is used verbatim
// as both the subject and the issuer of the certificate, which RFC 9925,
// Section 3.2 permits. The caller is responsible for the encoding: rawSubject
// is only checked to be structurally a Name, that is a SEQUENCE of one or more
// SETs of attribute type and value pairs with definite minimal lengths and no
// trailing data. The order of SET elements and the encoding of attribute
// values are not checked. The certificate is not self-signed: its signature
// algorithm is id-alg-unsigned and its signature value is empty, so it can
// only serve as a trust anchor that relying parties are configured with
// directly.
//
// Only these fields of req are used: KeyRequest (ECDSA P-256 when nil), CA
// and CRL. As in New, req.CA adjusts the expiry, backdate and path length of
// the default profile of CAPolicy, req.CRL sets its CRL distribution point,
// the adjusted policy must be valid, and signer.FillTemplate fills the
// certificate from that profile, including its validity period, key usages,
// basic constraints and subject key identifier, and any CRL, OCSP, issuer URL
// and certificate policy settings. The profile must issue CA certificates.
// Profile settings that New applies outside signer.FillTemplate, such as
// linting and certificate transparency, are not used. req.CN, req.Names and
// req.SerialNumber must be empty, because the subject comes from rawSubject.
// All other fields, including Hosts, are ignored, so the certificate has no
// subject alternative names.
//
// Before returning, NewUnsigned signs the certificate with the private key
// and checks that the signature verifies under the certificate's public key.
// It then discards the signature.
//
// Relying parties that don't implement RFC 9925 may not accept an unsigned
// certificate as a trust anchor; for example, OpenSSL 3.6 doesn't treat it as
// self-signed and fails path building unless partial-chain verification is
// enabled. Go parses names whose attribute values are not strings, such as a
// RELATIVE-OID, only from Go 1.27.
func NewUnsigned(req *csr.CertificateRequest, rawSubject []byte) (cert, key []byte, err error) {
	profile, err := prepareUnsigned(req, rawSubject)
	if err != nil {
		return nil, nil, err
	}

	keyRequest := req.KeyRequest
	if keyRequest == nil {
		keyRequest = csr.NewKeyRequest()
	}
	generated, err := keyRequest.Generate()
	if err != nil {
		return nil, nil, wrapError(cferr.PrivateKeyError, cferr.GenerationFailed, err)
	}
	priv, ok := generated.(crypto.Signer)
	if !ok {
		return nil, nil, cferr.Wrap(cferr.PrivateKeyError, cferr.Unknown,
			fmt.Errorf("generated private key type %T is not a crypto.Signer", generated))
	}

	key, err = csr.MarshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err = createUnsigned(profile, rawSubject, priv)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// NewUnsignedFromSigner returns an RFC 9925 unsigned root certificate for the
// public key of priv. The certificate is not self-signed: its signature
// algorithm is id-alg-unsigned and its signature value is empty.
//
// rawSubject must be the DER encoding of an X.501 Name. It is used verbatim
// as both the subject and the issuer of the certificate, which RFC 9925,
// Section 3.2 permits. The caller is responsible for the encoding: rawSubject
// is only checked to be structurally a Name, that is a SEQUENCE of one or more
// SETs of attribute type and value pairs with definite minimal lengths and no
// trailing data. The order of SET elements and the encoding of attribute
// values are not checked.
//
// Only these fields of req are used: CA and CRL. As in New, req.CA adjusts
// the expiry, backdate and path length of the default profile of CAPolicy,
// req.CRL sets its CRL distribution point, the adjusted policy must be valid,
// and signer.FillTemplate fills the certificate from that profile, including
// its validity period, key usages, basic constraints and subject key
// identifier, and any CRL, OCSP, issuer URL and certificate policy settings.
// The profile must issue CA certificates. Profile settings that New applies
// outside signer.FillTemplate, such as linting and certificate transparency,
// are not used. req.CN, req.Names and req.SerialNumber must be empty, because
// the subject comes from rawSubject. All other fields, including KeyRequest
// and Hosts, are ignored, so the certificate has no subject alternative
// names.
//
// Before returning, NewUnsignedFromSigner signs the certificate with priv and
// checks that the signature verifies under the certificate's public key. If
// it does not, because priv does not hold the matching private key or is
// faulty, it returns a KeyMismatch error. It then discards the signature.
func NewUnsignedFromSigner(req *csr.CertificateRequest, rawSubject []byte, priv crypto.Signer) ([]byte, error) {
	profile, err := prepareUnsigned(req, rawSubject)
	if err != nil {
		return nil, err
	}
	if priv == nil {
		return nil, cferr.Wrap(cferr.PrivateKeyError, cferr.Unknown, errors.New("missing private key"))
	}
	return createUnsigned(profile, rawSubject, priv)
}

// prepareUnsigned validates req and rawSubject and returns the signing
// profile for an unsigned root.
func prepareUnsigned(req *csr.CertificateRequest, rawSubject []byte) (*config.SigningProfile, error) {
	if err := validateUnsignedRequest(req); err != nil {
		return nil, err
	}
	if err := validateRawName(rawSubject); err != nil {
		return nil, err
	}
	return caProfile(req)
}

// validateUnsignedRequest rejects a request that sets subject fields, which
// would conflict with the raw subject.
func validateUnsignedRequest(req *csr.CertificateRequest) error {
	if req == nil {
		return cferr.Wrap(cferr.PolicyError, cferr.InvalidRequest, errors.New("missing certificate request"))
	}
	if req.CN != "" || len(req.Names) != 0 || req.SerialNumber != "" {
		return cferr.Wrap(cferr.PolicyError, cferr.InvalidRequest,
			errors.New("CN, names and serial number must be empty when the subject is a raw name"))
	}
	return nil
}

// caProfile returns the default profile of CAPolicy with the CA settings and
// CRL distribution point of req applied, as New does. It then validates the
// adjusted policy, as local.NewSigner does for New.
func caProfile(req *csr.CertificateRequest) (*config.SigningProfile, error) {
	policy := CAPolicy()
	if policy == nil || policy.Default == nil {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}
	profile := policy.Default

	if req.CA != nil {
		if req.CA.Expiry != "" {
			expiry, err := time.ParseDuration(req.CA.Expiry)
			if err != nil {
				return nil, wrapError(cferr.PolicyError, cferr.InvalidRequest, fmt.Errorf("parsing CA expiry: %w", err))
			}
			profile.ExpiryString = req.CA.Expiry
			profile.Expiry = expiry
		}

		if req.CA.Backdate != "" {
			backdate, err := time.ParseDuration(req.CA.Backdate)
			if err != nil {
				return nil, wrapError(cferr.PolicyError, cferr.InvalidRequest, fmt.Errorf("parsing CA backdate: %w", err))
			}
			profile.Backdate = backdate
		}

		profile.CAConstraint.MaxPathLen = req.CA.PathLength
		if req.CA.PathLength != 0 && req.CA.PathLenZero {
			log.Infof("ignore invalid 'pathlenzero' value")
		} else {
			profile.CAConstraint.MaxPathLenZero = req.CA.PathLenZero
		}
	}

	if req.CRL != "" {
		profile.CRL = req.CRL
	}

	if !policy.Valid() {
		return nil, cferr.New(cferr.PolicyError, cferr.InvalidPolicy)
	}
	return profile, nil
}

// validateRawName checks that raw is structurally an X.501 Name
// (RFC 5280, Section 4.1.2.4): a single SEQUENCE of one or more SETs, each
// holding one or more SEQUENCEs of an OBJECT IDENTIFIER followed by exactly
// one value, with definite minimal lengths and no trailing data at any level.
// It does not check the DER order of SET elements or the encoding of
// attribute values.
func validateRawName(raw []byte) error {
	input := cryptobyte.String(raw)
	var rdnSequence cryptobyte.String
	if !input.ReadASN1(&rdnSequence, cbasn1.SEQUENCE) || !input.Empty() {
		return invalidRawName("not a single DER SEQUENCE")
	}
	if rdnSequence.Empty() {
		return invalidRawName("empty RDNSequence")
	}

	for !rdnSequence.Empty() {
		var rdn cryptobyte.String
		if !rdnSequence.ReadASN1(&rdn, cbasn1.SET) {
			return invalidRawName("RelativeDistinguishedName is not a SET")
		}
		if rdn.Empty() {
			return invalidRawName("empty RelativeDistinguishedName")
		}
		for !rdn.Empty() {
			if err := readAttributeTypeAndValue(&rdn); err != nil {
				return err
			}
		}
	}
	return nil
}

// readAttributeTypeAndValue reads one AttributeTypeAndValue from rdn.
func readAttributeTypeAndValue(rdn *cryptobyte.String) error {
	var atv cryptobyte.String
	if !rdn.ReadASN1(&atv, cbasn1.SEQUENCE) {
		return invalidRawName("AttributeTypeAndValue is not a SEQUENCE")
	}

	var attributeType asn1.ObjectIdentifier
	if !atv.ReadASN1ObjectIdentifier(&attributeType) {
		return invalidRawName("attribute type is not an OBJECT IDENTIFIER")
	}

	var value cryptobyte.String
	var valueTag cbasn1.Tag
	if !atv.ReadAnyASN1Element(&value, &valueTag) || !atv.Empty() {
		return invalidRawName(fmt.Sprintf("attribute %s does not have exactly one value", attributeType))
	}
	return nil
}

func invalidRawName(detail string) error {
	return cferr.Wrap(cferr.PolicyError, cferr.InvalidRequest, fmt.Errorf("invalid raw subject name: %s", detail))
}

// createUnsigned issues a self-signed certificate with priv, checks the
// signature and returns the PEM-encoded unsigned form of the certificate.
func createUnsigned(profile *config.SigningProfile, rawSubject []byte, priv crypto.Signer) ([]byte, error) {
	sigAlgo := helpers.SignerAlgo(priv)
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		return nil, cferr.New(cferr.PrivateKeyError, cferr.Unavailable)
	}

	template, err := unsignedTemplate(profile, rawSubject, priv.Public())
	if err != nil {
		return nil, err
	}
	template.SignatureAlgorithm = sigAlgo

	recorder := &signatureRecorder{Signer: priv}
	der, err := x509.CreateCertificate(rand.Reader, template, template, template.PublicKey, recorder)
	if err != nil {
		// CreateCertificate verifies the signature it gets against the
		// signer's public key, so failing after a signature was produced
		// means the signature didn't verify against priv.Public(): a key
		// mismatch or a faulty signer.
		if recorder.signed {
			return nil, wrapError(cferr.PrivateKeyError, cferr.KeyMismatch, err)
		}
		return nil, wrapError(cferr.CertificateError, cferr.Unknown, err)
	}

	// CreateCertificate checks the signature against a fresh priv.Public(),
	// not the key in the certificate, so a signer whose Public() changes
	// while signing gets past it.
	if err := checkPossession(der); err != nil {
		return nil, err
	}

	unsigned, err := stripSignature(der)
	if err != nil {
		return nil, wrapError(cferr.CertificateError, cferr.Unknown, err)
	}

	// Fail closed if the rewrite corrupted the encoding or the names.
	parsed, err := x509.ParseCertificate(unsigned)
	if err != nil {
		return nil, wrapError(cferr.CertificateError, cferr.ParseFailed, err)
	}
	if !bytes.Equal(parsed.RawSubject, rawSubject) || !bytes.Equal(parsed.RawIssuer, rawSubject) {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed,
			errors.New("certificate subject or issuer differs from the raw subject name"))
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unsigned}), nil
}

// unsignedTemplate returns the template of an unsigned root for pub. As the
// local signer does for New, it fills the template from profile with
// signer.FillTemplate and rejects a profile that doesn't issue CA
// certificates.
func unsignedTemplate(profile *config.SigningProfile, rawSubject []byte, pub crypto.PublicKey) (*x509.Certificate, error) {
	serialNumber, err := randomSerialNumber(rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		RawSubject:   rawSubject,
		PublicKey:    pub,
	}
	if err := signer.FillTemplate(template, profile, profile, time.Time{}, time.Time{}); err != nil {
		return nil, wrapError(cferr.CertificateError, cferr.Unknown, err)
	}
	if !template.IsCA {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidRequest, errors.New("CA policy does not issue CA certificates"))
	}
	return template, nil
}

// randomSerialNumber returns a positive serial number of at most
// serialNumberLength octets read from random, as the local signer does, but
// draws again if the number is zero.
func randomSerialNumber(random io.Reader) (*big.Int, error) {
	buf := make([]byte, serialNumberLength)
	for range maxSerialNumberAttempts {
		if _, err := io.ReadFull(random, buf); err != nil {
			return nil, wrapError(cferr.CertificateError, cferr.Unknown, err)
		}
		// Clear the top bit so that the DER INTEGER is positive and its
		// encoding stays within serialNumberLength octets.
		buf[0] &= 0x7f
		if serialNumber := new(big.Int).SetBytes(buf); serialNumber.Sign() > 0 {
			return serialNumber, nil
		}
	}
	return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, errors.New("random source produced only zero serial numbers"))
}

// signatureRecorder wraps a crypto.Signer and records whether it produced a
// signature.
type signatureRecorder struct {
	crypto.Signer
	signed bool
}

// SignMessage implements crypto.MessageSigner by calling crypto.SignMessage
// on the wrapped signer, which is what x509.CreateCertificate does when given
// the wrapped signer directly.
func (r *signatureRecorder) SignMessage(random io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := crypto.SignMessage(r.Signer, random, msg, opts)
	r.signed = err == nil
	return signature, err
}

// checkPossession verifies the signature of the self-signed certificate der
// under its own public key, which proves that the signer holds the private
// key for that public key.
func checkPossession(der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return wrapError(cferr.CertificateError, cferr.ParseFailed, err)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return wrapError(cferr.PrivateKeyError, cferr.KeyMismatch, err)
	}
	return nil
}

// wrapError wraps err, which may be or wrap a *cferr.Error, as a CFSSL error
// with category and reason. cferr.Wrap panics if err is a bare *cferr.Error,
// so that error is returned unchanged instead. errors.As also finds a
// *cferr.Error wrapped with %w, which is returned so that it keeps its CFSSL
// code, at the cost of dropping the text of the outer wrapper.
func wrapError(category cferr.Category, reason cferr.Reason, err error) error {
	var cfsslErr *cferr.Error
	if errors.As(err, &cfsslErr) {
		return cfsslErr
	}
	return cferr.Wrap(category, reason, err)
}

// stripSignature turns the DER certificate der into an unsigned certificate,
// as RFC 9925, Section 3.1 specifies: it replaces both the signature field of
// the TBSCertificate and the outer signatureAlgorithm with id-alg-unsigned
// with absent parameters, and the signatureValue with a BIT STRING of length
// zero. All other TBSCertificate fields are kept as is.
func stripSignature(der []byte) ([]byte, error) {
	input := cryptobyte.String(der)
	var certificate, tbs, signatureAlgorithm cryptobyte.String
	if !input.ReadASN1(&certificate, cbasn1.SEQUENCE) || !input.Empty() ||
		!certificate.ReadASN1(&tbs, cbasn1.SEQUENCE) ||
		!certificate.ReadASN1Element(&signatureAlgorithm, cbasn1.SEQUENCE) ||
		!certificate.SkipASN1(cbasn1.BIT_STRING) || !certificate.Empty() {
		return nil, errors.New("malformed certificate")
	}

	var version, serialNumber, tbsSignature cryptobyte.String
	if !tbs.ReadASN1Element(&version, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.ReadASN1Element(&serialNumber, cbasn1.INTEGER) ||
		!tbs.ReadASN1Element(&tbsSignature, cbasn1.SEQUENCE) {
		return nil, errors.New("malformed TBSCertificate")
	}
	if !bytes.Equal(tbsSignature, signatureAlgorithm) {
		return nil, errors.New("TBSCertificate signature differs from the certificate signatureAlgorithm")
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(certBuilder *cryptobyte.Builder) {
		certBuilder.AddASN1(cbasn1.SEQUENCE, func(tbsBuilder *cryptobyte.Builder) {
			tbsBuilder.AddBytes(version)
			tbsBuilder.AddBytes(serialNumber)
			addUnsignedAlgorithm(tbsBuilder)
			// The remaining fields, issuer through extensions.
			tbsBuilder.AddBytes(tbs)
		})
		addUnsignedAlgorithm(certBuilder)
		certBuilder.AddASN1BitString(nil)
	})
	return b.Bytes()
}

// addUnsignedAlgorithm adds the AlgorithmIdentifier for id-alg-unsigned with
// the parameters field absent.
func addUnsignedAlgorithm(b *cryptobyte.Builder) {
	b.AddASN1(cbasn1.SEQUENCE, func(algorithm *cryptobyte.Builder) {
		algorithm.AddASN1ObjectIdentifier(idAlgUnsigned)
	})
}
