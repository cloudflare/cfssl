// Functions which allow for the creation of dummy certificates, chains, and
// keys from certificate requests.

package testsuite

import (
	"reflect"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

// CreateCertificateChain creates a chain of certificates from a slice of
// requests. The first request is the root certificate and the last is the
// leaf. The chain is returned as a slice of PEM-encoded bytes.
func CreateCertificateChain(requests []csr.CertificateRequest,
	options SignOptions) (certChain []byte, key []byte, err error) {

	// Create the root certificate using the first request. This will be
	// self-signed.
	certChain = make([]byte, 0)
	rootCert, _, prevKey, err := initca.New(&requests[0])
	if err != nil {
		return nil, nil, err
	}
	certChain = append(certChain, rootCert...)

	// For each of the next requests, create a certificate signed by the
	// previous certificate.
	prevCert := rootCert
	for _, request := range requests[1:] {
		cert, key, err := SignCertificate(request, prevCert, prevKey, options)
		if err != nil {
			return nil, nil, err
		}
		certChain = append(certChain, byte('\n'))
		certChain = append(certChain, cert...)
		prevCert = cert
		prevKey = key
	}

	return certChain, key, nil
}

// SignOptions allows callers to configure the signer according to their needs
// when calling SignCertificate. Any of these can be left nil, in which case
// standard defaults will be used.
type SignOptions struct {
	Hosts     []string
	Profile   config.SigningProfile
	Label     string
	SerialSeq string
	WhiteList signer.Whitelist
}

// SignCertificate takes a request and a certificate / key combination. A new
// certificate and key are generated from the request and signed by the input
// certificate. The 'options' argument allows the internal signer to be
// configured as needed. The returned certificate and key are PEM-encoded bytes.
func SignCertificate(request csr.CertificateRequest, signerCert, signerKey []byte,
	options SignOptions) (encodedCert, encodedKey []byte, err error) {

	// The default profile (used when options.Profile is not set).
	// Allows the signed certificate can be used as intermediate CA and server
	// auth certificate.
	defaultProfile := config.SigningProfile{
		Usage:        []string{"cert sign", "server auth"},
		CA:           true,
		Expiry:       time.Hour,
		ExpiryString: "1h",
	}

	// If options.Profile is the zero value, replace it with the default profile.
	emptyProfile := config.SigningProfile{}
	if reflect.DeepEqual(options.Profile, emptyProfile) {
		options.Profile = defaultProfile
	}

	// Generate the signer using the certificate, key, and profile.
	policy := &config.Signing{
		Profiles: map[string]*config.SigningProfile{},
		Default:  &options.Profile,
	}
	priv, err := helpers.ParsePrivateKeyPEM(signerKey)
	if err != nil {
		return nil, nil, err
	}
	parsedSignerCert, err := helpers.ParseCertificatePEM(signerCert)
	if err != nil {
		return nil, nil, err
	}
	sigAlgo := signer.DefaultSigAlgo(priv)
	localSigner, err := local.NewSigner(priv, parsedSignerCert, sigAlgo, policy)
	if err != nil {
		return nil, nil, err
	}

	// Get the CSR bytes and key bytes for the request. Store the CSR bytes in
	// a temporary file.
	csrBytes, encodedKey, err := csr.ParseRequest(&request)
	if err != nil {
		return nil, nil, err
	}

	// Construct the subject from the request and options.WhiteList.
	subject := &signer.Subject{
		CN:        request.CN,
		Names:     request.Names,
		Whitelist: &options.WhiteList,
	}

	// Create a sign request.
	// Note: we do not need to set a profile as the signer will use the default
	// we already set.
	signReq := signer.SignRequest{
		Hosts:     options.Hosts,
		Request:   string(csrBytes),
		Subject:   subject,
		Label:     options.Label,
		SerialSeq: options.SerialSeq,
	}

	encodedCert, err = localSigner.Sign(signReq)
	return
}
