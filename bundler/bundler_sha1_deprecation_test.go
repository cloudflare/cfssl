package bundler

// This test file contains tests on checking Bundle.Status with SHA-1 deprecation warning.
import (
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/cloudflare/cfssl/ubiquity"
)

const (
	sha1CA           = "testdata/ca.pem"
	sha1CAKey        = "testdata/ca.key"
	sha1Intermediate = "testdata/inter-L1-sha1.pem"
	sha2Intermediate = "testdata/inter-L1.pem"
	intermediateKey  = "testdata/inter-L1.key"
	intermediateCSR  = "testdata/inter-L1.csr"
	leafCSR          = "testdata/cfssl-leaf-ecdsa256.csr"
)

func TestChromeWarning(t *testing.T) {
	b := newCustomizedBundlerFromFile(t, sha1CA, sha1Intermediate, "")

	s, err := local.NewSignerFromFile(sha1Intermediate, intermediateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	certBytes := signCSRFile(s, leafCSR, t)
	intermediateBytes, err := os.ReadFile(sha1Intermediate)
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := os.ReadFile(sha1CA)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := helpers.ParseCertificatePEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := helpers.ParseCertificatePEM(intermediateBytes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := helpers.ParseCertificatePEM(rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	fullChain := []*x509.Certificate{leaf, intermediate, root}

	// Go 1.24 also rejects SHA-1 in Certificate.CheckSignatureFrom, so a Force
	// bundle cannot carry this full chain through partialVerify. Exercise the
	// bundler's status integration directly below that verifier boundary.
	statusCode, messages := addSHA1DeprecationWarnings(0, nil, fullChain)
	directBundle := &Bundle{Status: &BundleStatus{Code: statusCode, Messages: messages}}
	checkSHA1Warnings(t, directBundle, fullChain)

	t.Run("verified chain", func(t *testing.T) {
		if !supportsSHA1Verification(leaf, intermediate, root) {
			t.Skip("crypto/x509 rejects SHA-1 certificate signatures")
		}

		bundle, err := b.BundleFromPEMorDER(certBytes, nil, Ubiquitous, "")
		if err != nil {
			t.Fatal("bundling failed: ", err)
		}
		fullChain := append(append([]*x509.Certificate{}, bundle.Chain...), bundle.Root)
		checkSHA1Warnings(t, bundle, fullChain)
	})
}

func TestSHA2Preferences(t *testing.T) {
	sha1InterBytes, err := os.ReadFile(sha1Intermediate)
	if err != nil {
		t.Fatal(err)
	}
	sha2InterBytes, err := os.ReadFile(sha2Intermediate)
	if err != nil {
		t.Fatal(err)
	}
	rootBytes, err := os.ReadFile(sha1CA)
	if err != nil {
		t.Fatal(err)
	}

	sha1Inter, err := helpers.ParseCertificatePEM(sha1InterBytes)
	if err != nil {
		t.Fatal(err)
	}
	sha2Inter, err := helpers.ParseCertificatePEM(sha2InterBytes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := helpers.ParseCertificatePEM(rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	if sha1Inter.SignatureAlgorithm != x509.SHA1WithRSA {
		t.Fatalf("SHA-1 fixture uses %v", sha1Inter.SignatureAlgorithm)
	}

	sha2InterSigner := makeCASigner(sha1InterBytes, mustReadFile(intermediateKey), x509.SHA256WithRSA, t)
	leafBytes := signCSRFile(sha2InterSigner, leafCSR, t)
	leaf, err := helpers.ParseCertificatePEM(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	originalPlatforms := ubiquity.Platforms
	ubiquity.Platforms = nil
	t.Cleanup(func() { ubiquity.Platforms = originalPlatforms })
	chains := ubiquitousChains([][]*x509.Certificate{
		{leaf, sha1Inter, root},
		{leaf, sha2Inter, root},
	})
	if len(chains) != 1 || chains[0][1].SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatal("ubiquity selection did not prefer the SHA-2-homogeneous chain")
	}

	t.Run("verified chain", func(t *testing.T) {
		if !supportsSHA1Verification(leaf, sha1Inter, root) {
			t.Skip("crypto/x509 rejects SHA-1 certificate signatures")
		}

		b, err := NewBundlerFromPEM(rootBytes, append(append([]byte{}, sha1InterBytes...), sha2InterBytes...))
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := b.BundleFromPEMorDER(leafBytes, nil, Ubiquitous, "")
		if err != nil {
			t.Fatal("bundling failed: ", err)
		}
		if len(bundle.Chain) < 2 || bundle.Chain[1].SignatureAlgorithm != x509.SHA256WithRSA {
			t.Fatal("ubiquity selection by SHA-2 homogeneity failed")
		}
	})
}

func checkSHA1Warnings(t *testing.T, bundle *Bundle, fullChain []*x509.Certificate) {
	t.Helper()

	want := ubiquity.SHA1DeprecationMessages(fullChain)
	if len(want) == 0 {
		t.Fatal("SHA-1 deprecation messages should not be empty")
	}
	for _, wantMessage := range want {
		if !containsString(bundle.Status.Messages, wantMessage) {
			t.Fatalf("bundle messages %v do not contain %q", bundle.Status.Messages, wantMessage)
		}
	}
	if bundle.Status.Code&errors.BundleNotUbiquitousBit == 0 {
		t.Fatalf("bundle status code %d does not mark the chain as non-ubiquitous", bundle.Status.Code)
	}
}

func supportsSHA1Verification(leaf, intermediate, root *x509.Certificate) bool {
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

func makeCASignerFromFile(certFile, keyFile string, sigAlgo x509.SignatureAlgorithm, t *testing.T) signer.Signer {
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}

	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	return makeCASigner(certBytes, keyBytes, sigAlgo, t)
}

func makeCASigner(certBytes, keyBytes []byte, sigAlgo x509.SignatureAlgorithm, t *testing.T) signer.Signer {
	cert, err := helpers.ParseCertificatePEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	key, err := helpers.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	defaultProfile := &config.SigningProfile{
		Usage:        []string{"cert sign"},
		CAConstraint: config.CAConstraint{IsCA: true},
		Expiry:       time.Hour,
		ExpiryString: "1h",
	}
	policy := &config.Signing{
		Profiles: map[string]*config.SigningProfile{},
		Default:  defaultProfile,
	}
	s, err := local.NewSigner(key, cert, sigAlgo, policy)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func signCSRFile(s signer.Signer, csrFile string, t *testing.T) []byte {
	csrBytes, err := os.ReadFile(csrFile)
	if err != nil {
		t.Fatal(err)
	}

	signingRequest := signer.SignRequest{Request: string(csrBytes)}
	certBytes, err := s.Sign(signingRequest)
	if err != nil {
		t.Fatal(err)
	}

	return certBytes
}
