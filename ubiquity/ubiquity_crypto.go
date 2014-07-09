package ubiquity

// In this file, we mainly cover crypto ubiquity.
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"math"
)

type HashUbiquity int
type KeyAlgoUbiquity int

// SHA1 is ubiquitous. SHA2 is not supported on some legacy platforms.
// We consider MD2/MD5 is harmful and thus assign them lowest ubiquity.
const (
	UnknownHashUbiquity HashUbiquity = 0
	SHA2Ubiquity        HashUbiquity = 70
	SHA1Ubiquity        HashUbiquity = 100
	MD5Ubiquity         HashUbiquity = 0
	MD2Ubiquity         HashUbiquity = 0
)

// RSA and DSA are considered ubiquitous.
// ECDSA256 and ECDSA384 should be supported by TLS 1.2 and have limited support
// from TLS 1.0 and 1.1, based on RFC6460.  And ECDSA521 are relatively less supported
// as a standard.
const (
	RSAUbiquity         KeyAlgoUbiquity = 100
	DSAUbiquity         KeyAlgoUbiquity = 100
	ECDSA256Ubiquity    KeyAlgoUbiquity = 70
	ECDSA384Ubiquity    KeyAlgoUbiquity = 70
	ECDSA521Ubiquity    KeyAlgoUbiquity = 30
	UnknownAlgoUbiquity KeyAlgoUbiquity = 0
)

// hashUbiquity computes the ubiquity of the hash algorithm in the
// signature algorithm of a cert.
// SHA1 > SHA2 > MD > Others
func hashUbiquity(cert *x509.Certificate) HashUbiquity {
	switch cert.SignatureAlgorithm {
	case x509.ECDSAWithSHA1, x509.DSAWithSHA1, x509.SHA1WithRSA:
		return SHA1Ubiquity
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.DSAWithSHA256, x509.SHA256WithRSA, x509.SHA384WithRSA,
		x509.SHA512WithRSA:
		return SHA2Ubiquity
	case x509.MD5WithRSA, x509.MD2WithRSA:
		return MD5Ubiquity
	default:
		return UnknownHashUbiquity
	}
}

// keyAlgoUbiquity compute the ubiquity of the cert's public key algorithm
// RSA, DSA>ECDSA>Unknown
func keyAlgoUbiquity(cert *x509.Certificate) KeyAlgoUbiquity {
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		switch cert.PublicKey.(*ecdsa.PublicKey).Curve {
		case elliptic.P256():
			return ECDSA256Ubiquity
		case elliptic.P384():
			return ECDSA384Ubiquity
		case elliptic.P521():
			return ECDSA521Ubiquity
		default:
			return UnknownAlgoUbiquity
		}
	case x509.RSA:
		if cert.PublicKey.(*rsa.PublicKey).N.BitLen() >= 1024 {
			return RSAUbiquity
		} else {
			return UnknownAlgoUbiquity
		}
	case x509.DSA:
		return DSAUbiquity
	default:
		return UnknownAlgoUbiquity
	}
}

// Hash ubiquity of a chain is the lowest hash ubiquity among certs in it.
func ChainHashUbiquity(chain []*x509.Certificate) HashUbiquity {
	ret := math.MaxInt32
	for _, cert := range chain {
		uscore := int(hashUbiquity(cert))
		if ret > uscore {
			ret = uscore
		}
	}
	return HashUbiquity(ret)
}

// Key algorithm ubiquity of a chain is the lowest key algorithm ubiquity among certs in it.
func ChainKeyAlgoUbiquity(chain []*x509.Certificate) KeyAlgoUbiquity {
	ret := math.MaxInt32
	for _, cert := range chain {
		uscore := int(keyAlgoUbiquity(cert))
		if ret > uscore {
			ret = uscore
		}
	}
	return KeyAlgoUbiquity(ret)
}

// Return positive value if hash function ubiquity of chain1 is greater than that of chain2,
// negative value if ubiquity rank of chain1 is lower than that of chain2, 0 if they are ranked equal.
func CompareChainHashUbiquity(chain1, chain2 []*x509.Certificate) int {
	hu1 := ChainHashUbiquity(chain1)
	hu2 := ChainHashUbiquity(chain2)
	return int(hu1) - int(hu2)
}

// Return positive value if key algorithm ubiquity of chain1 is greater than that of chain2,
// negative value if ubiquity rank of chain1 is lower than that of chain2, 0 if they are ranked equal.
func CompareChainKeyAlgoUbiquity(chain1, chain2 []*x509.Certificate) int {
	kau1 := ChainKeyAlgoUbiquity(chain1)
	kau2 := ChainKeyAlgoUbiquity(chain2)
	return int(kau1) - int(kau2)
}

// CompareExpiryUbiquity ranks two certificate chains based on the exiry dates of intermediates and roots.
// Certs expire later are ranked higher than ones expire earlier. The ranking between chains are determined by
// the first pair of intermediates, scanned from the root level,  that ar ranked differently.
func CompareExpiryUbiquity(chain1, chain2 []*x509.Certificate) int {
	for i := 0; ; i++ {
		if i >= len(chain1) || i >= len(chain2) {
			break
		}
		// Compare expiry dates, later is ranked higher.
		t1 := &chain1[len(chain1)-1-i].NotAfter
		t2 := &chain2[len(chain2)-1-i].NotAfter
		r := compareTime(t1, t2)
		// Return when we find rank difference.
		if r != 0 {
			return r
		}
	}
	return 0
}
