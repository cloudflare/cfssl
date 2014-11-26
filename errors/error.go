package errors

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
)

// Error is the error type usually returned by functions in CF SSL package.
// It contains a 4-digit error code where the most significant digit
// describes the category where the error occurred and the rest 3 digits
// describe the specific error reason.
type Error struct {
	ErrorCode int    `json:"code"`
	Message   string `json:"message"`
}

// Category is the most significant digit of the error code.
type Category int

// Reason is the last 3 digits of the error code.
type Reason int

const (
	// Success indicates no error occurred.
	Success Category = 1000 * iota // 0XXX

	// CertificateError indicates a fault in a certificate.
	CertificateError // 1XXX

	// PrivateKeyError indicates a fault in a private key.
	PrivateKeyError // 2XXX

	// IntermediatesError indicates a fault in an intermediate.
	IntermediatesError // 3XXX

	// RootError indicates a fault in a root.
	RootError // 4XXX

	// PolicyError indicates an error arising from a malformed or
	// non-existent policy, or a breach of policy.
	PolicyError // 5XXX

	// DialError indicates a network fault.
	DialError // 6XXX
)

// None is a non-specified error.
const (
	None Reason = iota
)

// Warning code for a success
const (
	BundleExpiringBit      int = 1 << iota // 0x01
	BundleNotUbiquitousBit                 // 0x02
)

// Parsing errors
const (
	Unknown      Reason = iota // X000
	ReadFailed                 // X001
	DecodeFailed               // X002
	ParseFailed                // X003
)

// The following represent certificate non-parsing errors, and must be
// specified along with CertificateError.
const (
	// SelfSigned indicates that a certificate is self-signed and
	// cannot be used in the manner being attempted.
	SelfSigned Reason = 100 * (iota + 1) // Code 11XX

	// VerifyFailed is an X.509 verification failure. The least two
	// significant digits of 12XX is determined as the actual x509
	// error is examined.
	VerifyFailed // Code 12XX

	// BadRequest indicates that the certificate request is invalid.
	BadRequest // Code 13XX
)

const (
	certificateInvalid = 10 * (iota + 1) //121X
	unknownAuthority                     //122x
)

// The following represent private-key non-parsing errors, and must be
// specified with PrivateKeyError.
const (
	// Encrypted indicates that the private key is a PKCS #8 encrypted
	// private key. At this time, CFSSL does not support decrypting
	// these keys.
	Encrypted Reason = 100 * (iota + 1) //21XX

	// NotRSAOrECC indicates that they key is not an RSA or ECC
	// private key; these are the only two private key types supported
	// at this time by CFSSL.
	NotRSAOrECC //22XX

	// KeyMismatch indicates that the private key does not match
	// the public key or certificate being presented with the key.
	KeyMismatch //23XX

	// GenerationFailed indicates that a private key could not
	// be generated.
	GenerationFailed //24XX
)

// The following are policy-related non-parsing errors, and must be
// specified along with PolicyError.
const (
	// NoKeyUsages indicates that the profile does not permit any
	// key usages for the certificate.
	NoKeyUsages Reason = 100 * (iota + 1) // 51XX

	// InvalidPolicy indicates that policy being requested is not
	// a valid policy or does not exist.
	InvalidPolicy // 52XX

	// InvalidRequest indicates a certificate request violated the
	// constraints of the policy being applied to the request.
	InvalidRequest // 53XX
)

// The error interface implementation, which formats to a JSON object string.
func (e *Error) Error() string {
	marshaled, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	return string(marshaled)

}

// New returns an error that contains the given error and an error code derived from
// the given category, reason and the error. Currently, to avoid confusion, it is not
// allowed to create an error of category Success
func New(category Category, reason Reason, err error) *Error {
	errorCode := int(category) + int(reason)
	switch category {
	case CertificateError:
		// With an error given, report the status with more detailed status code
		// for some certificate errors we care.
		if err != nil {
			switch errorType := err.(type) {
			case x509.CertificateInvalidError:
				errorCode += certificateInvalid + int(errorType.Reason)
			case x509.UnknownAuthorityError:
				errorCode += unknownAuthority
			}
		} else {
			// Without a given error, customize an error message.
			msg := "Unknown certificate error"
			switch reason {
			case DecodeFailed:
				msg = "Failed to decode certificate"
			case ParseFailed:
				msg = "Failed to parse certificate"
			case SelfSigned:
				msg = "Certificate is self signed"
			}
			err = errors.New(msg)
		}
	case PrivateKeyError:
		// If there isn't a given error,
		// customize one.
		if err == nil {
			msg := "Unknown private key error"
			switch reason {
			case DecodeFailed:
				msg = "Failed to decode private key"
			case ParseFailed:
				msg = "Failed to parse private key"
			case Encrypted:
				msg = "Private key is encrypted"
			case NotRSAOrECC:
				msg = "Private key algorithm is not RSA or ECC"
			case KeyMismatch:
				msg = "Private key does not match public key"
			}
			err = errors.New(msg)
		}
	case IntermediatesError, RootError:
		// Right now, these two types of errors should come from
		// a standard error during parsing. So if there is no
		// passed-in error, panic.
		if err == nil {
			panic("IntermediatesError/RootError needs a supplied error to initialize.")
		}

	case PolicyError:
		if err == nil {
			err = errors.New("invalid policy")
		}
	case DialError:
		if err == nil {
			err = errors.New("dialing remote server failed")
		}
	default:
		panic(fmt.Sprintf("Unsupported CF-SSL error type: %d.",
			category))
	}

	return &Error{ErrorCode: errorCode, Message: err.Error()}

}
