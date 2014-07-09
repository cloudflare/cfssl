package errors

import (
	"crypto/x509"
	"encoding/json"
	"errors"
)

// Error is the error type usually returned by functions in CF SSL package.
// It contains a 4-digit error code where the most significant digit
// describes the category where the error occurred and the rest 3 digits
// describe the specific error reason.
type Error struct {
	ErrorCode int    `json:"code"`
	Message   string `json:"message"`
}

// The error category as the most significant digit of the error code
type Category int

// The error reason as the last 3 digits of the error code.
type Reason int

const (
	Success            Category = 1000 * iota // 0XXX
	CertificateError                          // 1XXX
	PrivateKeyError                           // 2XXX
	IntermediatesError                        // 3XXX
	RootError                                 // 4XXX
	PolicyError                               // 5XXX
	DialError                                 // 6XXX
)

// Non-specified error
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

// Certificate non-parsing errors, must be specified along with CertificateError
const (
	// Code 11XX
	SelfSigned Reason = 100 * (iota + 1)
	// Code 12XX
	// The least two significant digits of 12XX is determined as the actual x509 error is examined.
	VerifyFailed
	// Returned on bad certificate request
	BadRequest
)

const (
	certificateInvalid = 10 * (iota + 1) //121X
	unknownAuthority                     //122x
)

// Private key non-parsing errors, must be specified with PrivateKeyError
const (
	Encrypted        Reason = 100 * (iota + 1) //21XX
	NotRSAOrECC                                //22XX
	KeyMismatch                                //23XX
	GenerationFailed                           //24XX
)

// Policy non-parsing errors, must be specified along with PolicyError.
const (
	NoKeyUsages    Reason = 100 * (iota + 1) // 51XX
	InvalidPolicy                            // 52XX
	InvalidRequest                           // 53XX
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
		// Right now, these two types of errors should come from a standard error during
		// parsing. So if there is no passed-in error, panic.
		if err == nil {
			panic(errors.New("IntermediatesError/RootError needs a supplied error to initialize."))
		}

	case PolicyError:
		if err == nil {
			err = errors.New("invalid policy")
		}
	case DialError:
		if err == nil {
			err = errors.New("Failed dialing remote server.")
		}
	default: // Got a different Category? panic.
		panic(errors.New("Unsupported CF-SSL Error Type"))
	}

	return &Error{ErrorCode: errorCode, Message: err.Error()}

}
