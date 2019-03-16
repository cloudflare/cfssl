package crypto11

import (
	"C"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"unsafe"

	"github.com/miekg/pkcs11"
)

// ErrMalformedDER represents a failure to decode an ASN.1-encoded message
var ErrMalformedDER = errors.New("crypto11: malformed DER message")

// ErrMalformedSignature represents a failure to decode a signature.  This
// means the PKCS#11 library has returned an empty or odd-length byte
// string.
var ErrMalformedSignature = errors.New("crypto11xo: malformed signature")

const labelLength = 64

func ulongToBytes(n uint) []byte {
	return C.GoBytes(unsafe.Pointer(&n), C.sizeof_ulong) // ugh!
}

func bytesToUlong(bs []byte) (n uint) {
	return *(*uint)(unsafe.Pointer(&bs[0])) // ugh
}

func concat(slices ...[]byte) []byte {
	n := 0
	for _, slice := range slices {
		n += len(slice)
	}
	r := make([]byte, n)
	n = 0
	for _, slice := range slices {
		n += copy(r[n:], slice)
	}
	return r
}

// Representation of a *DSA signature
type dsaSignature struct {
	R, S *big.Int
}

// Populate a dsaSignature from a raw byte sequence
func (sig *dsaSignature) unmarshalBytes(sigBytes []byte) error {
	if len(sigBytes) == 0 || len(sigBytes)%2 != 0 {
		return ErrMalformedSignature
	}
	n := len(sigBytes) / 2
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(sigBytes[:n])
	sig.S.SetBytes(sigBytes[n:])
	return nil
}

// Populate a dsaSignature from DER encoding
func (sig *dsaSignature) unmarshalDER(sigDER []byte) error {
	if rest, err := asn1.Unmarshal(sigDER, sig); err != nil {
		return err
	} else if len(rest) > 0 {
		return ErrMalformedDER
	}
	return nil
}

// Return the DER encoding of a dsaSignature
func (sig *dsaSignature) marshalDER() ([]byte, error) {
	return asn1.Marshal(*sig)
}

// Compute *DSA signature and marshal the result in DER form
func dsaGeneric(slot uint, key pkcs11.ObjectHandle, mechanism uint, digest []byte) ([]byte, error) {
	var err error
	var sigBytes []byte
	var sig dsaSignature
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(mechanism, nil)}
	err = withSession(slot, func(session *PKCS11Session) error {
		if err = instance.ctx.SignInit(session.Handle, mech, key); err != nil {
			return err
		}
		sigBytes, err = instance.ctx.Sign(session.Handle, digest)
		return err
	})
	if err != nil {
		return nil, err
	}
	err = sig.unmarshalBytes(sigBytes)
	if err != nil {
		return nil, err
	}

	return sig.marshalDER()
}

// Pick a random label for a key
func generateKeyLabel() ([]byte, error) {
	rawLabel := make([]byte, labelLength / 2)
	var rand PKCS11RandReader
	sz, err := rand.Read(rawLabel)
	if err != nil {
		return nil, err
	}
	if sz < len(rawLabel) {
		return nil, ErrCannotGetRandomData
	}
	label := make([]byte, labelLength)
	hex.Encode(label, rawLabel)
	return label, nil
}
