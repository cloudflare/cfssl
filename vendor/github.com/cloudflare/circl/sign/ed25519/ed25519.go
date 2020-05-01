package ed25519

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
)

// Size is the length in bytes of Ed25519 keys.
const Size = 32

// PublicKey represents a public key of Ed25519.
type PublicKey []byte

// PrivateKey represents a private key of Ed25519.
type PrivateKey []byte

// KeyPair implements crypto.Signer (golang.org/pkg/crypto/#Signer) interface.
type KeyPair struct{ private, public [Size]byte }

// GetPrivate returns a copy of the private key.
func (k *KeyPair) GetPrivate() PrivateKey { return makeCopy(&k.private) }

// GetPublic returns the public key corresponding to the private key.
func (k *KeyPair) GetPublic() PublicKey { return makeCopy(&k.public) }

// Public returns a crypto.PublicKey corresponding to the private key.
func (k *KeyPair) Public() crypto.PublicKey { return k.GetPublic() }

// Sign signs the given message with priv.
// Ed25519 performs two passes over messages to be signed and therefore cannot
// handle pre-hashed messages. Thus opts.HashFunc() must return zero to
// indicate the message hasn't been hashed. This can be achieved by passing
// crypto.Hash(0) as the value for opts.
func (k *KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ed25519: cannot sign hashed message")
	}
	return Sign(k, message), nil
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rnd io.Reader) (*KeyPair, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	private := make(PrivateKey, Size)
	if _, err := io.ReadFull(rnd, private); err != nil {
		return nil, err
	}
	return NewKeyFromSeed(private), nil
}

// NewKeyFromSeed generates a pair of Ed25519 signing keys given a
// previously-generated private key.
func NewKeyFromSeed(private PrivateKey) *KeyPair {
	if l := len(private); l != Size {
		panic("ed25519: bad private key length")
	}
	var P pointR1
	pk := new(KeyPair)
	k := sha512.Sum512(private)
	clamp(k[:])
	reduceModOrder(k[:Size], false)
	P.fixedMult(k[:Size])
	P.ToBytes(pk.public[:])
	copy(pk.private[:], private[:Size])
	return pk
}

// Sign returns the signature of a message using both the private and public
// keys of the signer.
func Sign(k *KeyPair, message []byte) []byte {
	h := sha512.Sum512(k.private[:])
	clamp(h[:])
	H := sha512.New()
	_, _ = H.Write(h[Size:])
	_, _ = H.Write(message)
	r := H.Sum(nil)
	reduceModOrder(r[:], true)

	var P pointR1
	P.fixedMult(r[:Size])
	signature := make([]byte, 2*Size)
	P.ToBytes(signature[:Size])

	H.Reset()
	_, _ = H.Write(signature[:Size])
	_, _ = H.Write(k.public[:])
	_, _ = H.Write(message)
	hRAM := H.Sum(nil)
	reduceModOrder(hRAM[:], true)
	calculateS(signature[Size:], r[:Size], hRAM[:Size], h[:Size])
	return signature
}

// Verify returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
func Verify(public PublicKey, message, signature []byte) bool {
	if len(public) != Size ||
		len(signature) != 2*Size ||
		!isLessThan(signature[Size:], order[:Size]) {
		return false
	}
	var P pointR1
	if ok := P.FromBytes(public); !ok {
		return false
	}
	P.neg()

	H := sha512.New()
	_, _ = H.Write(signature[:Size])
	_, _ = H.Write(public)
	_, _ = H.Write(message)
	hRAM := H.Sum(nil)
	reduceModOrder(hRAM[:], true)

	var Q pointR1
	Q.doubleMult(&P, signature[Size:], hRAM[:Size])
	var enc [Size]byte
	Q.ToBytes(enc[:])
	return bytes.Equal(enc[:], signature[:Size])
}

func clamp(k []byte) {
	k[0] &= 248
	k[Size-1] = (k[Size-1] & 127) | 64
}

func makeCopy(in *[Size]byte) []byte {
	out := make([]byte, Size)
	copy(out, in[:])
	return out
}
