// +build !nopkcs11

package pkcs11key

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/ecdsa"
	"github.com/miekg/pkcs11"
	"testing"
)

type mockCtx struct{}

const rsaPrivateKeyHandle = pkcs11.ObjectHandle(23)
const ecPrivateKeyHandle = pkcs11.ObjectHandle(32)
const ecPublicKeyHandle = pkcs11.ObjectHandle(33)
// EC Private key with no matching public key
const ecPrivNoPubHandle = pkcs11.ObjectHandle(34)
const ecInvEcPointPrivHandle = pkcs11.ObjectHandle(35)
const ecInvEcPointPubHandle = pkcs11.ObjectHandle(36)
const sessionHandle = pkcs11.SessionHandle(17)

var slots = []uint{7, 8, 9}
var tokenInfo = pkcs11.TokenInfo{
	Label: "token label",
}
var currentSearch []*pkcs11.Attribute

func (c mockCtx) CloseSession(sh pkcs11.SessionHandle) error {
	return nil
}

func (c mockCtx) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	return nil
}

func (c mockCtx) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	currentSearch = temp
	return nil
}

func (c mockCtx) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	for _, a := range currentSearch {
		// We search private keys using CKA_LABEL
		if a.Type == pkcs11.CKA_LABEL {
			if a.Value[0] == 0x72 { // Label start with 'r'
				return []pkcs11.ObjectHandle{rsaPrivateKeyHandle}, true, nil
			} else if a.Value[0] == 0x65 { // Label start with 'e'
				return []pkcs11.ObjectHandle{ecPrivateKeyHandle}, true, nil
			} else if a.Value[0] == 0x6E { // Label start with 'n'
				return []pkcs11.ObjectHandle{ecPrivNoPubHandle}, true, nil
			} else if a.Value[0] == 0x69 { // Label start with 'i'
				return []pkcs11.ObjectHandle{ecInvEcPointPrivHandle}, true, nil
			}
		}
		// We search th EC public key using CKA_ID
		if a.Type == pkcs11.CKA_ID {
			if a.Value[0] == 0x3 {
				return []pkcs11.ObjectHandle{ecPublicKeyHandle}, true, nil
			} else if a.Value[0] == 0x5 {
				return []pkcs11.ObjectHandle{ecInvEcPointPubHandle}, true, nil
			} else {
				return []pkcs11.ObjectHandle{}, true, nil
			}
		}
	}
	return nil, false, nil
}

func rsaPrivateAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		// Return simple values for these attributes. Note that a value of `1` for
		// both modulus an public exponent would be a very bad public key, but it's
		// sufficient to satisfy the current code.
		if a.Type == pkcs11.CKA_MODULUS ||
			a.Type == pkcs11.CKA_PUBLIC_EXPONENT ||
			a.Type == pkcs11.CKA_ALWAYS_AUTHENTICATE {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: []byte{byte(1)},
			})
		}
		if a.Type == pkcs11.CKA_KEY_TYPE {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: []byte{byte(0)},
			})
		}
	}
	return output, nil
}

var ecOid = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

func ecPrivateAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		if a.Type == pkcs11.CKA_EC_PARAMS {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: ecOid,
			})
		}
		if a.Type == pkcs11.CKA_KEY_TYPE ||
			a.Type == pkcs11.CKA_ID {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: []byte{byte(3)},
			})
		}
	}
	return output, nil
}

var ecPoint = []byte{0x04, 0x41, 0x04, 0x4C, 0xD7, 0x7B, 0x7B, 0x2E,
	0x3D, 0x57, 0x98, 0xB8, 0x2F, 0x99, 0xB4, 0x83,
	0x99, 0xE6, 0xD4, 0x4C, 0x4F, 0xBC, 0x2D, 0x60,
	0xCD, 0x08, 0x8E, 0x93, 0x65, 0x6F, 0x20, 0x51,
	0x1C, 0xE7, 0xFD, 0x59, 0x34, 0xAA, 0xA9, 0x36,
	0x26, 0xCE, 0x4A, 0xC5, 0xA2, 0x4A, 0x85, 0x6C,
	0xB3, 0x95, 0xFF, 0x92, 0x0F, 0x56, 0x76, 0x34,
	0x1F, 0x69, 0x52, 0x5F, 0x20, 0x83, 0x13, 0x50,
	0xA3, 0xDE, 0xBE}

func ecPublicAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		if a.Type == pkcs11.CKA_EC_PARAMS {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: ecOid,
			})
		}
		if a.Type == pkcs11.CKA_EC_POINT {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: ecPoint,
			})
		}
		if a.Type == pkcs11.CKA_KEY_TYPE ||
			a.Type == pkcs11.CKA_ID {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: []byte{byte(3)},
			})
		}
	}
	return output, nil
}

func ecPrivNoPubAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		if a.Type == pkcs11.CKA_EC_PARAMS {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: ecOid,
			})
		}
		if a.Type == pkcs11.CKA_KEY_TYPE {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: []byte{byte(3)},
			})
		}
		if a.Type == pkcs11.CKA_ID {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: []byte{byte(4)},
			})
		}
	}
	return output, nil
}

func ecInvalidEcPointAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		if a.Type == pkcs11.CKA_EC_PARAMS {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: ecOid,
			})
		}
		if a.Type == pkcs11.CKA_EC_POINT {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: []byte{byte(0)},
			})
		}
		if a.Type == pkcs11.CKA_KEY_TYPE {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: []byte{byte(3)},
			})
		}
		if a.Type == pkcs11.CKA_ID {
			output = append(output, &pkcs11.Attribute{
				Type:  a.Type,
				Value: []byte{byte(5)},
			})
		}
	}
	return output, nil
}


func (c mockCtx) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	if o == rsaPrivateKeyHandle {
		return rsaPrivateAttributes(template)
	} else if o == ecPrivateKeyHandle {
		return ecPrivateAttributes(template)
	} else if o == ecPublicKeyHandle {
		return ecPublicAttributes(template)
	} else if o == ecPrivNoPubHandle {
		return ecPrivNoPubAttributes(template)
	} else if o == ecInvEcPointPrivHandle {
		return ecInvalidEcPointAttributes(template)
	} else if o == ecInvEcPointPubHandle {
		return ecInvalidEcPointAttributes(template)
	}
	return nil, nil
}

func (c mockCtx) GetSlotList(tokenPresent bool) ([]uint, error) {
	return slots, nil
}

func (c mockCtx) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	return tokenInfo, nil
}

func (c mockCtx) Initialize() error {
	return nil
}

func (c mockCtx) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	return nil
}

func (c mockCtx) Logout(sh pkcs11.SessionHandle) error {
	return nil
}

func (c mockCtx) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	return sessionHandle, nil
}

func (c mockCtx) SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return nil
}

func (c mockCtx) Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	return message, nil
}

func setup(t *testing.T, label string) *Key {
	ps := Key{
		module:     mockCtx{},
		tokenLabel: "token label",
		pin:        "unused",
	}
	err := ps.setup(label)
	if err != nil {
		t.Fatalf("Failed to set up Key: %s", err)
	}
	return &ps
}

var signInput = []byte("1234567890 1234567890 1234567890")
func sign(t *testing.T, ps *Key) ([]byte) {
	// Sign input must be exactly 32 bytes to match SHA256 size. In normally
	// usage, Sign would be called by e.g. x509.CreateCertificate, which would
	// handle padding to the necessary size.
	output, err := ps.Sign(rand.Reader, signInput, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign: %s", err)
	}

	if len(output) < len(signInput) {
		t.Fatalf("Invalid signature size: got %d bytes expected at least %d",
			len(output), len(signInput))
	}

	i := len(output) - len(signInput)
	if !bytes.Equal(output[i:], signInput) {
		t.Fatal("Incorrect sign output got %v expected %v", output, signInput)
	}
	return output
}

func TestSign(t *testing.T) {
	ps := setup(t, "rsa")
	sig := sign(t, ps)
	
	// Check that the RSA signature starts with the SHA256 hash prefix
	var sha256_pre = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	if !(bytes.Equal(sha256_pre, sig[0:19])) {
		t.Fatal("RSA signature doesn't start with prefix")
	}

	pub := ps.Public()
	// Check public key is of right type
	_ = pub.(*rsa.PublicKey)

	ps = setup(t, "ec")
	sig = sign(t, ps)

	if !(bytes.Equal(signInput, sig)) {
		t.Fatal("ECDSA signature error: got %v expected %v", sig, signInput)
	}

	pub = ps.Public()
	// Check public key is of right type
	ecPub := pub.(*ecdsa.PublicKey)
	if !(bytes.Equal(ecPub.X.Bytes(), ecPoint[3:35]) &&
		bytes.Equal(ecPub.Y.Bytes(), ecPoint[35:])) {
		t.Fatal("Incorrect decoding of EC Point")		
	}

	k := Key{
		module:     mockCtx{},
		tokenLabel: "token label",
		pin:        "unused",
	}

	// Trying to load private EC key with no public key
	err := k.setup("no_pub_ec")
	if err == nil {
		t.Fatalf("Unexpected succes: %v", k)
	}

	// Trying to load private EC key with no public key
	err = k.setup("invalid_ec_point")
	if err == nil {
		t.Fatalf("Unexpected succes: %v", k)
	}
}

// This is a version of the mock that gives CKR_ATTRIBUTE_TYPE_INVALID when
// asked about the CKA_ALWAYS_AUTHENTICATE attribute.
type mockCtxFailsAlwaysAuthenticate struct {
	mockCtx
}

func (c mockCtxFailsAlwaysAuthenticate) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	for _, a := range template {
		if a.Type == pkcs11.CKA_ALWAYS_AUTHENTICATE {
			return nil, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)
		}
	}
	return c.mockCtx.GetAttributeValue(sh, o, template)
}

func TestAttributeTypeInvalid(t *testing.T) {
	ps := &Key{
		module:     mockCtxFailsAlwaysAuthenticate{},
		tokenLabel: "token label",
		pin:        "unused",
	}
	err := ps.setup("rsa")
	if err != nil {
		t.Errorf("Failed to set up with a token that returns CKR_ATTRIBUTE_TYPE_INVALID: %s", err)
	}
}
