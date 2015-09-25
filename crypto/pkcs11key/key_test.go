package pkcs11key

import (
	"crypto"
	"crypto/rand"
	"bytes"
	"testing"
	"github.com/miekg/pkcs11"
)

type mockCtx struct{}

const privateKeyHandle = pkcs11.ObjectHandle(23)
const sessionHandle = pkcs11.SessionHandle(17)
var slots = []uint{7, 8, 9}
var tokenInfo = pkcs11.TokenInfo{
	Label: "token label",
}

func (c mockCtx) CloseSession(sh pkcs11.SessionHandle) error {
	return nil
}

func (c mockCtx) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	return nil
}

func (c mockCtx) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	return nil
}

func (c mockCtx) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	return []pkcs11.ObjectHandle{privateKeyHandle}, true, nil
}

func (c mockCtx) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		// Return simple values for these attributes. Note that a value of `1` for
		// both modulus an public exponent would be a very bad public key, but it's
		// sufficient to satisfy the current code.
		if a.Type == pkcs11.CKA_MODULUS ||
			 a.Type == pkcs11.CKA_PUBLIC_EXPONENT ||
			 a.Type == pkcs11.CKA_ALWAYS_AUTHENTICATE {
			output = append(output, &pkcs11.Attribute{
				Type: a.Type,
				Value: []byte{byte(1)},
			})
		}
	}
	return output, nil
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
	return []byte("some signed data"), nil
}

func TestSetup(t *testing.T) {
	ps := &Key{
		module: mockCtx{},
		tokenLabel: "token label",
		pin: "unused",
	}
	err := ps.setup("private key label")
	if err != nil {
		t.Errorf("Failed to set up Key: %s", err)
	}
}

func setup(t *testing.T) *Key {
	ps := Key{
		module: mockCtx{},
		tokenLabel: "token label",
		pin: "unused",
	}
	err := ps.setup("private key label")
	if err != nil {
		t.Fatalf("Failed to set up Key: %s", err)
	}
	return &ps
}

func TestSign(t *testing.T) {
	ps := setup(t)
	// Sign input must be exactly 32 bytes to match SHA256 size. In normally
	// usage, Sign would be called by e.g. x509.CreateCertificate, which would
	// handle padding to the necessary size.
	signInput := []byte("1234567890 1234567890 1234567890")
	output, err := ps.Sign(rand.Reader, signInput, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign: %s", err)
	}
	if !bytes.Equal(output, []byte("some signed data")) {
		t.Fatal("Incorrect sign output")
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
		module: mockCtxFailsAlwaysAuthenticate{},
		tokenLabel: "token label",
		pin: "unused",
	}
	err := ps.setup("private key label")
	if err != nil {
		t.Errorf("Failed to set up with a token that returns CKR_ATTRIBUTE_TYPE_INVALID: %s", err)
	}
}
