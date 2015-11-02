// +build !nopkcs11

package pkcs11key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"github.com/miekg/pkcs11"
	"reflect"
	"strings"
	"testing"
)

type mockCtx struct {
	currentSearch []*pkcs11.Attribute
}

const sessionHandle = pkcs11.SessionHandle(17)
const rsaPrivateKeyHandle = pkcs11.ObjectHandle(23)

// Correct EC private key
const ecPrivateKeyHandle = pkcs11.ObjectHandle(32)
const ecPublicKeyHandle = pkcs11.ObjectHandle(33)
const ecCorrectKeyID = byte(0x03)

// EC private key with no matching public key
const ecPrivNoPubHandle = pkcs11.ObjectHandle(34)
const ecPrivNoPubID = byte(0x4)

// EC private and public key with invalid EC point
const ecInvEcPointPrivHandle = pkcs11.ObjectHandle(35)
const ecInvEcPointPubHandle = pkcs11.ObjectHandle(36)
const ecInvEcPointID = byte(0x5)

var slots = []uint{7, 8, 9}
var tokenInfo = pkcs11.TokenInfo{
	Label: "token label",
}

func (c *mockCtx) CloseSession(sh pkcs11.SessionHandle) error {
	return nil
}

func (c *mockCtx) FindObjectsFinal(sh pkcs11.SessionHandle) error {
	c.currentSearch = []*pkcs11.Attribute{}
	return nil
}

func (c *mockCtx) FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error {
	c.currentSearch = temp
	return nil
}

func (c *mockCtx) FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error) {
	for _, a := range c.currentSearch {
		// We search private keys using CKA_LABEL
		if a.Type == pkcs11.CKA_LABEL {
			switch string(a.Value) {
			case "rsa":
				return []pkcs11.ObjectHandle{rsaPrivateKeyHandle}, true, nil
			case "ec":
				return []pkcs11.ObjectHandle{ecPrivateKeyHandle}, true, nil
			case "no_public_key_ec":
				return []pkcs11.ObjectHandle{ecPrivNoPubHandle}, true, nil
			case "invalid_ec_point":
				return []pkcs11.ObjectHandle{ecInvEcPointPrivHandle}, true, nil
			}
		}
		// We search th EC public key using CKA_ID
		if a.Type == pkcs11.CKA_ID {
			switch a.Value[0] {
			case ecCorrectKeyID:
				return []pkcs11.ObjectHandle{ecPublicKeyHandle}, true, nil
			case ecInvEcPointID:
				return []pkcs11.ObjectHandle{ecInvEcPointPubHandle}, true, nil
			default:
				return []pkcs11.ObjectHandle{}, true, nil
			}
		}
	}
	return nil, false, nil
}

func p11Attribute(Type uint, Value []byte) *pkcs11.Attribute {
	return &pkcs11.Attribute{
		Type:  Type,
		Value: Value,
	}
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
			output = append(output, p11Attribute(a.Type, []byte{byte(1)}))
		}
		if a.Type == pkcs11.CKA_KEY_TYPE {
			output = append(output, p11Attribute(a.Type, []byte{byte(pkcs11.CKK_RSA)}))
		}
	}
	return output, nil
}

var ecOid = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

var ecPoint = []byte{0x04, 0x41, 0x04, 0x4C, 0xD7, 0x7B, 0x7B, 0x2E,
	0x3D, 0x57, 0x98, 0xB8, 0x2F, 0x99, 0xB4, 0x83,
	0x99, 0xE6, 0xD4, 0x4C, 0x4F, 0xBC, 0x2D, 0x60,
	0xCD, 0x08, 0x8E, 0x93, 0x65, 0x6F, 0x20, 0x51,
	0x1C, 0xE7, 0xFD, 0x59, 0x34, 0xAA, 0xA9, 0x36,
	0x26, 0xCE, 0x4A, 0xC5, 0xA2, 0x4A, 0x85, 0x6C,
	0xB3, 0x95, 0xFF, 0x92, 0x0F, 0x56, 0x76, 0x34,
	0x1F, 0x69, 0x52, 0x5F, 0x20, 0x83, 0x13, 0x50,
	0xA3, 0xDE, 0xBE}

func ecCorrectKeyAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		switch a.Type {
		case pkcs11.CKA_EC_PARAMS:
			output = append(output, p11Attribute(a.Type, ecOid))
		case pkcs11.CKA_EC_POINT:
			output = append(output, p11Attribute(a.Type, ecPoint))
		case pkcs11.CKA_KEY_TYPE:
			output = append(output, p11Attribute(a.Type, []byte{byte(pkcs11.CKK_EC)}))
		case pkcs11.CKA_ID:
			output = append(output, p11Attribute(a.Type, []byte{byte(ecCorrectKeyID)}))
		}
	}
	return output, nil
}

func ecPrivNoPubAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		switch a.Type {
		case pkcs11.CKA_EC_PARAMS:
			output = append(output, p11Attribute(a.Type, ecOid))
		case pkcs11.CKA_KEY_TYPE:
			output = append(output, p11Attribute(a.Type, []byte{byte(pkcs11.CKK_EC)}))
		case pkcs11.CKA_ID:
			output = append(output, p11Attribute(a.Type, []byte{byte(ecPrivNoPubID)}))
		}
	}
	return output, nil
}

func ecInvalidEcPointAttributes(template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	var output []*pkcs11.Attribute
	for _, a := range template {
		switch a.Type {
		case pkcs11.CKA_EC_PARAMS:
			output = append(output, p11Attribute(a.Type, ecOid))
		case pkcs11.CKA_EC_POINT:
			output = append(output, p11Attribute(a.Type, []byte{0x04, 0x5, 0x04, 0x1, 0x2, 0x3, 0x4}))
		case pkcs11.CKA_KEY_TYPE:
			output = append(output, p11Attribute(a.Type, []byte{byte(pkcs11.CKK_EC)}))
		case pkcs11.CKA_ID:
			output = append(output, p11Attribute(a.Type, []byte{byte(ecInvEcPointID)}))
		}
	}
	return output, nil
}

func (c *mockCtx) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	if o == rsaPrivateKeyHandle {
		return rsaPrivateAttributes(template)
	} else if o == ecPrivateKeyHandle {
		return ecCorrectKeyAttributes(template)
	} else if o == ecPublicKeyHandle {
		return ecCorrectKeyAttributes(template)
	} else if o == ecPrivNoPubHandle {
		return ecPrivNoPubAttributes(template)
	} else if o == ecInvEcPointPrivHandle {
		return ecInvalidEcPointAttributes(template)
	} else if o == ecInvEcPointPubHandle {
		return ecInvalidEcPointAttributes(template)
	}
	return nil, nil
}

func (c *mockCtx) GetSlotList(tokenPresent bool) ([]uint, error) {
	return slots, nil
}

func (c *mockCtx) GetTokenInfo(slotID uint) (pkcs11.TokenInfo, error) {
	return tokenInfo, nil
}

func (c *mockCtx) Initialize() error {
	return nil
}

func (c *mockCtx) Login(sh pkcs11.SessionHandle, userType uint, pin string) error {
	return nil
}

func (c *mockCtx) Logout(sh pkcs11.SessionHandle) error {
	return nil
}

func (c *mockCtx) OpenSession(slotID uint, flags uint) (pkcs11.SessionHandle, error) {
	return sessionHandle, nil
}

func (c *mockCtx) SignInit(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return nil
}

func (c *mockCtx) Sign(sh pkcs11.SessionHandle, message []byte) ([]byte, error) {
	return message, nil
}

func setup(t *testing.T, label string) *Key {
	ps := Key{
		module:     &mockCtx{},
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

func sign(t *testing.T, ps *Key) []byte {
	// Sign input must be exactly 32 bytes to match SHA256 size. In normally
	// usage, Sign would be called by e.g. x509.CreateCertificate, which would
	// handle padding to the necessary size.
	output, err := ps.Sign(rand.Reader, signInput, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign: %s", err)
	}

	if len(output) < len(signInput) {
		t.Fatalf("Invalid signature size")
	}

	i := len(output) - len(signInput)
	if !bytes.Equal(output[i:], signInput) {
		t.Fatal("Incorrect sign output")
	}
	return output
}

func TestSign(t *testing.T) {
	ps := setup(t, "rsa")
	sig := sign(t, ps)

	// Check that the RSA signature starts with the SHA256 hash prefix
	var sha256Pre = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	if !(bytes.Equal(sha256Pre, sig[0:19])) {
		t.Fatal("RSA signature doesn't start with prefix")
	}

	pub := ps.Public()
	// Check public key is of right type
	_, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Errorf("Attempted to load RSA key from module, got key of type %s. Expected *rsa.PublicKey", reflect.TypeOf(pub))
	}

	ps = setup(t, "ec")
	sig = sign(t, ps)

	if !(bytes.Equal(signInput, sig)) {
		t.Fatal("ECDSA signature error")
	}
}

func TestReadECPoint(t *testing.T) {
	ps := setup(t, "ec")
	pub := ps.Public()
	// Check public key is of right type
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Attempted to load ECDSA key from module, got key of type %s. Expected *ecdsa.PublicKey", reflect.TypeOf(pub))
	}

	// Disable this test because it can only work in go 1.5 and later
	// if strings.Compare(ecPub.Curve.Params().Name, "P-256") != 0 {
	// 	t.Fatal("Invalid curve decoded")
	// }

	curve := namedCurveFromOID(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	x, y := readECPoint(curve, ecPoint)

	if !(bytes.Equal(ecPub.X.Bytes(), x.Bytes()) &&
		bytes.Equal(ecPub.Y.Bytes(), y.Bytes())) {
		t.Errorf("Incorrect value for EC Point with ASN.1")
	}

	x, y = readECPoint(curve, ecPoint[2:])
	if !(bytes.Equal(ecPub.X.Bytes(), x.Bytes()) &&
		bytes.Equal(ecPub.Y.Bytes(), y.Bytes())) {
		t.Errorf("Incorrect value for EC Point without ASN.1")
	}

	x, y = readECPoint(curve, []byte{0x04, 0x05, 0x04, 0x1, 0x2, 0x3, 0x4})
	if x != nil {
		t.Errorf("Unexpected EC point with ASN.1")
	}

	x, y = readECPoint(curve, []byte{0x04, 0x1, 0x2, 0x3, 0x4})
	if x != nil {
		t.Errorf("Unexpected EC point with ASN.1")
	}

}

func TestEcKeyErrors(t *testing.T) {
	k := Key{
		module:     &mockCtx{},
		tokenLabel: "token label",
		pin:        "unused",
	}

	// Trying to load private EC key with no public key
	err := k.setup("no_public_key_ec")
	if err == nil {
		t.Errorf("Unexpected success")
	}
	if strings.Compare(err.Error(), "public key not found") != 0 {
		t.Errorf("Unexpected error value: %v", err)
	}

	// Trying to load private EC key with invalid EC point
	err = k.setup("invalid_ec_point")
	if err == nil {
		t.Errorf("Unexpected success")
	}
	if strings.Compare(err.Error(), "invalid EC Point") != 0 {
		t.Errorf("Unexpected error value: %v", err)
	}
}

// This is a version of the mock that gives CKR_ATTRIBUTE_TYPE_INVALID when
// asked about the CKA_ALWAYS_AUTHENTICATE attribute.
type mockCtxFailsAlwaysAuthenticate struct {
	mockCtx
}

func (c *mockCtxFailsAlwaysAuthenticate) GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	for _, a := range template {
		if a.Type == pkcs11.CKA_ALWAYS_AUTHENTICATE {
			return nil, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID)
		}
	}
	return c.mockCtx.GetAttributeValue(sh, o, template)
}

func TestAttributeTypeInvalid(t *testing.T) {
	ps := &Key{
		module:     &mockCtxFailsAlwaysAuthenticate{},
		tokenLabel: "token label",
		pin:        "unused",
	}
	err := ps.setup("rsa")
	if err != nil {
		t.Errorf("Failed to set up with a token that returns CKR_ATTRIBUTE_TYPE_INVALID: %s", err)
	}
}
