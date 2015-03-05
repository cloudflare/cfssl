package universal

import (
	"testing"
)

func TestNewPKCS11Signer(t *testing.T) {
	h := map[string]string{
		"rsc": "abc",
		"r":   "def",
	}
	var r = &Root{
		Config:      h,
		ForceRemote: false,
	}
	_, _, err := pkcs11Signer(r, nil)
	if err != nil {
		t.Fatal(err)
	}

}
