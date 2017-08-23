package jwtauth

import (
	"io/ioutil"
	"testing"
)

const (
	signingKey         = "../cli/gencrl/testdata/ca-keyTwo.pem"
	signingPubKey      = "../cli/gencrl/testdata/caTwo.pem"
	createdToken       = "testdata/token"
	createdTokenPubKey = "testdata/token.pubkey"
)

func TestValidTokens(t *testing.T) {
	pubBytes, err := ioutil.ReadFile(createdTokenPubKey)
	if err != nil {
		t.Fatal(err)
	}

	createdTokenBytes, err := ioutil.ReadFile(createdToken)
	if err != nil {
		t.Fatal(err)
	}

	retVal, err := Verify(pubBytes, string(createdTokenBytes))
	if err != nil {
		t.Fatal(err)
	}

	if retVal == false {
		t.Fatal("Wrong retval, should be valid")
	}

}
