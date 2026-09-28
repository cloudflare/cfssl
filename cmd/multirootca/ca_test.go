package main

import (
	"crypto/mldsa"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/multiroot/config"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/whitelist"
)

func TestLoadSignersRejectsMLDSAWithoutRegisteringSigner(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("generating ML-DSA key: %v", err)
	}

	loadedSigners := map[string]signer.Signer{}
	loadedWhitelists := map[string]whitelist.NetACL{}
	err = loadSigners(config.RootList{
		"unsupported": {PrivateKey: key},
	}, loadedSigners, loadedWhitelists)
	if err == nil {
		t.Fatal("loadSigners accepted an unsupported ML-DSA root")
	}
	if !strings.Contains(err.Error(), `load signer "unsupported": unsupported private key type`) {
		t.Fatalf("loadSigners error = %q, want label and parseSigner error", err)
	}
	if len(loadedSigners) != 0 {
		t.Fatalf("loadSigners registered %d signer(s) after rejecting the root", len(loadedSigners))
	}
	if len(loadedWhitelists) != 0 {
		t.Fatalf("loadSigners registered %d whitelist(s) after rejecting the root", len(loadedWhitelists))
	}
}
