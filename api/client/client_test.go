package client

import (
	"net"
	"testing"

	"github.com/cloudflare/cfssl/auth"
)

var (
	testProvider auth.Provider
	testKey      = "0123456789ABCDEF0123456789ABCDEF"
	testAD       = []byte{1, 2, 3, 4} // IP address 1.2.3.4
)

func TestNewServer(t *testing.T) {
	s := NewServer("1.1.1.1:::123456789")

	if s != nil {
		t.Fatalf("fatal error, server created with too many colons %v", s)
	}

	s2 := NewServer("1.1.1.1:[]")
	if s != nil {
		t.Fatalf("%v", s2)

	}

	_, port, _ := net.SplitHostPort("")
	if port != "" {
		t.Fatalf("%v", port)

	}
}

func TestInvalidPort(t *testing.T) {
	s := NewServer("1.1.1.1:99999999999999999999999999999")
	if s != nil {
		t.Fatalf("%v", s)
	}
}

func TestAuthSign(t *testing.T) {
	s := NewServer("1.1")
	testProvider, _ = auth.New(testKey, nil)
	testRequest := []byte(`testing 1 2 3`)
	as, _ := s.AuthSign(testRequest, testAD, testProvider)
	if as != nil {
		t.Fatal("fatal error with auth sign function")
	}
}

func TestSign(t *testing.T) {
	s := NewServer("1.1")
	sign, _ := s.Sign([]byte{5, 5, 5, 5})
	if sign != nil {
		t.Fatalf("%v", sign)
	}
}
