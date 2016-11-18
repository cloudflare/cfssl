package tls

import "testing"

func TestHashAlgorithmString(t *testing.T) {
	var tests = []struct {
		algo HashAlgorithm
		want string
	}{
		{None, "None"},
		{MD5, "MD5"},
		{SHA1, "SHA1"},
		{SHA224, "SHA224"},
		{SHA256, "SHA256"},
		{SHA384, "SHA384"},
		{SHA512, "SHA512"},
		{99, "UNKNOWN(99)"},
	}
	for _, test := range tests {
		if got := test.algo.String(); got != test.want {
			t.Errorf("%v.String()=%q; want %q", test.algo, got, test.want)
		}
	}
}

func TestSignatureAlgorithmString(t *testing.T) {
	var tests = []struct {
		algo SignatureAlgorithm
		want string
	}{
		{Anonymous, "Anonymous"},
		{RSA, "RSA"},
		{DSA, "DSA"},
		{ECDSA, "ECDSA"},
		{99, "UNKNOWN(99)"},
	}
	for _, test := range tests {
		if got := test.algo.String(); got != test.want {
			t.Errorf("%v.String()=%q; want %q", test.algo, got, test.want)
		}
	}
}
