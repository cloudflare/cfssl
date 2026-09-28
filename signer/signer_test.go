package signer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
)

func TestAppendIf(t *testing.T) {
	s := ""
	a := make([]string, 0, 5)
	appendIf(s, &a)
	if len(a) != 0 {
		t.Fatal("appendIf should not append to a with an empty s")
	}
	s = "test"
	appendIf(s, &a)
	if len(a[0]) != 4 {
		t.Fatal("appendIf should append s to a")
	}
}

func TestSplitHosts(t *testing.T) {
	list := SplitHosts("")
	if list != nil {
		t.Fatal("SplitHost should return nil with empty input")
	}

	list = SplitHosts("single.domain")
	if len(list) != 1 {
		t.Fatal("SplitHost fails to split single domain")
	}

	list = SplitHosts("comma,separated,values")
	if len(list) != 3 {
		t.Fatal("SplitHost fails to split multiple domains")
	}
	if list[0] != "comma" || list[1] != "separated" || list[2] != "values" {
		t.Fatal("SplitHost fails to split multiple domains")
	}
}

func TestAddPolicies(t *testing.T) {
	var cert x509.Certificate
	addPolicies(&cert, []config.CertificatePolicy{
		{
			ID: config.OID([]int{1, 2, 3, 4}),
		},
	})

	if len(cert.ExtraExtensions) != 1 {
		t.Fatal("No extension added")
	}
	ext := cert.ExtraExtensions[0]
	if !reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 32}) {
		t.Fatal(fmt.Sprintf("Wrong OID for policy qualifier %v", ext.Id))
	}
	if ext.Critical {
		t.Fatal("Policy qualifier marked critical")
	}
	expectedBytes, _ := hex.DecodeString("3007300506032a0304")
	if !bytes.Equal(ext.Value, expectedBytes) {
		t.Fatal(fmt.Sprintf("Value didn't match expected bytes: got %s, expected %s",
			hex.EncodeToString(ext.Value), hex.EncodeToString(expectedBytes)))
	}
}

func TestAddPoliciesWithQualifiers(t *testing.T) {
	var cert x509.Certificate
	addPolicies(&cert, []config.CertificatePolicy{
		{
			ID: config.OID([]int{1, 2, 3, 4}),
			Qualifiers: []config.CertificatePolicyQualifier{
				{
					Type:  "id-qt-cps",
					Value: "http://example.com/cps",
				},
				{
					Type:  "id-qt-unotice",
					Value: "Do What Thou Wilt",
				},
			},
		},
	})

	if len(cert.ExtraExtensions) != 1 {
		t.Fatal("No extension added")
	}
	ext := cert.ExtraExtensions[0]
	if !reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 32}) {
		t.Fatal(fmt.Sprintf("Wrong OID for policy qualifier %v", ext.Id))
	}
	if ext.Critical {
		t.Fatal("Policy qualifier marked critical")
	}
	expectedBytes, _ := hex.DecodeString("304e304c06032a03043045302206082b060105050702011616687474703a2f2f6578616d706c652e636f6d2f637073301f06082b0601050507020230130c11446f20576861742054686f752057696c74")
	if !bytes.Equal(ext.Value, expectedBytes) {
		t.Fatal(fmt.Sprintf("Value didn't match expected bytes: %s vs %s",
			hex.EncodeToString(ext.Value), hex.EncodeToString(expectedBytes)))
	}
}

func TestIsCaManagedExtension(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want bool
	}{
		{"KeyUsage", asn1.ObjectIdentifier{2, 5, 29, 15}, true},
		{"ExtKeyUsage", asn1.ObjectIdentifier{2, 5, 29, 37}, true},
		{"BasicConstraints", asn1.ObjectIdentifier{2, 5, 29, 19}, true},
		{"SubjectKeyIdentifier", asn1.ObjectIdentifier{2, 5, 29, 14}, true},
		{"AuthorityKeyIdentifier", asn1.ObjectIdentifier{2, 5, 29, 35}, true},
		{"AuthorityInfoAccess", asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, true},
		{"CRLDistributionPoints", asn1.ObjectIdentifier{2, 5, 29, 31}, true},
		{"CertificatePolicies", asn1.ObjectIdentifier{2, 5, 29, 32}, true},
		{"NameConstraints", asn1.ObjectIdentifier{2, 5, 29, 30}, true},
		{"SubjectAltName", asn1.ObjectIdentifier{2, 5, 29, 17}, true},
		{"IssuerAltName", asn1.ObjectIdentifier{2, 5, 29, 18}, true},
		{"private use OID", asn1.ObjectIdentifier{1, 2, 3, 4, 5}, false},
		{"DelegationUsage", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}, false},
		{"CT Poison", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCaManagedExtension(tt.oid)
			if got != tt.want {
				t.Errorf("isCaManagedExtension(%v) = %v, want %v", tt.oid, got, tt.want)
			}
		})
	}
}

func TestName(t *testing.T) {
	sub := &Subject{
		CN: "foobar",
		Names: []csr.Name{
			{
				C:  "US",
				ST: "CA",
				L:  "Cool Locality",
				O:  "Cool Org",
				OU: "Really Cool Sub Org",
			},
			{
				L: "Another Cool Locality",
			},
		},
		SerialNumber: "deadbeef",
	}
	name := sub.Name()
	if name.CommonName != sub.CN {
		t.Errorf("CommonName: want %#v, got %#v", sub.CN, name.CommonName)
	}
	if name.SerialNumber != sub.SerialNumber {
		t.Errorf("SerialNumber: want %#v, got %#v", sub.SerialNumber, name.SerialNumber)
	}
	if !reflect.DeepEqual([]string{"US"}, name.Country) {
		t.Errorf("Country: want %s, got %s", []string{"US"}, name.Country)
	}
	if !reflect.DeepEqual([]string{"CA"}, name.Province) {
		t.Errorf("Province: want %s, got %s", []string{"CA"}, name.Province)
	}
	if !reflect.DeepEqual([]string{"Cool Org"}, name.Organization) {
		t.Errorf("Organization: want %s, got %s", []string{"Cool Org"}, name.Organization)
	}
	if !reflect.DeepEqual([]string{"Really Cool Sub Org"}, name.OrganizationalUnit) {
		t.Errorf("Organizational Unit: want %s, got %s", []string{"Really Cool Sub Org"}, name.OrganizationalUnit)
	}
	if !reflect.DeepEqual([]string{"Cool Locality", "Another Cool Locality"}, name.Locality) {
		t.Errorf("Locality: want %s, got %s", []string{"CA"}, name.Locality)
	}

}

func TestDefaultSigAlgoMLDSA(t *testing.T) {
	tests := []struct {
		name   string
		params mldsa.Parameters
		want   x509.SignatureAlgorithm
	}{
		{"MLDSA44", mldsa.MLDSA44(), x509.MLDSA44},
		{"MLDSA65", mldsa.MLDSA65(), x509.MLDSA65},
		{"MLDSA87", mldsa.MLDSA87(), x509.MLDSA87},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			priv, err := mldsa.GenerateKey(tt.params)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			got := DefaultSigAlgo(priv)
			if got != tt.want {
				t.Errorf("DefaultSigAlgo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFillTemplateMLDSAKeyUsage(t *testing.T) {
	allKeyUsages := []string{
		"signing", "digital signature", "content commitment", "key encipherment", "data encipherment",
		"key agreement", "cert sign", "crl sign", "encipher only", "decipher only",
	}
	noKeyUsagesCode := cferr.New(cferr.PolicyError, cferr.NoKeyUsages).ErrorCode

	tests := []struct {
		name    string
		usage   []string
		isCA    bool
		wantKU  x509.KeyUsage
		wantEKU []x509.ExtKeyUsage
		wantErr bool
	}{
		{
			name:    "DefaultProfileDropsKeyEncipherment",
			usage:   config.DefaultConfig().Usage,
			wantKU:  x509.KeyUsageDigitalSignature,
			wantEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		},
		{
			name:   "AllKeyUsagesKeepsOnlySignatureUsages",
			usage:  allKeyUsages,
			wantKU: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		},
		{
			name:    "OnlyKeyEnciphermentReturnsNoKeyUsages",
			usage:   []string{"key encipherment"},
			wantErr: true,
		},
		{
			name:    "OnlyKeyEnciphermentWithEKUReturnsNoKeyUsages",
			usage:   []string{"key encipherment", "server auth"},
			wantErr: true,
		},
		{
			name:    "OnlyKeyAgreementWithEKUReturnsNoKeyUsages",
			usage:   []string{"key agreement", "client auth"},
			wantErr: true,
		},
		{
			name:    "CAOnlyKeyEnciphermentWithEKUReturnsNoKeyUsages",
			usage:   []string{"key encipherment", "server auth"},
			isCA:    true,
			wantErr: true,
		},
		{
			name:    "OnlyEKUKeepsEKUWithoutKeyUsage",
			usage:   []string{"server auth"},
			wantEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
	}

	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			t.Fatalf("GenerateKey(%v) failed: %v", params, err)
		}
		for _, tt := range tests {
			t.Run(params.String()+"/"+tt.name, func(t *testing.T) {
				profile := config.DefaultConfig()
				profile.Usage = tt.usage
				profile.CAConstraint.IsCA = tt.isCA
				template := &x509.Certificate{PublicKey: key.PublicKey()}

				err := FillTemplate(template, config.DefaultConfig(), profile, time.Time{}, time.Time{})
				if tt.wantErr {
					var cfErr *cferr.Error
					if !errors.As(err, &cfErr) || cfErr.ErrorCode != noKeyUsagesCode {
						t.Fatalf("FillTemplate() error = %v, want NoKeyUsages policy error (code %d)", err, noKeyUsagesCode)
					}
					return
				}
				if err != nil {
					t.Fatalf("FillTemplate() failed: %v", err)
				}
				if template.KeyUsage != tt.wantKU {
					t.Errorf("KeyUsage = %#b, want %#b", template.KeyUsage, tt.wantKU)
				}
				if !reflect.DeepEqual(template.ExtKeyUsage, tt.wantEKU) {
					t.Errorf("ExtKeyUsage = %v, want %v", template.ExtKeyUsage, tt.wantEKU)
				}
			})
		}
	}
}

func TestFillTemplateClassicalKeyUsageUnchanged(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}
	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}

	keys := []struct {
		name string
		pub  crypto.PublicKey
	}{
		{"RSA", &rsaKey.PublicKey},
		{"ECDSA", &ecdsaKey.PublicKey},
		{"Ed25519", ed25519Pub},
	}
	profiles := []struct {
		name   string
		usage  []string
		wantKU x509.KeyUsage
	}{
		{"DefaultProfile", config.DefaultConfig().Usage, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		{"OnlyKeyEnciphermentWithEKU", []string{"key encipherment", "server auth"}, x509.KeyUsageKeyEncipherment},
	}

	for _, p := range profiles {
		for _, k := range keys {
			t.Run(p.name+"/"+k.name, func(t *testing.T) {
				profile := config.DefaultConfig()
				profile.Usage = p.usage
				template := &x509.Certificate{PublicKey: k.pub}
				if err := FillTemplate(template, config.DefaultConfig(), profile, time.Time{}, time.Time{}); err != nil {
					t.Fatalf("FillTemplate() failed: %v", err)
				}
				if template.KeyUsage != p.wantKU {
					t.Errorf("KeyUsage = %#b, want %#b", template.KeyUsage, p.wantKU)
				}
			})
		}
	}
}
