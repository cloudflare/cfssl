package bundler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/ubiquity"
)

const (
	remoteServerName = "bundle.remote.test"
	remoteWildcard   = "*.remote.test"
	remoteIP         = "192.0.2.1"
)

func TestBundleFromRemote(t *testing.T) {
	originalPlatforms := ubiquity.Platforms
	ubiquity.Platforms = nil
	t.Cleanup(func() { ubiquity.Platforms = originalPlatforms })

	tests := []struct {
		name         string
		hostname     string
		ip           string
		wantDialName string
		wantHostname string
	}{
		{
			name:         "hostname",
			hostname:     remoteServerName,
			wantDialName: remoteServerName + ":443",
			wantHostname: remoteServerName,
		},
		{
			name:         "explicit IP with wildcard hostname",
			hostname:     "www.remote.test",
			ip:           remoteIP,
			wantDialName: remoteIP + ":443",
			wantHostname: remoteWildcard,
		},
	}

	for _, flavor := range []BundleFlavor{Ubiquitous, Optimal} {
		for _, test := range tests {
			t.Run(string(flavor)+"/"+test.name, func(t *testing.T) {
				serverAddress, servedCert, serverNames := startRemoteTLSServer(t)
				b := newCustomizedBundlerFromFile(t, testCFSSLRootBundle, testCFSSLIntBundle, "")

				var dialName string
				b.opts.dialTLS = func(dialer *net.Dialer, network, address string, config *tls.Config) (*tls.Conn, error) {
					dialName = address
					return tls.DialWithDialer(dialer, network, serverAddress, config)
				}

				bundle, err := b.BundleFromRemote(test.hostname, test.ip, flavor)
				if err != nil {
					t.Fatalf("BundleFromRemote(%q, %q) failed: %v", test.hostname, test.ip, err)
				}
				if dialName != test.wantDialName {
					t.Fatalf("dialed %q, want %q", dialName, test.wantDialName)
				}
				if len(bundle.Chain) == 0 || !bundle.Chain[0].Equal(servedCert) {
					t.Fatal("bundle does not start with the certificate served by the remote")
				}
				if !containsString(bundle.Hostnames, test.wantHostname) {
					t.Fatalf("bundle hostnames %v do not contain %q", bundle.Hostnames, test.wantHostname)
				}

				select {
				case got := <-serverNames:
					if got != test.hostname {
						t.Fatalf("TLS server received SNI %q, want %q", got, test.hostname)
					}
				case <-time.After(time.Second):
					t.Fatal("TLS server did not receive a ClientHello")
				}
			})
		}
	}
}

func TestBundleFromRemoteDialErrors(t *testing.T) {
	tests := []struct {
		name         string
		hostname     string
		ip           string
		wantDialName string
	}{
		{
			name:         "invalid host",
			hostname:     "cloudflare1337.invalid",
			wantDialName: "cloudflare1337.invalid:443",
		},
		{
			name:         "invalid address as hostname",
			hostname:     "300.300.300.300",
			wantDialName: "300.300.300.300:443",
		},
		{
			name:         "invalid explicit IP",
			ip:           "300.300.300.300",
			wantDialName: "300.300.300.300:443",
		},
	}

	for _, flavor := range []BundleFlavor{Ubiquitous, Optimal} {
		for _, test := range tests {
			t.Run(string(flavor)+"/"+test.name, func(t *testing.T) {
				b := newBundler(t)
				dialCalls := 0
				b.opts.dialTLS = func(_ *net.Dialer, _, address string, _ *tls.Config) (*tls.Conn, error) {
					dialCalls++
					if address != test.wantDialName {
						t.Fatalf("dialed %q, want %q", address, test.wantDialName)
					}
					return nil, fmt.Errorf("dial tcp: lookup %s: no such host", strings.TrimSuffix(address, ":443"))
				}

				_, err := b.BundleFromRemote(test.hostname, test.ip, flavor)
				if err == nil {
					t.Fatal("expected a dial error")
				}
				if !strings.Contains(err.Error(), `"code":6000`) || !strings.Contains(err.Error(), test.wantDialName[:len(test.wantDialName)-4]) {
					t.Fatalf("unexpected dial error: %v", err)
				}
				if dialCalls != 2 {
					t.Fatalf("dial called %d times, want 2", dialCalls)
				}
			})
		}
	}
}

func TestBundleFromRemoteCertificateErrors(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		bundler  func(*testing.T) *Bundler
	}{
		{
			name:     "hostname mismatch",
			hostname: "unrelated.test",
			bundler: func(t *testing.T) *Bundler {
				return newCustomizedBundlerFromFile(t, testCFSSLRootBundle, testCFSSLIntBundle, "")
			},
		},
		{
			name:     "untrusted certificate",
			hostname: remoteServerName,
			bundler:  newBundler,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverAddress, _, _ := startRemoteTLSServer(t)
			b := test.bundler(t)
			dialCalls := 0
			b.opts.dialTLS = func(dialer *net.Dialer, network, _ string, config *tls.Config) (*tls.Conn, error) {
				dialCalls++
				return tls.DialWithDialer(dialer, network, serverAddress, config)
			}

			_, err := b.BundleFromRemote(test.hostname, "", Optimal)
			if err == nil || !strings.Contains(err.Error(), `"code":12`) {
				t.Fatalf("expected certificate verification error, got %v", err)
			}
			if dialCalls != 2 {
				t.Fatalf("dial called %d times, want 2", dialCalls)
			}
		})
	}
}

func startRemoteTLSServer(t *testing.T) (string, *x509.Certificate, <-chan string) {
	t.Helper()

	certificate, leaf := newRemoteServerCertificate(t)
	serverNames := make(chan string, 4)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverNames <- hello.ServerName
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tlsConn, ok := conn.(*tls.Conn)
				if !ok {
					return
				}
				_ = tlsConn.Handshake()
			}(conn)
		}
	}()

	return listener.Addr().String(), leaf, serverNames
}

func newRemoteServerCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	issuer := mustReadCertificate(t, interL2)
	issuerKeyPEM, err := os.ReadFile(interL2Key)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := helpers.ParsePrivateKeyPEM(issuerKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: remoteServerName},
		DNSNames:              []string{remoteServerName, remoteWildcard},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateL1 := mustReadCertificate(t, interL1)

	return tls.Certificate{
		Certificate: [][]byte{leafDER, issuer.Raw, intermediateL1.Raw},
		PrivateKey:  leafKey,
	}, leaf
}

func mustReadCertificate(t *testing.T, filename string) *x509.Certificate {
	t.Helper()

	certPEM, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func containsString(values []string, want string) bool {
	return slices.Contains(values, want)
}
