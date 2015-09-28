package core

import (
	"crypto/tls"
	"crypto/x509"
)

// TLSClientAuthClientConfig returns a new client authentication TLS
// configuration that can be used for a client using client auth
// connecting to the named host.
func TLSClientAuthClientConfig(cert tls.Certificate, host string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      SystemRoots,
		ServerName:   host,
		CipherSuites: CipherSuites,
		MinVersion:   tls.VersionTLS12,
	}
}

// TLSClientAuthServerConfig returns a new client authentication TLS
// configuration for servers expecting mutually authenticated
// clients. The clientAuth parameter should contain the root pool used
// to authenticate clients.
func TLSClientAuthServerConfig(cert tls.Certificate, clientAuth *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      SystemRoots,
		ClientCAs:    clientAuth,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		CipherSuites: CipherSuites,
		MinVersion:   tls.VersionTLS12,
	}
}

// TLSServerConfig is a general server configuration that should be
// used for non-client authentication purposes, such as HTTPS.
func TLSServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      SystemRoots,
		CipherSuites: CipherSuites,
		MinVersion:   tls.VersionTLS12,
	}
}
