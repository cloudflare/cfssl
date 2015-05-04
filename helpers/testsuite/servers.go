// Servers which can be configured then run locally to test various parts of
// CFSSL project.

package testsuite

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// TestServer wraps http.Server, so it is as flexible as the standard library's
// server. In addition, it has convenience functions for setting up the server's
// TLS config as well as a Stop() function which kills the server.
type TestServer struct {
	*http.Server
	innerListener *net.TCPListener
	tempFiles     []string
}

// CFSSLServer represents a CFSSL API server. The Addr and Port fields must be
// initiated for the server to start successfully. If any of the other exported
// fields are left blank, the default values are used.  These are as definied
// in the documentation for the 'cfssl serve' command.
type CFSSLServer struct {
	Addr      string
	Port      string
	CA        []byte
	CABundle  []byte
	CAKey     []byte
	IntBundle []byte

	process   *os.Process
	tempFiles []string
}

// NewTestServer initializes a TestServer from an http.Server object.
func NewTestServer(innerServer http.Server) TestServer {
	return TestServer{&innerServer, nil, nil}
}

// Start the test server. If TLSConfig is nil, the server will only use TCP.
func (ts *TestServer) Start() error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", ts.Addr)
	if err != nil {
		return err
	}
	ts.innerListener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	if ts.TLSConfig == nil {
		ts.tempFiles = make([]string, 0)
		go ts.Serve(ts.innerListener)
	} else {
		tlsListener := tls.NewListener(ts.innerListener, ts.TLSConfig)
		go ts.Serve(tlsListener)
	}

	return nil
}

// UseDefaultTLSConfig is a convenience function which allows the caller to ask
// that a server use the following configuration:
// 		- all cipher suites supported
//		- minimum version set to TLSv1
//		- the input certificate pair loaded
func (ts *TestServer) UseDefaultTLSConfig(cert, key []byte) error {
	ts.TLSConfig = &tls.Config{}
	ts.TLSConfig.CipherSuites = []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	ts.TLSConfig.MinVersion = tls.VersionTLS10
	return ts.LoadCertificatePair(cert, key)
}

// LoadCertificatePair sets the certificate and key pair that the server will
// use for TLS authentication. Assumes that ts.TLSConfig has been initialized.
func (ts *TestServer) LoadCertificatePair(cert, key []byte) error {
	if ts.TLSConfig == nil {
		return errors.New("TLSConfig needs to be initialized")
	}

	certFile, err := createTempFile(cert)
	if err != nil {
		os.Remove(certFile)
		return err
	}
	keyFile, err := createTempFile(key)
	if err != nil {
		os.Remove(certFile)
		os.Remove(keyFile)
		return err
	}
	ts.tempFiles = []string{certFile, keyFile}

	ts.TLSConfig.Certificates = make([]tls.Certificate, 1)
	ts.TLSConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	return err
}

// Kill the test server.
func (ts *TestServer) Kill() error {
	err := ts.innerListener.Close()
	if err != nil {
		return err
	}
	for _, file := range ts.tempFiles {
		os.Remove(file)
	}
	return nil
}

// Start the CFSSLServer. Both the address and port number are assumed to be
// valid.
func (server *CFSSLServer) Start() error {
	// This value is explained below.
	startupTime := time.Second

	args := []string{"serve", "-address", server.Addr, "-port", server.Port}
	var tempCAFile, tempCABundleFile, tempCAKeyFile, tempIntBundleFile string
	var err error
	server.tempFiles = make([]string, 0)
	if len(server.CA) > 0 {
		tempCAFile, err = createTempFile(server.CA)
		server.tempFiles = append(server.tempFiles, tempCAFile)
		args = append(args, "-ca")
		args = append(args, tempCAFile)
	}
	if len(server.CABundle) > 0 {
		tempCABundleFile, err = createTempFile(server.CABundle)
		server.tempFiles = append(server.tempFiles, tempCABundleFile)
		args = append(args, "-ca-bundle")
		args = append(args, tempCABundleFile)
	}
	if len(server.CAKey) > 0 {
		tempCAKeyFile, err = createTempFile(server.CAKey)
		server.tempFiles = append(server.tempFiles, tempCAKeyFile)
		args = append(args, "-ca-key")
		args = append(args, tempCAKeyFile)
	}
	if len(server.IntBundle) > 0 {
		tempIntBundleFile, err = createTempFile(server.IntBundle)
		server.tempFiles = append(server.tempFiles, tempIntBundleFile)
		args = append(args, "-int-bundle")
		args = append(args, tempIntBundleFile)
	}
	// If an error occurred in the creation of any file, return an error.
	if err != nil {
		for _, file := range server.tempFiles {
			os.Remove(file)
		}
		return err
	}

	command := exec.Command("cfssl", args...)

	stdErrPipe, err := command.StderrPipe()
	if err != nil {
		for _, file := range server.tempFiles {
			os.Remove(file)
		}
		return err
	}

	err = command.Start()
	if err != nil {
		for _, file := range server.tempFiles {
			os.Remove(file)
		}
		return err
	}

	// We check to see if the address given is already in use. There is no way
	// to do this other than to just wait and see if an error message pops up.
	// Therefore we wait for startupTime, and if we don't see an error message
	// by then, we deem the server ready and return.

	errorOccurred := make(chan bool)
	go func() {
		scanner := bufio.NewScanner(stdErrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "address already in use") {
				errorOccurred <- true
			}
		}
	}()

	select {
	case <-errorOccurred:
		for _, file := range server.tempFiles {
			os.Remove(file)
		}
		fullAddress := net.JoinHostPort(server.Addr, server.Port)
		return errors.New(
			"Error occurred on server: address " + fullAddress +
				" already in use.")
	case <-time.After(startupTime):
		server.process = command.Process
		return nil
	}
}

// Kill a running CFSSL server.
func (server *CFSSLServer) Kill() error {
	for _, file := range server.tempFiles {
		os.Remove(file)
	}
	return server.process.Kill()
}
