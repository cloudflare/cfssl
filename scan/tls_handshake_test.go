package scan

import (
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

const TestTimeout = 5 // seconds
const TLSServerAddr = "127.0.0.1:4443"

// tlsServer starts up a test TLS server that accepts new connections
// The server will run until TestTimeout seconds have elapsed
func tlsServer(t *testing.T, done chan bool) {
	// Set the maximimum timeout before any test will fail
	go func() {
		time.Sleep(time.Second * TestTimeout)
		t.Errorf("server test timed out.")
		done <- true
	}()

	// Load the x509 server certificates
	cert, err := tls.LoadX509KeyPair("./testdata/server.crt", "./testdata/server.key")
	if err != nil {
		t.Errorf("server loadkeys: %s", err)
		done <- true
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader

	// Create a TLS connection listener
	listener, err := tls.Listen("tcp", TLSServerAddr, &config)
	if err != nil {
		t.Errorf("server error starting TLS server: %s", err)
		done <- true
	}
	defer listener.Close()

	// Accept all incoming TLS connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("server error at Accept(): %s", err)
			done <- true
		}
		defer conn.Close()
		go func(conn net.Conn) {
			defer conn.Close()
			// Read some bytes but don't do anything with them yet
			buf := make([]byte, 512)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					break
				}
			}
		}(conn)
	}
}

// createTLSTestServer creates a TLS server for making test connections
// Returns a bool goroutine channel; tests send `true` to the channel when complete
func createTLSTestServer(t *testing.T) chan bool {
	done := make(chan bool)
	go tlsServer(t, done)
	time.Sleep(time.Second)
	return done
}

// Sanity test to ensure that the testing server/framework works
func TestTLSConnection(t *testing.T) {
	// Start up the test server and retrieve a 'done' channel for test completion
	done := createTLSTestServer(t)
	go func() {

		// Create a new TLS config and try to dial the server
		config := tls.Config{InsecureSkipVerify: true}
		conn, err := tls.Dial("tcp", TLSServerAddr, &config)
		if err != nil {
			t.Errorf("client error at Dial(): %s", err)
			done <- true
			return
		}
		defer conn.Close()

		// Test that we successfully connected to the server we wanted
		if conn.RemoteAddr().String() != TLSServerAddr {
			t.Errorf("client error at Dial(): %s", conn.RemoteAddr())
			done <- true
			return
		}
		done <- true
	}()
	<-done
}
