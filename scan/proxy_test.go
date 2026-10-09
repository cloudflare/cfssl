package scan

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func unsetProxyEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"ALL_PROXY", "all_proxy",
		"HTTPS_PROXY", "https_proxy",
		"HTTP_PROXY", "http_proxy",
		"NO_PROXY", "no_proxy",
	} {
		t.Setenv(key, "")
	}
}

func TestHTTPClientUsesProxyFromEnvironment(t *testing.T) {
	transport, ok := Client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Client.Transport is %T, want *http.Transport", Client.Transport)
	}
	if transport.Proxy == nil {
		t.Fatal("Client transport Proxy is nil, want http.ProxyFromEnvironment")
	}
	if transport.Dial != nil {
		t.Fatal("Client transport Dial is set; it bypasses ProxyFromEnvironment")
	}
	if transport.DialContext == nil {
		t.Fatal("Client transport DialContext is nil, want Dialer's DialContext")
	}

	unsetProxyEnv(t)

	proxyURL := "http://proxy.example:8080"
	t.Setenv("HTTP_PROXY", proxyURL)
	t.Setenv("http_proxy", proxyURL)

	// ProxyFromEnvironment never proxies loopback hosts, so use a public URL.
	req, err := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("transport.Proxy: %v", err)
	}
	if got == nil || got.String() != proxyURL {
		t.Fatalf("transport.Proxy = %v, want %s", got, proxyURL)
	}
}

func TestProxyAwareDialerDirectWhenNoProxy(t *testing.T) {
	unsetProxyEnv(t)

	if d := proxyAwareDialer(); d != Dialer {
		t.Fatalf("proxyAwareDialer() = %T, want Dialer", d)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	conn, err := dial(Network, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	<-done
}

func TestDialUsesHTTPProxyFromEnv(t *testing.T) {
	unsetProxyEnv(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
		close(accepted)
	}()

	var mu sync.Mutex
	var connects []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mu.Lock()
		connects = append(connects, r.Host)
		mu.Unlock()

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer clientConn.Close()

		backend, err := net.Dial("tcp", r.Host)
		if err != nil {
			fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer backend.Close()
		fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go io.Copy(backend, clientConn)
		io.Copy(clientConn, backend)
	}))
	defer proxy.Close()

	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)

	conn, err := dial(Network, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial through proxy: %v", err)
	}
	conn.Close()
	<-accepted

	mu.Lock()
	defer mu.Unlock()
	if len(connects) != 1 || connects[0] != ln.Addr().String() {
		t.Fatalf("CONNECT hosts = %v, want [%s]", connects, ln.Addr().String())
	}
}

func TestDialUsesSOCKS5ProxyFromEnv(t *testing.T) {
	unsetProxyEnv(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	t.Setenv("ALL_PROXY", "socks5://"+ln.Addr().String())

	d := proxyAwareDialer()
	if d == Dialer {
		t.Fatal("proxyAwareDialer() returned Dialer despite ALL_PROXY socks5 URL")
	}
}
