package scan

import (
	"bufio"
	stdctx "context"
	stdtls "crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/scan/crypto/tls"
	"golang.org/x/net/proxy"
)

func init() {
	proxy.RegisterDialerType("http", newHTTPProxyDialer)
	proxy.RegisterDialerType("https", newHTTPProxyDialer)
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

func proxyURLFromEnv() *url.URL {
	raw := firstEnv("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return nil
	}
	return u
}

// proxyAwareDialer returns a dialer that honors proxy environment variables.
// When none are set, it falls back to Dialer so TCP/TLS scans keep the 1s timeout.
func proxyAwareDialer() proxy.Dialer {
	u := proxyURLFromEnv()
	if u == nil {
		return Dialer
	}
	d, err := proxy.FromURL(u, Dialer)
	if err != nil {
		return Dialer
	}
	noProxy := firstEnv("NO_PROXY", "no_proxy")
	if noProxy == "" {
		return d
	}
	perHost := proxy.NewPerHost(d, Dialer)
	perHost.AddFromString(noProxy)
	return perHost
}

func dial(network, addr string) (net.Conn, error) {
	return proxyAwareDialer().Dial(network, addr)
}

func dialTLS(network, addr string, config *tls.Config) (*tls.Conn, error) {
	start := time.Now()
	rawConn, err := dial(network, addr)
	if err != nil {
		return nil, err
	}

	if timeout := Dialer.Timeout; timeout > 0 {
		remaining := timeout - time.Since(start)
		if remaining <= 0 {
			rawConn.Close()
			return nil, timeoutError{}
		}
		if err := rawConn.SetDeadline(time.Now().Add(remaining)); err != nil {
			rawConn.Close()
			return nil, err
		}
		defer rawConn.SetDeadline(time.Time{})
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = &tls.Config{}
	}
	if config.ServerName == "" {
		c := *config
		c.ServerName = hostname
		config = &c
	}

	conn := tls.Client(rawConn, config)
	if err := conn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "scan: dial timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func newHTTPProxyDialer(u *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	return &httpProxyDialer{proxyURL: u, forward: forward}, nil
}

type httpProxyDialer struct {
	proxyURL *url.URL
	forward  proxy.Dialer
}

func (d *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(stdctx.Background(), network, addr)
}

func (d *httpProxyDialer) DialContext(ctx stdctx.Context, network, addr string) (net.Conn, error) {
	proxyAddr := d.proxyURL.Host
	if d.proxyURL.Port() == "" {
		port := "80"
		if d.proxyURL.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(d.proxyURL.Hostname(), port)
	}

	var conn net.Conn
	var err error
	if f, ok := d.forward.(proxy.ContextDialer); ok {
		conn, err = f.DialContext(ctx, "tcp", proxyAddr)
	} else {
		conn, err = d.forward.Dial("tcp", proxyAddr)
	}
	if err != nil {
		return nil, err
	}

	if d.proxyURL.Scheme == "https" {
		conn = stdtls.Client(conn, &stdtls.Config{ServerName: d.proxyURL.Hostname()})
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if user := d.proxyURL.User; user != nil {
		username := user.Username()
		password, _ := user.Password()
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT to %s failed: %s", addr, resp.Status)
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}
