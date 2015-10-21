package transport

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/cloudflare/cfssl/log"
)

// A Listener is a TCP network listener for TLS-secured connections.
type Listener struct {
	*Transport
	config   *tls.Config
	address  string
	listener net.Listener
}

// PollInterval is how often to check whether a new certificate has
// been found.
var PollInterval = 30 * time.Second

// Listen sets up a new server. If an error is returned, it means
// the server isn't ready to begin listening.
func Listen(address string, tr *Transport) (*Listener, error) {
	l := &Listener{
		Transport: tr,
		address:   address,
	}

	var err error
	l.config, err = l.getConfig()
	if err != nil {
		return nil, err
	}

	l.listener, err = tls.Listen("tcp", l.address, l.config)
	if err != nil {
		return nil, err
	}

	log.Debug("listener ready")
	return l, nil
}

func pollWait(target time.Time) {
	for {
		<-time.After(PollInterval)
		if time.Now().After(target) {
			break
		}
	}
}

// AutoUpdate will automatically update the listener. If a non-nil
// certUpdates chan is provided, it will receive timestamps for
// reissued certificates. If errChan is non-nil, any errors that occur
// in the updater will be passed along.
func (l *Listener) AutoUpdate(certUpdates chan time.Time, errChan chan error) {
	for {
		// Wait until it's time to update the certificate.
		target := time.Now().Add(l.Transport.Lifespan())
		if PollInterval == 0 {
			<-time.After(l.Transport.Lifespan())
		} else {
			pollWait(target)
		}

		// Keep trying to update the certificate until it's
		// ready.
		for {
			log.Debug("refreshing certificate")
			err := l.Transport.RefreshKeys()
			if err == nil {
				break
			}

			log.Debug("failed to update certificate, will try again in 5 minutes")
			if errChan != nil {
				errChan <- err
			}

			<-time.After(5 * time.Minute)
		}

		if certUpdates != nil {
			certUpdates <- time.Now()
		}

		var err error
		l.config, err = l.getConfig()
		if err != nil {
			log.Debug("immediately after getting a new certificate, the Transport is reporting errors: %v", err)
			if errChan != nil {
				errChan <- err
			}
		}

		log.Debug("listener: auto update of certificate complete")
	}
}

func (l *Listener) getConfig() (*tls.Config, error) {
	if l.Transport.ClientTrustStore != nil {
		return l.Transport.TLSClientAuthServerConfig()
	}
	return l.Transport.TLSServerConfig()
}

// Addr returns the server's address.
func (l *Listener) Addr() string {
	return l.address
}

// Close shuts down the listener.
func (l *Listener) Close() error {
	l.config = nil
	err := l.listener.Close()
	l.listener = nil
	return err
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	if l.config == nil {
		log.Debug("listener needs a TLS config")
		return nil, errors.New("transport: listener isn't active")
	}

	if l.listener == nil {
		log.Debug("listener isn't listening")
		return nil, errors.New("transport: listener isn't active")
	}

	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}

	conn = tls.Server(conn, l.config)
	return conn, nil
}
