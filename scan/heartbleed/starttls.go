package heartbleed

import (
	"bufio"
	"errors"
	"net"
	"regexp"
	"strings"
)

// Services holds types of services
var Services = []string{
	"ftp",
	"smtp",
	"pop3",
	"imap",
}

// LineProtoTriple holds match strings
type LineProtoTriple struct {
	GreetMatch    string
	AuthReq       string
	ResponseMatch string
}

func (proto *LineProtoTriple) do(w *bufio.Writer, r *bufio.Reader) (err error) {
	var line string
	re := regexp.MustCompile(proto.GreetMatch)
	for {
		if line, err = r.ReadString('\n'); err != nil {
			return
		}
		line = strings.TrimRight(line, "\r")

		if re.MatchString(line) {
			break
		}
	}

	if _, err = w.WriteString(proto.AuthReq + "\r\n"); err != nil {
		return
	}
	if err = w.Flush(); err != nil {
		return
	}

	if line, err = r.ReadString('\n'); err != nil {
		return
	}
	line = strings.TrimRight(line, "\r")

	re = regexp.MustCompile(proto.ResponseMatch)
	if !re.MatchString(line) {
		return errors.New("Server does not support STARTTLS (" + strings.TrimSpace(line) + ")")
	}

	return
}

func starttlsFTP(w *bufio.Writer, r *bufio.Reader) error {
	proto := &LineProtoTriple{
		GreetMatch:    "^220 ",
		AuthReq:       "AUTH TLS",
		ResponseMatch: "^234 ",
	}
	return proto.do(w, r)

}

func starttlsSMTP(w *bufio.Writer, r *bufio.Reader) error {
	proto := &LineProtoTriple{
		GreetMatch:    "^220 ",
		AuthReq:       "STARTTLS",
		ResponseMatch: "^220 ",
	}
	return proto.do(w, r)
}

func starttlsPOP3(w *bufio.Writer, r *bufio.Reader) error {
	proto := &LineProtoTriple{
		GreetMatch:    "^\\+OK ",
		AuthReq:       "STLS",
		ResponseMatch: "^\\+OK ",
	}
	return proto.do(w, r)
}

func starttlsIMAP(w *bufio.Writer, r *bufio.Reader) error {
	proto := &LineProtoTriple{
		GreetMatch:    "^\\* ",
		AuthReq:       "a001 STARTTLS",
		ResponseMatch: "^a001 OK ",
	}
	return proto.do(w, r)
}

// DoStartTLS executes startTLS function based on service type
func DoStartTLS(conn net.Conn, startType string) (err error) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	switch strings.ToLower(startType) {
	case "ftp":
		err = starttlsFTP(w, r)
	case "smtp":
		err = starttlsSMTP(w, r)
	case "pop3":
		err = starttlsPOP3(w, r)
	case "imap":
		err = starttlsIMAP(w, r)
	case "http":
		err = errors.New("You should check the http\"s\" site")
	default:
		err = errors.New("Unknown service for StartTLS")
	}

	return
}
