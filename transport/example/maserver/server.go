package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/cfssl/transport"
	"github.com/cloudflare/cfssl/transport/core"
)

// maclient is a mutual-authentication server, meant to demonstrate
// using the client-side mutual authentication side of the transport
// package.

var progname = filepath.Base(os.Args[0])
var before = 5 * time.Minute

// Err displays a formatting error message to standard error,
// appending the error string, and exits with the status code from
// `exit`, à la err(3).
func Err(exit int, err error, format string, a ...interface{}) {
	format = fmt.Sprintf("[%s] %s", progname, format)
	format += ": %v\n"
	a = append(a, err)
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(exit)
}

// Warn displays a formatted error message to standard output,
// appending the error string, à la warn(3).
func Warn(err error, format string, a ...interface{}) (int, error) {
	format = fmt.Sprintf("[%s] %s", progname, format)
	format += ": %v\n"
	a = append(a, err)
	return fmt.Fprintf(os.Stderr, format, a...)
}

func main() {
	var addr, conf string
	flag.StringVar(&addr, "a", "127.0.0.1:9876", "`address` of server")
	flag.StringVar(&conf, "f", "server.json", "config `file` to use")
	flag.Parse()

	var id = new(core.Identity)
	data, err := ioutil.ReadFile(conf)
	if err != nil {
		Err(1, err, "reading config file")
	}

	err = json.Unmarshal(data, id)
	if err != nil {
		Err(1, err, "parsing config file")
	}

	tr, err := transport.New(before, id)
	if err != nil {
		Err(1, err, "creating transport")
	}

	l, err := transport.Listen(addr, tr)
	if err != nil {
		Err(1, err, "setting up listener")
	}

	log.Println("setting up auto-update")
	go l.AutoUpdate(nil, nil)

	log.Println("listening on", addr)
	Warn(serve(l), "serving listener")
}

func serve(l net.Listener) error {
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			Warn(err, "client connection failed")
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			buf, err := ioutil.ReadAll(conn)
			if err != nil {
				Warn(err, "reading from client")
				return
			}

			log.Printf("received %d-byte message: %s", len(buf), buf)
		}(conn)
	}
}
