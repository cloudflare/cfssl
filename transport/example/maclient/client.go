package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/cfssl/transport"
	"github.com/cloudflare/cfssl/transport/core"
)

// maclient is a mutual-authentication client, meant to demonstrate
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

func main() {
	var addr, conf string
	flag.StringVar(&addr, "a", "127.0.0.1:9876", "`address` of server")
	flag.StringVar(&conf, "f", "client.json", "config `file` to use")
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

	conn, err := transport.Dial(addr, tr)
	if err != nil {
		Err(1, err, "dialing %s", addr)
	}

	_, err = conn.Write([]byte("hello, world"))
	if err != nil {
		Err(1, err, "writing on socket")
	}

	<-time.After(3 * time.Second)

	fmt.Println("OK")
	conn.Close()
}
