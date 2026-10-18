// Package ocspserve implements the ocspserve function.
package ocspserve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
)

// Usage text of 'cfssl serve'
var ocspServerUsageText = `cfssl ocspserve -- set up an HTTP server that handles OCSP requests from either a file or directly from a database (see RFC 5019)

  Usage of ocspserve:
          cfssl ocspserve [-address address] [-port port] [-responses file] [-db-config db-config]

  Flags:
  `

// Flags used by 'cfssl serve'
var ocspServerFlags = []string{"address", "port", "responses", "db-config"}

// ocspServerMain is the command line entry point to the OCSP responder.
// It sets up a new HTTP server that responds to OCSP requests.
func ocspServerMain(args []string, c cli.Config) error {
	var src ocsp.Source
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	if c.Responses != "" {
		s, err := ocsp.NewSourceFromFile(c.Responses)
		if err != nil {
			return errors.New("unable to read response file")
		}
		src = s
	} else if c.DBConfigFile != "" {
		s, err := ocsp.NewSourceFromDB(c.DBConfigFile)
		if err != nil {
			return errors.New("unable to read configuration file")
		}
		src = s
	} else {
		return errors.New(
			"no response file or db-config provided, please set the one of these using either -responses or -db-config flags",
		)
	}

	log.Info("Registering OCSP responder handler")
	http.Handle(c.Path, ocsp.NewResponder(src, nil))

	addr := net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
	log.Info("Now listening on ", addr)

	server := &http.Server{Addr: addr, Handler: nil}

	//gracefull shutdown on SIGTERM or SIGINT
	//see issue https://github.com/golang/go/issues/19541
	//see https://play.golang.org/p/LdXUYyzDxY
	exit := make(chan struct{})
	quit := make(chan os.Signal, 1) //use buffered version due to vet false positive . Could be unbuffered in go@1.20
	signal.Notify(quit, os.Interrupt)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Infof("recovered: %+v\n", err)
			}
		}()
		<-quit
		d := time.Now().Add(60 * time.Second) // deadline 5s max
		ctx, cancel := context.WithDeadline(context.Background(), d)

		defer cancel()

		log.Info("Shutting down server...")
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("could not shutdown: %v", err)
		}
		close(exit)
	}()
	err := server.ListenAndServe()
	<-exit

	if err != http.ErrServerClosed {
		log.Fatalf("listen: %s\n", err)
	}

	return err
}

// Command assembles the definition of Command 'ocspserve'
var Command = &cli.Command{UsageText: ocspServerUsageText, Flags: ocspServerFlags, Main: ocspServerMain}
