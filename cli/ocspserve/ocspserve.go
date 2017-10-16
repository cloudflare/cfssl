// Package ocspserve implements the ocspserve function.
package ocspserve

import (
	"errors"
	"fmt"
	"net/http"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"os"
	"os/signal"
	"syscall"
	"time"
	"context"
)

// Usage text of 'cfssl serve'
var ocspServerUsageText = `cfssl ocspserve -- set up an HTTP server that handles OCSP requests from a file (see RFC 5019)

  Usage of ocspserve:
          cfssl ocspserve [-address address] [-port port] [-responses file]

  Flags:
  `

// Flags used by 'cfssl serve'
var ocspServerFlags = []string{"address", "port", "responses"}

// ocspServerMain is the command line entry point to the OCSP responder.
// It sets up a new HTTP server that responds to OCSP requests.
func ocspServerMain(args []string, c cli.Config) error {
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	if c.Responses == "" {
		return errors.New("no response file provided, please set the -responses flag")
	}

	src, err := ocsp.NewSourceFromFile(c.Responses)
	if err != nil {
		return errors.New("unable to read response file")
	}

	log.Info("Registering OCSP responder handler")

	http.Handle(c.Path, ocsp.NewResponder(src))

	addr := fmt.Sprintf("%s:%d", c.Address, c.Port)
	server := &http.Server{Addr: addr, Handler: nil}

	log.Info("Now listening on ", addr)

	//gracefull shutdown on SIGTERM or SIGINT
	//see issue https://github.com/golang/go/issues/19541
	//see https://play.golang.org/p/LdXUYyzDxY
	exit := make(chan struct{})
	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGTERM)
	signal.Notify(quit, syscall.SIGINT)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Infof("recovered: %+v\n", err)
			}
		}()
		<-quit
		d := time.Now().Add(5 * time.Second) // deadline 5s max
		ctx, cancel := context.WithDeadline(context.Background(), d)

		defer cancel()

		log.Info("Shutting down server...")
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("could not shutdown: %v", err)
		}
		close(exit)
	}()
	err = server.ListenAndServe()
	<-exit
	if err != http.ErrServerClosed {
		log.Fatalf("listen: %s\n", err)
		return err
	} else {
		return nil
	}
}

// Command assembles the definition of Command 'ocspserve'
var Command = &cli.Command{UsageText: ocspServerUsageText, Flags: ocspServerFlags, Main: ocspServerMain}
