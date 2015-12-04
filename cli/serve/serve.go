// Package serve implements the serve command for CFSSL's API.
package serve

import (
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	rice "github.com/GeertJohan/go.rice"
	"github.com/cloudflare/cfssl/api/bundle"
	"github.com/cloudflare/cfssl/api/certinfo"
	"github.com/cloudflare/cfssl/api/crl"
	"github.com/cloudflare/cfssl/api/generator"
	"github.com/cloudflare/cfssl/api/info"
	"github.com/cloudflare/cfssl/api/initca"
	apiocsp "github.com/cloudflare/cfssl/api/ocsp"
	"github.com/cloudflare/cfssl/api/revoke"
	"github.com/cloudflare/cfssl/api/scan"
	apisign "github.com/cloudflare/cfssl/api/sign"
	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/cli"
	ocspsign "github.com/cloudflare/cfssl/cli/ocspsign"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/ubiquity"
)

// Usage text of 'cfssl serve'
var serverUsageText = `cfssl serve -- set up a HTTP server handles CF SSL requests

Usage of serve:
        cfssl serve [-address address] [-ca cert] [-ca-bundle bundle] \
                    [-ca-key key] [-int-bundle bundle] [-int-dir dir] [-port port] \
                    [-metadata file] [-remote remote_host] [-config config] \
                    [-responder cert] [-responder-key key] [-tls-cert cert] [-tls-key key] \
                    [-db-config db-config]

Flags:
`

// Flags used by 'cfssl serve'
var serverFlags = []string{"address", "port", "ca", "ca-key", "ca-bundle", "int-bundle", "int-dir", "metadata",
	"remote", "config", "responder", "responder-key", "tls-key", "tls-cert", "db-config"}

var (
	conf       cli.Config
	s          signer.Signer
	ocspSigner ocsp.Signer
	db         *sql.DB
)

// V1APIPrefix is the prefix of all CFSSL V1 API Endpoints.
var V1APIPrefix = "/api/v1/cfssl/"

// v1APIPath prepends the V1 API prefix to endpoints not beginning with "/"
func v1APIPath(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = V1APIPrefix + path
	}
	return (&url.URL{Path: path}).String()
}

// httpBox implements http.FileSystem which allows the use of Box with a http.FileServer.
// Atempting to Open an API endpoint will result in an error.
type httpBox struct {
	*rice.Box
	redirects map[string]string
}

func (hb *httpBox) findStaticBox() (err error) {
	hb.Box, err = rice.FindBox("static")
	return
}

// Open returns a File for non-API enpoints using the http.File interface.
func (hb *httpBox) Open(name string) (http.File, error) {
	if strings.HasPrefix(name, V1APIPrefix) {
		return nil, os.ErrNotExist
	}

	if location, ok := hb.redirects[name]; ok {
		return hb.Box.Open(location)
	}

	return hb.Box.Open(name)
}

// staticBox is the box containing all static assets.
var staticBox = &httpBox{
	redirects: map[string]string{
		"/scan":   "/index.html",
		"/bundle": "/index.html",
	},
}

var errBadSigner = errors.New("signer not initialized")
var errNoCertDBConfigured = errors.New("cert db not configured (missing -db-config)")

var endpoints = map[string]func() (http.Handler, error){
	"sign": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return apisign.NewHandlerFromSigner(s)
	},

	"authsign": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return apisign.NewAuthHandlerFromSigner(s)
	},

	"info": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return info.NewHandler(s)
	},

	"gencrl": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return crl.NewHandler(), nil
	},

	"newcert": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return generator.NewCertGeneratorHandlerFromSigner(generator.CSRValidate, s), nil
	},

	"bundle": func() (http.Handler, error) {
		return bundle.NewHandler(conf.CABundleFile, conf.IntBundleFile)
	},

	"newkey": func() (http.Handler, error) {
		return generator.NewHandler(generator.CSRValidate)
	},

	"init_ca": func() (http.Handler, error) {
		return initca.NewHandler(), nil
	},

	"scan": func() (http.Handler, error) {
		return scan.NewHandler(conf.CABundleFile)
	},

	"scaninfo": func() (http.Handler, error) {
		return scan.NewInfoHandler(), nil
	},

	"certinfo": func() (http.Handler, error) {
		return certinfo.NewHandler(), nil
	},

	"ocspsign": func() (http.Handler, error) {
		if ocspSigner == nil {
			return nil, errBadSigner
		}
		return apiocsp.NewHandler(ocspSigner), nil
	},

	"revoke": func() (http.Handler, error) {
		if db == nil {
			return nil, errNoCertDBConfigured
		}
		return revoke.NewHandler(db), nil
	},

	"/": func() (http.Handler, error) {
		if err := staticBox.findStaticBox(); err != nil {
			return nil, err
		}

		return http.FileServer(staticBox), nil
	},
}

// registerHandlers instantiates various handlers and associate them to corresponding endpoints.
func registerHandlers() {
	for path, getHandler := range endpoints {
		path = v1APIPath(path)
		log.Infof("Setting up '%s' endpoint", path)
		if handler, err := getHandler(); err != nil {
			log.Warningf("endpoint '%s' is disabled: %v", path, err)
		} else {
			http.Handle(path, handler)
		}
	}

	log.Info("Handler set up complete.")
}

// serverMain is the command line entry point to the API server. It sets up a
// new HTTP server to handle sign, bundle, and validate requests.
func serverMain(args []string, c cli.Config) error {
	conf = c
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	bundler.IntermediateStash = conf.IntDir
	var err error

	if err = ubiquity.LoadPlatforms(conf.Metadata); err != nil {
		return err
	}

	if c.DBConfigFile != "" {
		db, err = certdb.DBFromConfig(c.DBConfigFile)
		if err != nil {
			return err
		}
	}

	log.Info("Initializing signer")

	if s, err = sign.SignerFromConfigAndDB(c, db); err != nil {
		log.Warningf("couldn't initialize signer: %v", err)
	}

	if ocspSigner, err = ocspsign.SignerFromConfig(c); err != nil {
		log.Warningf("couldn't initialize ocsp signer: %v", err)
	}

	registerHandlers()

	addr := net.JoinHostPort(conf.Address, strconv.Itoa(conf.Port))

	if conf.TLSCertFile == "" || conf.TLSKeyFile == "" {
		log.Info("Now listening on ", addr)
		return http.ListenAndServe(addr, nil)
	}

	log.Info("Now listening on https://", addr)

	return http.ListenAndServeTLS(addr, conf.TLSCertFile, conf.TLSKeyFile, nil)

}

// Command assembles the definition of Command 'serve'
var Command = &cli.Command{UsageText: serverUsageText, Flags: serverFlags, Main: serverMain}
