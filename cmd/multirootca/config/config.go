// Package config contains the multiroot configuration file parser.
package config

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/cfssl/log"

	"github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/core"
)

// configMap is shorthand for the type used as a config struct.
type configMap map[string]map[string]string

var (
	configSection    = regexp.MustCompile("^\\s*\\[\\s*(\\w+)\\s*\\]\\s*$")
	quotedConfigLine = regexp.MustCompile("^\\s*(\\w+)\\s*=\\s*[\"'](.*)[\"']\\s*$")
	configLine       = regexp.MustCompile("^\\s*(\\w+)\\s*=\\s*(.*)\\s*$")
	commentLine      = regexp.MustCompile("^#.*$")
	blankLine        = regexp.MustCompile("^\\s*$")
)

var defaultSection = "default"

// ParseFile takes the filename as a string and returns a configMap.
func parseFile(fileName string) (cfg configMap, err error) {
	var file *os.File

	cfg = make(configMap, 0)
	file, err = os.Open(fileName)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	var currentSection string
	for scanner.Scan() {
		line := scanner.Text()

		if commentLine.MatchString(line) {
			continue
		} else if blankLine.MatchString(line) {
			continue
		} else if configSection.MatchString(line) {
			section := configSection.ReplaceAllString(line, "$1")
			if !cfg.SectionInConfig(section) {
				cfg[section] = make(map[string]string, 0)
			}
			currentSection = section
		} else if configLine.MatchString(line) {
			regex := configLine
			if quotedConfigLine.MatchString(line) {
				regex = quotedConfigLine
			}
			if currentSection == "" {
				currentSection = defaultSection
				if !cfg.SectionInConfig(currentSection) {
					cfg[currentSection] = make(map[string]string, 0)
				}
			}
			key := regex.ReplaceAllString(line, "$1")
			val := regex.ReplaceAllString(line, "$2")
			cfg[currentSection][key] = val
		} else {
			err = fmt.Errorf("invalid config file")
			break
		}
	}
	return
}

// SectionInConfig determines whether a section is in the configuration.
func (c *configMap) SectionInConfig(section string) bool {
	for s := range *c {
		if section == s {
			return true
		}
	}
	return false
}

// A Root represents a single certificate authority root key pair.
type Root struct {
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	Config      *config.Signing
}

// ErrUnsupportedScheme indicates a private key scheme that is not currently supported.
var ErrUnsupportedScheme = errors.New("config: unsupported private key scheme")

func parsePrivateKeySpec(spec string, cfg map[string]string) (crypto.Signer, error) {
	specURL, err := url.Parse(spec)
	if err != nil {
		return nil, err
	}

	var priv crypto.Signer
	switch specURL.Scheme {
	case "file":
		// A file spec will be parsed such that the root
		// directory of a relative path will be stored as the
		// hostname, and the remainder of the file's path is
		// stored in the Path field.
		log.Debug("loading private key file", specURL.Path)
		path := filepath.Join(specURL.Host, specURL.Path)
		in, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}

		log.Debug("attempting to load PEM-encoded private key")
		priv, err = helpers.ParsePrivateKeyPEM(in)
		if err != nil {
			log.Debug("file is not a PEM-encoded private key")
			log.Debug("attempting to load DER-encoded private key")
			priv, err = derhelpers.ParsePrivateKeyDER(in)
			if err != nil {
				return nil, err
			}
		}
		log.Debug("loaded private key")
		return priv, nil
	case "rofile":
		log.Warning("Red October support is currently experimental")
		path := filepath.Join(specURL.Host, specURL.Path)
		in, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}

		roServer := cfg["ro_server"]
		if roServer == "" {
			return nil, errors.New("config: no RedOctober server available")
		}

		// roCAPath can be empty; if it is, the client uses
		// the system default CA roots.
		roCAPath := cfg["ro_ca"]

		roUser := cfg["ro_user"]
		if roUser == "" {
			return nil, errors.New("config: no RedOctober user available")
		}

		roPass := cfg["ro_pass"]
		if roPass == "" {
			return nil, errors.New("config: no RedOctober passphrase available")
		}

		log.Debug("decrypting key via RedOctober Server")
		roClient, err := client.NewRemoteServer(roServer, roCAPath)
		if err != nil {
			return nil, err
		}

		req := core.DecryptRequest{
			Name:     roUser,
			Password: roPass,
			Data:     in,
		}
		in, err = roClient.DecryptIntoData(req)
		if err != nil {
			return nil, err
		}

		return priv, nil
	default:
		return nil, ErrUnsupportedScheme
	}
}

// A RootList associates a set of labels with the appropriate private
// keys and their certificates.
type RootList map[string]*Root

var (
	// ErrMissingPrivateKey indicates that the configuration is
	// missing a private key specifier.
	ErrMissingPrivateKey = errors.New("config: root is missing private key spec")

	// ErrMissingCertificatePath indicates that the configuration
	// is missing a certificate specifier.
	ErrMissingCertificatePath = errors.New("config: root is missing certificate path")

	// ErrMissingConfigPath indicates that the configuration lacks
	// a valid CFSSL configuration.
	ErrMissingConfigPath = errors.New("config: root is missing configuration file path")

	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("config: invalid configuration")
)

// Parse loads a RootList from a file.
func Parse(filename string) (RootList, error) {
	cfgMap, err := parseFile(filename)
	if err != nil {
		return nil, err
	}

	var rootList = RootList{}
	for label, entries := range cfgMap {
		var root Root
		spec, ok := entries["private"]
		if !ok {
			return nil, ErrMissingPrivateKey
		}

		certPath, ok := entries["certificate"]
		if !ok {
			return nil, ErrMissingCertificatePath
		}

		configPath, ok := entries["config"]
		if !ok {
			return nil, ErrMissingConfigPath
		}

		// Entries is provided for any additional
		// configuration data that may need to come from the
		// section.
		root.PrivateKey, err = parsePrivateKeySpec(spec, entries)
		if err != nil {
			return nil, err
		}

		in, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}

		root.Certificate, err = helpers.ParseCertificatePEM(in)
		if err != nil {
			return nil, err
		}

		conf, err := config.LoadFile(configPath)
		if err != nil {
			return nil, err
		}
		root.Config = conf.Signing

		rootList[label] = &root
	}

	return rootList, nil
}
