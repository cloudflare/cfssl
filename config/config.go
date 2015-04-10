// Package config contains the configuration logic for CF-SSL.
package config

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/auth"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

// A SigningProfile stores information that the CA needs to store
// signature policy.
type SigningProfile struct {
	Usage          []string  `json:"usages"`
	IssuerURL      []string  `json:"issuer_urls"`
	OCSP           string    `json:"ocsp_url"`
	CRL            string    `json:"crl_url"`
	CA             bool      `json:"is_ca"`
	PolicyStrings  []string  `json:"policies"`
	OCSPNoCheck    bool      `json:"ocsp_no_check"`
	ExpiryString   string    `json:"expiry"`
	BackdateString string    `json:"backdate"`
	AuthKeyName    string    `json:"auth_key"`
	RemoteName     string    `json:"remote"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`

	Policies     []asn1.ObjectIdentifier
	Expiry       time.Duration
	Backdate     time.Duration
	Provider     auth.Provider
	RemoteServer string
}

func parseObjectIdentifier(oidString string) (oid asn1.ObjectIdentifier, err error) {
	validOID, err := regexp.MatchString("\\d(\\.\\d+)*", oidString)
	if err != nil {
		return
	}
	if !validOID {
		err = errors.New("Invalid OID")
		return
	}

	segments := strings.Split(oidString, ".")
	oid = make(asn1.ObjectIdentifier, len(segments))
	for i, intString := range segments {
		oid[i], err = strconv.Atoi(intString)
		if err != nil {
			return
		}
	}
	return
}

const timeFormat = "2006-01-02T15:04:05"

// populate is used to fill in the fields that are not in JSON
//
// First, the ExpiryString parameter is needed to parse
// expiration timestamps from JSON. The JSON decoder is not able to
// decode a string time duration to a time.Duration, so this is called
// when loading the configuration to properly parse and fill out the
// Expiry parameter.
// This function is also used to create references to the auth key
// and default remote for the profile.
// It returns true if ExpiryString is a valid representation of a
// time.Duration, and the AuthKeyString and RemoteName point to
// valid objects. It returns false otherwise.
func (p *SigningProfile) populate(cfg *Config) error {
	if p == nil {
		return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, errors.New("can't parse nil profile"))
	}

	var err error
	if p.RemoteName == "" {
		log.Debugf("parse expiry in profile")
		if p.ExpiryString == "" {
			return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, errors.New("empty expiry string"))
		}

		dur, err := time.ParseDuration(p.ExpiryString)
		if err != nil {
			return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, err)
		}

		log.Debugf("expiry is valid")
		p.Expiry = dur

		if p.BackdateString != "" {
			dur, err = time.ParseDuration(p.BackdateString)
			if err != nil {
				return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, err)
			}

			p.Backdate = dur
		}

		if !p.NotBefore.IsZero() && !p.NotAfter.IsZero() && p.NotAfter.Before(p.NotBefore) {
			return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, err)
		}

		if len(p.PolicyStrings) > 0 {
			p.Policies = make([]asn1.ObjectIdentifier, len(p.PolicyStrings))
			for i, oidString := range p.PolicyStrings {
				p.Policies[i], err = parseObjectIdentifier(oidString)
				if err != nil {
					return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, err)
				}
			}
		}
	} else {
		log.Debug("match remote in profile to remotes section")
		if remote := cfg.Remotes[p.RemoteName]; remote != "" {
			if err := p.updateRemote(remote); err != nil {
				return err
			}
		} else {
			return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy,
				errors.New("failed to find remote in remotes section"))
		}
	}

	if p.AuthKeyName != "" {
		log.Debug("match auth key in profile to auth_keys section")
		if key, ok := cfg.AuthKeys[p.AuthKeyName]; ok == true {
			if key.Type == "standard" {
				p.Provider, err = auth.New(key.Key, nil)
				if err != nil {
					log.Debugf("failed to create new standard auth provider: %v", err)
					return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy,
						errors.New("failed to create new standard auth provider"))
				}
			} else {
				log.Debugf("unknown authentication type %v", key.Type)
				return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy,
					errors.New("unknown authentication type"))
			}
		} else {
			return cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy,
				errors.New("failed to find auth_key in auth_keys section"))
		}
	}

	return nil
}

// updateRemote takes a signing profile and initializes the remote server object
// to the hostname:port combination sent by remote
func (p *SigningProfile) updateRemote(remote string) error {
	if remote != "" {
		p.RemoteServer = remote
	}
	return nil
}

// OverrideRemotes takes a signing configuration and updates the remote server object
// to the hostname:port combination sent by remote
func (p *Signing) OverrideRemotes(remote string) error {
	if remote != "" {
		var err error
		for _, profile := range p.Profiles {
			err = profile.updateRemote(remote)
			if err != nil {
				return err
			}
		}
		err = p.Default.updateRemote(remote)
		if err != nil {
			return err
		}
	}
	return nil
}

// NeedsRemoteSigner returns true if one of the profiles has a remote set
func (p *Signing) NeedsRemoteSigner() bool {
	for _, profile := range p.Profiles {
		if profile.RemoteName != "" {
			return true
		}
	}
	if p.Default.RemoteName != "" {
		return true
	}

	return false
}

// NeedsLocalSigner returns true if one of the profiles doe not have a remote set
func (p *Signing) NeedsLocalSigner() bool {
	for _, profile := range p.Profiles {
		if profile.RemoteName == "" {
			return true
		}
	}
	if p.Default.RemoteName == "" {
		return true
	}

	return false
}

// Usages parses the list of key uses in the profile, translating them
// to a list of X.509 key usages and extended key usages.  The unknown
// uses are collected into a slice that is also returned.
func (p *SigningProfile) Usages() (ku x509.KeyUsage, eku []x509.ExtKeyUsage, unk []string) {
	for _, keyUse := range p.Usage {
		if kuse, ok := KeyUsage[keyUse]; ok {
			ku |= kuse
		} else if ekuse, ok := ExtKeyUsage[keyUse]; ok {
			eku = append(eku, ekuse)
		} else {
			unk = append(unk, keyUse)
		}
	}
	return
}

// A valid profile must be a valid local profile or a valid remote profile.
// A valid local profile has defined at least key usages to be used, and a
// valid local default profile has defined at least a default expiration.
// A valid remote profile (default or not) has remote signer initialized.
// In addition, a remote profile must has a valid auth provider if auth
// key defined.
func (p *SigningProfile) validProfile(isDefault bool) bool {
	if p == nil {
		return false
	}

	if p.RemoteName != "" {
		log.Debugf("validate remote profile")

		if p.RemoteServer == "" {
			log.Debugf("invalid remote profile: no remote signer specified")
			return false
		}

		if p.AuthKeyName != "" && p.Provider == nil {
			log.Debugf("invalid remote profile: auth key name is defined but no auth provider is set")
			return false
		}
	} else {
		log.Debugf("validate local profile")
		if !isDefault {
			if len(p.Usage) == 0 {
				log.Debugf("invalid local profile: no usages specified")
				return false
			} else if _, _, unk := p.Usages(); len(unk) == len(p.Usage) {
				log.Debugf("invalid local profile: no valid usages")
				return false
			}
		} else {
			if p.Expiry == 0 {
				log.Debugf("invalid local profile: no expiry set")
				return false
			}
		}
	}

	log.Debugf("profile is valid")
	return true
}

// Signing codifies the signature configuration policy for a CA.
type Signing struct {
	Profiles map[string]*SigningProfile `json:"profiles"`
	Default  *SigningProfile            `json:"default"`
}

// Config stores configuration information for the CA.
type Config struct {
	Signing  *Signing           `json:"signing"`
	AuthKeys map[string]AuthKey `json:"auth_keys,omitempty"`
	Remotes  map[string]string  `json:"remotes,omitempty"`
}

// Valid ensures that Config is a valid configuration. It should be
// called immediately after parsing a configuration file.
func (c *Config) Valid() bool {
	return c.Signing.Valid()
}

// Valid checks the signature policies, ensuring they are valid
// policies. A policy is valid if it has defined at least key usages
// to be used, and a valid default profile has defined at least a
// default expiration.
func (p *Signing) Valid() bool {
	if p == nil {
		return false
	}

	log.Debugf("validating configuration")
	if !p.Default.validProfile(true) {
		log.Debugf("default profile is invalid")
		return false
	}

	for _, sp := range p.Profiles {
		if !sp.validProfile(false) {
			log.Debugf("invalid profile")
			return false
		}
	}
	return true
}

// KeyUsage contains a mapping of string names to key usages.
var KeyUsage = map[string]x509.KeyUsage{
	"signing":             x509.KeyUsageDigitalSignature,
	"digital signature":   x509.KeyUsageDigitalSignature,
	"content committment": x509.KeyUsageContentCommitment,
	"key encipherment":    x509.KeyUsageKeyEncipherment,
	"data encipherment":   x509.KeyUsageDataEncipherment,
	"cert sign":           x509.KeyUsageCertSign,
	"crl sign":            x509.KeyUsageCRLSign,
	"encipher only":       x509.KeyUsageEncipherOnly,
	"decipher only":       x509.KeyUsageDecipherOnly,
}

// ExtKeyUsage contains a mapping of string names to extended key
// usages.
var ExtKeyUsage = map[string]x509.ExtKeyUsage{
	"any":              x509.ExtKeyUsageAny,
	"server auth":      x509.ExtKeyUsageServerAuth,
	"client auth":      x509.ExtKeyUsageClientAuth,
	"code signing":     x509.ExtKeyUsageCodeSigning,
	"email protection": x509.ExtKeyUsageEmailProtection,
	"s/mime":           x509.ExtKeyUsageEmailProtection,
	"ipsec end system": x509.ExtKeyUsageIPSECEndSystem,
	"ipsec tunnel":     x509.ExtKeyUsageIPSECTunnel,
	"ipsec user":       x509.ExtKeyUsageIPSECUser,
	"timestamping":     x509.ExtKeyUsageTimeStamping,
	"ocsp signing":     x509.ExtKeyUsageOCSPSigning,
	"microsoft sgc":    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"netscape sgc":     x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// An AuthKey contains an entry for a key used for authentication.
type AuthKey struct {
	// Type contains information needed to select the appropriate
	// constructor. For example, "standard" for HMAC-SHA-256,
	// "standard-ip" for HMAC-SHA-256 incorporating the client's
	// IP.
	Type string `json:"type"`
	// Key contains the key information, such as a hex-encoded
	// HMAC key.
	Key string `json:"key"`
}

// DefaultConfig returns a default configuration specifying basic key
// usage and a 1 year expiration time. The key usages chosen are
// signing, key encipherment, client auth and server auth.
func DefaultConfig() *SigningProfile {
	d := helpers.OneYear
	return &SigningProfile{
		Usage:        []string{"signing", "key encipherment", "server auth", "client auth"},
		Expiry:       d,
		ExpiryString: "8760h",
	}
}

// LoadFile attempts to load the configuration file stored at the path
// and returns the configuration. On error, it returns nil.
func LoadFile(path string) (*Config, error) {
	log.Debugf("loading configuration file from %s", path)
	if path == "" {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, errors.New("invalid path"))
	}

	body, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, errors.New("could not read configuration file"))
	}

	return LoadConfig(body)
}

// LoadConfig attempts to load the configuration from a byte slice.
// On error, it returns nil.
func LoadConfig(config []byte) (*Config, error) {
	var cfg = &Config{}
	err := json.Unmarshal(config, &cfg)
	if err != nil {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, errors.New("failed to unmarshal configuration"))
	}

	if cfg.Signing.Default == nil {
		log.Debugf("no default given: using default config")
		cfg.Signing.Default = DefaultConfig()
	} else {
		if err := cfg.Signing.Default.populate(cfg); err != nil {
			return nil, err
		}
	}

	for k := range cfg.Signing.Profiles {
		if err := cfg.Signing.Profiles[k].populate(cfg); err != nil {
			return nil, err
		}
	}

	if !cfg.Valid() {
		return nil, cferr.Wrap(cferr.PolicyError, cferr.InvalidPolicy, errors.New("invalid configuration"))
	}

	log.Debugf("configuration ok")
	return cfg, nil
}
