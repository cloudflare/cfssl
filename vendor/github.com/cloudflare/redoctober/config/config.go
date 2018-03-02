// Package config implements configuration structures for Red
// October.
package config

import (
	"encoding/json"
	"io/ioutil"
)

// Server contains the configuration information required to start a
// redoctober server.
type Server struct {
	// Addr contains the host:port that the server should listen
	// on.
	Addr string `json:"address"`

	// CAPath contains the path to the TLS CA for client
	// authentication. This is an optional field.
	CAPath string `json:"ca_path,omitempty"`

	// KeyPaths and CertPaths contains a list of paths to TLS key
	// pairs that should be used to secure connections to the
	// server. The paths should be comma-separated.
	KeyPaths  string `json:"private_keys"`
	CertPaths string `json:"certificates"`

	// Systemd indicates whether systemd socket activation should
	// be used instead of a normal port listener.
	Systemd bool `json:"use_systemd,omitempty"`
}

// UI contains the configuration information for the WWW API.
type UI struct {
	// Root contains the base URL for the UI.
	Root string `json:"root"`

	// Static is an optional path for overriding the built in HTML
	// UI.
	Static string `json:"static"`
}

// HipChat contains the settings for Hipchat integration. The ID is
// the name that should be used in the startup message.
type HipChat struct {
	Host   string `json:"host"`
	Room   string `json:"room"`
	ID     string `json:"id"`
	APIKey string `json:"api_key"`
}

// Valid returns true if the HipChat config is ready to be used for
// HipChat notifications.
func (hc *HipChat) Valid() bool {
	if hc.APIKey == "" {
		return false
	}

	if hc.Room == "" {
		return false
	}

	if hc.Host == "" {
		return false
	}

	return true
}

// Metrics contains the configuration for the Prometheus metrics
// collector.
type Metrics struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

// Reporting contains configuration for error reporting.
type Reporting struct {
	SentryDSN string `json:"sentry_dsn"`
}

// Delegations contains configuration for persisting delegations.
type Delegations struct {
	// Persist controls whether delegations are persisted or not.
	Persist bool `json:"persist"`

	// Policy contains the MSP predicate for delegation
	// persistence, and users contains the users allowed
	// to delegate.
	Policy string   `json:"policy"`
	Users  []string `json:"users"`

	// Mechanism specifies the persistence mechanism to use.
	Mechanism string `json:"mechanism"`

	// Location contains location information for the persistence
	// mechanism, such as a file path or database connection
	// string.
	Location string `json:"location"`
}

// Config contains all the configuration options for a redoctober
// instance.
type Config struct {
	Server      *Server      `json:"server"`
	UI          *UI          `json:"ui"`
	HipChat     *HipChat     `json:"hipchat"`
	Metrics     *Metrics     `json:"metrics"`
	Reporting   *Reporting   `json:"reporting"`
	Delegations *Delegations `json:"delegations"`
}

// Valid ensures that the config has enough data to start a Red
// October process.
func (c *Config) Valid() bool {
	// The RedOctober API relies on TLS for security.
	if len(c.Server.CertPaths) == 0 || len(c.Server.KeyPaths) == 0 {
		return false
	}

	// The server needs some address to listen on.
	if c.Server.Addr == "" && !c.Server.Systemd {
		return false
	}

	return true
}

// New returns a new, empty config.
func New() *Config {
	return &Config{
		Server:      &Server{},
		UI:          &UI{},
		HipChat:     &HipChat{},
		Metrics:     &Metrics{},
		Reporting:   &Reporting{},
		Delegations: &Delegations{},
	}
}

// Load reads a JSON-encoded config file from disk.
func Load(path string) (*Config, error) {
	cfg := New()
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(in, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
