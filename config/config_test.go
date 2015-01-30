package config

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

var expiry = 1 * time.Minute

var invalidProfileConfig = &Config{
	Signing: &Signing{
		Profiles: map[string]*SigningProfile{
			"invalid": {
				Usage:  []string{"wiretapping"},
				Expiry: expiry,
			},
			"empty": {},
		},
		Default: &SigningProfile{
			Usage:  []string{"digital signature"},
			Expiry: expiry,
		},
	},
}

var invalidDefaultConfig = &Config{
	Signing: &Signing{
		Profiles: map[string]*SigningProfile{
			"key usage": {
				Usage: []string{"digital signature"},
			},
		},
		Default: &SigningProfile{
			Usage: []string{"s/mime"},
		},
	},
}

var validConfig = &Config{
	Signing: &Signing{
		Profiles: map[string]*SigningProfile{
			"valid": {
				Usage:  []string{"digital signature"},
				Expiry: expiry,
			},
		},
		Default: &SigningProfile{
			Usage:  []string{"digital signature"},
			Expiry: expiry,
		},
	},
}

func TestInvalidProfile(t *testing.T) {
	if invalidProfileConfig.Signing.Profiles["invalid"].validProfile(false) {
		t.Fatal("invalid profile accepted as valid")
	}

	if invalidProfileConfig.Signing.Profiles["empty"].validProfile(false) {
		t.Fatal("invalid profile accepted as valid")
	}

	if invalidProfileConfig.Valid() {
		t.Fatal("invalid config accepted as valid")
	}

	if !invalidProfileConfig.Signing.Profiles["invalid"].validProfile(true) {
		t.Fatal("invalid profile should be a valid default profile")
	}
}

func TestInvalidDefault(t *testing.T) {
	if invalidDefaultConfig.Signing.Default.validProfile(true) {
		t.Fatal("invalid default accepted as valid")
	}

	if invalidDefaultConfig.Valid() {
		t.Fatal("invalid config accepted as valid")
	}

	if !invalidDefaultConfig.Signing.Default.validProfile(false) {
		t.Fatal("invalid default profile should be a valid profile")
	}
}

func TestValidConfig(t *testing.T) {
	if !validConfig.Valid() {
		t.Fatal("Valid config is not valid")
	}
	bytes, _ := json.Marshal(validConfig)
	fmt.Printf("%v", string(bytes))
}

func TestDefaultConfig(t *testing.T) {
	if !DefaultConfig().validProfile(false) {
		t.Fatal("global default signing profile should be a valid profile.")
	}

	if !DefaultConfig().validProfile(true) {
		t.Fatal("global default signing profile should be a valid default profile")
	}
}

func TestParse(t *testing.T) {
	var validProfiles = []*SigningProfile{
		{
			ExpiryString: "8760h",
		},
		{
			ExpiryString: "168h",
		},
		{
			ExpiryString: "300s",
		},
	}
	var invalidProfiles = []*SigningProfile{
		nil,
		{},
		{
			ExpiryString: "",
		},
		{
			ExpiryString: "365d",
		},
		{
			ExpiryString: "1y",
		},
		{
			ExpiryString: "one year",
		},
	}

	for _, p := range validProfiles {
		if p.populate(nil) != nil {
			t.Fatalf("Failed to parse ExpiryString=%s", p.ExpiryString)
		}
	}

	for _, p := range invalidProfiles {
		if p.populate(nil) == nil {
			if p != nil {
				t.Fatalf("ExpiryString=%s should not be parseable", p.ExpiryString)
			}
			t.Fatalf("Nil profile should not be parseable")
		}
	}
}

func TestLoadFile(t *testing.T) {
	validConfigFiles := []string{"testdata/valid_config.json", "testdata/valid_config_auth.json", "testdata/valid_config_no_default.json"}
	for _, configFile := range validConfigFiles {
		_, err := LoadFile(configFile)
		if err != nil {
			t.Fatal("Load valid config failded.", configFile)
		}
	}
}

func TestLoadInvalidConfigFile(t *testing.T) {
	invalidConfigFiles := []string{"", "testdata/no_such_file",
		"testdata/invalid_default.json",
		"testdata/invalid_profiles.json",
		"testdata/invalid_usage.json",
		"testdata/invalid_config.json",
		"testdata/invalid_auth.json",
		"testdata/invalid_remote.json"}
	for _, configFile := range invalidConfigFiles {
		_, err := LoadFile(configFile)
		if err == nil {
			t.Fatal("Invalid config is loaded.", configFile)
		}
	}
}
