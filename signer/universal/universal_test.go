package universal

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api"
	apiinfo "github.com/cloudflare/cfssl/api/info"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

const (
	testCaFile    = "../local/testdata/ca.pem"
	testCaKeyFile = "../local/testdata/ca_key.pem"
)

var expiry = 1 * time.Minute
var validLocalConfig = &config.Config{
	Signing: &config.Signing{
		Profiles: map[string]*config.SigningProfile{
			"valid": {
				Usage:  []string{"digital signature"},
				Expiry: expiry,
			},
		},
		Default: &config.SigningProfile{
			Usage:  []string{"digital signature"},
			Expiry: expiry,
		},
	},
}

var validMinimalRemoteConfig = `
{
  "signing": {
    "profiles": {
      "CA": {
        "usages": [
          "cert sign",
          "clr sign"
        ],
        "expiry": "720h",
        "auth_key": "ca-auth"
      }
    },
    "default": {
      "usages": [
        "digital signature",
        "email protection"
      ],
      "expiry": "8000h"
    }
  },
  "auth_keys": {
    "ca-auth": {
      "type": "standard",
      "key": "0123456789ABCDEF0123456789ABCDEF"
    }
  }
}`

var validMinimalUniversalConfig = `
{
  "signing": {
    "profiles": {
      "CA": {
        "usages": [
          "cert sign",
          "clr sign"
        ],
        "expiry": "720h",
        "auth_key": "local-auth",
        "auth_remote": {
          "remote": "localhost",
          "auth_key": "ca-auth"
        }
      },
      "email": {
        "usages": [
          "s/mime"
        ],
        "expiry": "720h"
      }
    },
    "default": {
      "usages": [
        "digital signature",
        "email protection"
      ],
      "expiry": "8000h"
    }
  },
  "auth_keys": {
    "local-auth": {
      "type": "standard",
      "key": "123456789ABCDEF0123456789ABCDEF0"
    },
    "ca-auth": {
      "type": "standard",
      "key": "0123456789ABCDEF0123456789ABCDEF"
    }
  },
  "remotes": {
    "localhost": "127.0.0.1:1234"
  }
}`

var validRemoteConfig = `
{
  "signing": {
    "profiles": {
      "CA": {
        "usages": [
          "cert sign",
          "clr sign"
        ],
        "expiry": "720h",
        "auth_key": "ca-auth"
      },
      "ipsec": {
        "usages": [
          "ipsec tunnel"
        ],
        "expiry": "720h"
      }
    },
    "default": {
      "usages": [
        "digital signature",
        "email protection"
      ],
      "expiry": "8000h"
    }
  },
  "auth_keys": {
    "ca-auth": {
      "type": "standard",
      "key": "0123456789ABCDEF0123456789ABCDEF"
    }
  }
}`

var validUniversalConfig = `
{
  "signing": {
    "profiles": {
      "CA": {
        "usages": [
          "cert sign",
          "clr sign"
        ],
        "expiry": "720h",
        "auth_key": "local-auth",
        "auth_remote": {
          "remote": "localhost",
          "auth_key": "ca-auth"
        }
      },
      "ipsec": {
        "usages": [
          "ipsec tunnel"
        ],
        "expiry": "720h",
		"remote": "localhost"
      },
      "email": {
        "usages": [
          "s/mime"
        ],
        "expiry": "720h"
      }
    },
    "default": {
      "usages": [
        "digital signature",
        "email protection"
      ],
      "expiry": "8000h"
    }
  },
  "auth_keys": {
    "local-auth": {
      "type": "standard",
      "key": "123456789ABCDEF0123456789ABCDEF0"
    },
    "ca-auth": {
      "type": "standard",
      "key": "0123456789ABCDEF0123456789ABCDEF"
    }
  },
  "remotes": {
    "localhost": "127.0.0.1:1234"
  }
}`

var validNoAuthRemoteConfig = `
{
  "signing": {
    "profiles": {
      "CA": {
        "usages": [
          "cert sign",
          "clr sign"
        ],
        "expiry": "720h"
      },
      "ipsec": {
        "usages": [
          "ipsec tunnel"
        ],
        "expiry": "720h"
      }
    },
    "default": {
      "usages": [
        "digital signature",
        "email protection"
      ],
      "expiry": "8000h"
    }
  }
}`

var validNoAuthUniversalConfig = `
{
  "signing": {
    "profiles": {
      "CA": {
        "usages": [
          "cert sign",
          "clr sign"
        ],
        "expiry": "720h",
		"remote": "localhost"
      },
      "ipsec": {
        "usages": [
          "ipsec tunnel"
        ],
        "expiry": "720h",
		"remote": "localhost"
      },
      "email": {
        "usages": [
          "s/mime"
        ],
        "expiry": "720h"
      }
    },
    "default": {
      "usages": [
        "digital signature",
        "email protection"
      ],
      "expiry": "8000h"
    }
  },
  "remotes": {
    "localhost": "127.0.0.1:1234"
  }
}`

func TestNewSigner(t *testing.T) {
	h := map[string]string{
		"key-file":  testCaKeyFile,
		"cert-file": testCaFile,
	}

	r := &Root{
		Config:      h,
		ForceRemote: false,
	}

	_, err := NewSigner(*r, validLocalConfig.Signing)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUniversalRemoteAndLocalInfo(t *testing.T) {
	// set up remote server
	remoteConfig := newConfig(t, []byte(validMinimalRemoteConfig))
	remoteServer := newTestInfoServer(t, newTestUniversalSigner(t, remoteConfig.Signing))
	defer closeTestServer(t, remoteServer)

	universalConfig := newConfig(t, []byte(validMinimalUniversalConfig))
	// override with test server address, ignore url prefix "http://"
	for name, profile := range universalConfig.Signing.Profiles {
		if profile.RemoteServer != "" {
			universalConfig.Signing.Profiles[name].RemoteServer = remoteServer.URL[7:]
		}
	}
	s := newTestUniversalSigner(t, universalConfig.Signing)

	for name, profile := range universalConfig.Signing.Profiles {
		req := info.Req{
			Profile: name,
		}
		resp, err := s.Info(req)
		if err != nil {
			t.Fatal("remote info failed:", err)
		}

		if strings.Join(profile.Usage, ",") != strings.Join(resp.Usage, ",") {
			t.Fatalf("Expected usage for profile %s to be %+v, got %+v", name, profile.Usage, resp.Usage)
		}

		caBytes, err := ioutil.ReadFile(testCaFile)
		caBytes = bytes.TrimSpace(caBytes)
		if err != nil {
			t.Fatal("fail to read test CA cert:", err)
		}

		if bytes.Compare(caBytes, []byte(resp.Certificate)) != 0 {
			t.Fatal("Get a different CA cert through info api.", len(resp.Certificate), len(caBytes))
		}
	}
}

func TestUniversalMultipleRemoteAndLocalInfo(t *testing.T) {
	// set up remote server
	remoteConfig := newConfig(t, []byte(validRemoteConfig))
	remoteServer := newTestInfoServer(t, newTestUniversalSigner(t, remoteConfig.Signing))
	defer closeTestServer(t, remoteServer)

	universalConfig := newConfig(t, []byte(validUniversalConfig))
	// override with test server address, ignore url prefix "http://"
	for name, profile := range universalConfig.Signing.Profiles {
		if profile.RemoteServer != "" {
			universalConfig.Signing.Profiles[name].RemoteServer = remoteServer.URL[7:]
		}
	}
	s := newTestUniversalSigner(t, universalConfig.Signing)

	for name, profile := range universalConfig.Signing.Profiles {
		req := info.Req{
			Profile: name,
		}
		resp, err := s.Info(req)
		if err != nil {
			t.Fatal("remote info failed:", err)
		}

		if strings.Join(profile.Usage, ",") != strings.Join(resp.Usage, ",") {
			t.Fatalf("Expected usage for profile %s to be %+v, got %+v", name, profile.Usage, resp.Usage)
		}

		caBytes, err := ioutil.ReadFile(testCaFile)
		caBytes = bytes.TrimSpace(caBytes)
		if err != nil {
			t.Fatal("fail to read test CA cert:", err)
		}

		if bytes.Compare(caBytes, []byte(resp.Certificate)) != 0 {
			t.Fatal("Get a different CA cert through info api.", len(resp.Certificate), len(caBytes))
		}
	}
}

type csrTest struct {
	file    string
	keyAlgo string
	keyLen  int
	// Error checking function
	errorCallback func(*testing.T, error)
}

var csrTests = []csrTest{
	{
		file:          "../local/testdata/rsa2048.csr",
		keyAlgo:       "rsa",
		keyLen:        2048,
		errorCallback: nil,
	},
	{
		file:          "../local/testdata/rsa3072.csr",
		keyAlgo:       "rsa",
		keyLen:        3072,
		errorCallback: nil,
	},
	{
		file:          "../local/testdata/rsa4096.csr",
		keyAlgo:       "rsa",
		keyLen:        4096,
		errorCallback: nil,
	},
	{
		file:          "../local/testdata/ecdsa256.csr",
		keyAlgo:       "ecdsa",
		keyLen:        256,
		errorCallback: nil,
	},
	{
		file:          "../local/testdata/ecdsa384.csr",
		keyAlgo:       "ecdsa",
		keyLen:        384,
		errorCallback: nil,
	},
	{
		file:          "../local/testdata/ecdsa521.csr",
		keyAlgo:       "ecdsa",
		keyLen:        521,
		errorCallback: nil,
	},
}

func TestUniversalRemoteAndLocalSign(t *testing.T) {
	// set up remote server
	remoteConfig := newConfig(t, []byte(validNoAuthRemoteConfig))
	remoteServer := newTestSignServer(t, newTestUniversalSigner(t, remoteConfig.Signing))
	defer closeTestServer(t, remoteServer)

	universalConfig := newConfig(t, []byte(validNoAuthUniversalConfig))
	// override with test server address, ignore url prefix "http://"
	for name, profile := range universalConfig.Signing.Profiles {
		if profile.RemoteServer != "" {
			universalConfig.Signing.Profiles[name].RemoteServer = remoteServer.URL[7:]
		}
	}
	s := newTestUniversalSigner(t, universalConfig.Signing)

	for name, profile := range universalConfig.Signing.Profiles {
		hosts := []string{"cloudflare.com"}
		for _, test := range csrTests {
			csr, err := ioutil.ReadFile(test.file)
			if err != nil {
				t.Fatalf("CSR loading error (%s): %v", name, err)
			}
			testSerial := big.NewInt(0x7007F)

			certBytes, err := s.Sign(signer.SignRequest{
				Hosts:   hosts,
				Request: string(csr),
				Serial:  testSerial,
				Profile: name,
			})
			if test.errorCallback != nil {
				test.errorCallback(t, err)
			} else {
				if err != nil {
					t.Fatalf("Expected no error. Got %s. Param %s %d", err.Error(), test.keyAlgo, test.keyLen)
				}
				cert, err := helpers.ParseCertificatePEM(certBytes)
				if err != nil {
					t.Fatal("Fail to parse returned certificate:", err)
				}
				ku, _, _ := profile.Usages()
				if cert.KeyUsage != ku {
					t.Fatalf("Key usage was incorrect expected %+v, got %+v", ku, cert.KeyUsage)
				}
			}
		}
	}
}

func newConfig(t *testing.T, configBytes []byte) *config.Config {
	conf, err := config.LoadConfig([]byte(configBytes))
	if err != nil {
		t.Fatal("config loading error:", err)
	}
	if !conf.Valid() {
		t.Fatal("config is not valid")
	}
	return conf
}

func newTestUniversalSigner(t *testing.T, policy *config.Signing) signer.Signer {
	h := map[string]string{
		"key-file":  testCaKeyFile,
		"cert-file": testCaFile,
	}

	r := &Root{
		Config:      h,
		ForceRemote: false,
	}

	s, err := NewSigner(*r, policy)
	if err != nil {
		t.Fatal("fail to init universal signer:", err)
	}

	return s
}

func newTestSignHandler(t *testing.T, s signer.Signer) (h http.Handler) {
	h, err := NewSignHandlerFromSigner(s)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func newTestInfoHandler(t *testing.T, s signer.Signer) (h http.Handler) {
	h, err := apiinfo.NewHandler(s)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func newTestSignServer(t *testing.T, s signer.Signer) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/cfssl/sign", newTestSignHandler(t, s))
	ts := httptest.NewUnstartedServer(mux)
	ts.Start()
	t.Log(ts.URL)
	return ts
}

func newTestInfoServer(t *testing.T, s signer.Signer) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/cfssl/info", newTestInfoHandler(t, s))
	ts := httptest.NewUnstartedServer(mux)
	ts.Start()
	t.Log(ts.URL)
	return ts
}

func closeTestServer(t *testing.T, ts *httptest.Server) {
	t.Log("Finalizing test server.")
	ts.Close()
}

// NewSignHandlerFromSigner generates a new SignHandler directly from
// an existing signer.
func NewSignHandlerFromSigner(s signer.Signer) (h http.Handler, err error) {
	policy := s.Policy()
	if policy == nil {
		err = errors.New(errors.PolicyError, errors.InvalidPolicy)
		return
	}

	// Sign will only respond for profiles that have no auth provider.
	// So if all of the profiles require authentication, we return an error.
	haveUnauth := (policy.Default.Provider == nil)
	for _, profile := range policy.Profiles {
		if !haveUnauth {
			break
		}
		haveUnauth = (profile.Provider == nil)
	}

	if !haveUnauth {
		err = errors.New(errors.PolicyError, errors.InvalidPolicy)
		return
	}

	return &api.HTTPHandler{
		Handler: &SignHandler{
			signer: s,
		},
		Methods: []string{"POST"},
	}, nil
}

// A SignHandler accepts requests with a hostname and certficate
// parameter (which should be PEM-encoded) and returns a new signed
// certificate. It includes upstream servers indexed by their
// profile name.
type SignHandler struct {
	signer signer.Signer
}

// Handle responds to requests for the CA to sign the certificate request
// present in the "certificate_request" parameter for the host named
// in the "hostname" parameter. The certificate should be PEM-encoded. If
// provided, subject information from the "subject" parameter will be used
// in place of the subject information from the CSR.
func (h *SignHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("signature request received")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	var req signer.SignRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		return err
	}

	if len(req.Hosts) == 0 {
		return errors.NewBadRequestString("missing paratmeter 'hosts'")
	}

	if req.Request == "" {
		return errors.NewBadRequestString("missing parameter 'certificate_request'")
	}

	var cert []byte
	var profile *config.SigningProfile

	policy := h.signer.Policy()
	if policy != nil && policy.Profiles != nil && req.Profile != "" {
		profile = policy.Profiles[req.Profile]
	}

	if profile == nil && policy != nil {
		profile = policy.Default
	}

	if profile.Provider != nil {
		log.Error("profile requires authentication")
		return errors.NewBadRequestString("authentication required")
	}

	cert, err = h.signer.Sign(req)
	if err != nil {
		log.Warningf("failed to sign request: %v", err)
		return err
	}

	result := map[string]string{"certificate": string(cert)}
	log.Info("wrote response")
	return api.SendResponse(w, result)
}
