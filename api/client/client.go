package client

import (
	"bytes"
	"encoding/json"
	stderr "errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/errors"
)

// A Server points to a remote CFSSL instance.
type Server struct {
	Address string
	Port    int
}

// NewServer sets up a new server target. The address should be the
// DNS name (or "name:port") of the remote CFSSL instance. If no port
// is specified, the CFSSL default port (8888) is used.
func NewServer(addr string) *Server {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port, err = net.SplitHostPort(addr + ":8888")
		if err != nil {
			return nil
		}
	}

	var portno int
	if port == "" {
		portno = 8888
	} else {
		portno, err = strconv.Atoi(port)
		if err != nil {
			return nil
		}
	}

	return &Server{host, portno}
}

func (srv *Server) getURL(endpoint string) string {
	return fmt.Sprintf("http://%s:%d/api/v1/cfssl/%s", srv.Address, srv.Port, endpoint)
}

// AuthSign fills out an authenticated request to the server,
// receiving a certificate or error in response.
func (srv *Server) AuthSign(req, ID []byte, profileName string, provider auth.Provider) ([]byte, error) {
	url := srv.getURL("authsign")

	token, err := provider.Token(req)
	if err != nil {
		return nil, errors.New(errors.APIClientError, errors.AuthenticationFailure, err)
	}

	aReq := &auth.AuthenticatedRequest{
		Timestamp:     time.Now().Unix(),
		RemoteAddress: ID,
		Token:         token,
		Request:       req,
	}

	jsonData, err := json.Marshal(aReq)
	if err != nil {
		return nil, errors.New(errors.APIClientError, errors.JSONError, err)
	}

	buf := bytes.NewBuffer(jsonData)
	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		return nil, errors.New(errors.APIClientError, errors.ClientHTTPError, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New(errors.APIClientError, errors.IOError, err)
	}
	resp.Body.Close()

	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, errors.New(errors.APIClientError, errors.JSONError, err)
	}

	if !response.Success || response.Result == nil {
		if len(response.Errors) > 0 {
			return nil, errors.New(errors.APIClientError, errors.ServerRequestFailed, stderr.New(response.Errors[0].Message))
		}
		return nil, errors.New(errors.APIClientError, errors.ServerRequestFailed, nil)
	}
	result := response.Result.(map[string]interface{})
	cert := result["certificate"].(string)

	return []byte(cert), nil
}

// Sign sends a signature request to the remote CFSSL server,
// receiving a signed certificate or an error in response. The hostname,
// csr, and profileName are used as with a local signing operation, and
// the label is used to select a signing root in a multi-root CA.
func (srv *Server) Sign(hostname string, csr []byte, profileName, label string) ([]byte, error) {
	url := srv.getURL("sign")
	var request = map[string]string{
		"certificate_request": string(csr),
		"hostname":            hostname,
		"profile":             profileName,
		"label":               label,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, errors.New(errors.APIClientError, errors.JSONError, err)
	}

	buf := bytes.NewBuffer(jsonData)
	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		return nil, errors.New(errors.APIClientError, errors.ClientHTTPError, err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New(errors.APIClientError, errors.IOError, err)
	}
	resp.Body.Close()

	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, errors.New(errors.APIClientError, errors.JSONError, err)
	}

	if !response.Success || response.Result == nil {
		if len(response.Errors) > 0 {
			return nil, errors.New(errors.APIClientError, errors.ServerRequestFailed, stderr.New(response.Errors[0].Message))
		}
		return nil, errors.New(errors.APIClientError, errors.ServerRequestFailed, nil)
	}
	result := response.Result.(map[string]interface{})
	cert := result["certificate"].(string)

	return []byte(cert), nil
}
