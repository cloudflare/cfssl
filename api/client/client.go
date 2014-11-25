package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"

	"github.com/cloudflare/cfssl/auth"
)

// A Server points to a remote CFSSL instance.
type Server struct {
	Address string
	Port    int
}

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

func (srv *Server) AuthSign(hostname string, csr []byte, profileName string, provider auth.Provider) ([]byte, error) {
	req, err := srv.Sign(hostname, csr, profileName)
	if err != nil {
		return nil, err
	}
	return provider.Token(req)
}

// Sign sends a signature request to the remote CFSSL server,
// receiving a signed certificate or an error in response.
func (srv *Server) Sign(hostname string, csr []byte, profileName string) ([]byte, error) {
	url := srv.getURL("sign")
	var request = map[string]string{
		"certificate_request": string(csr),
		"hostname":            hostname,
		"profile":             profileName,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(jsonData)
	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	if !response.Success || response.Result == nil {
		if len(response.Errors) > 0 {
			return nil, errors.New(response.Errors[0].Message)
		}
		return nil, errors.New("API response was not successful")
	}
	result := response.Result.(map[string]interface{})
	cert := result["certificate"].(string)

	return []byte(cert), nil
}
