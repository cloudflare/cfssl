package scan

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudflare/cfssl/certinfo"
	"github.com/cloudflare/cfssl/helpers"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// Issuer is a CertSpotter API Response for the expanded Issuer Object containing
// an Issuer Name and a SHA256 hash of the PublicKey
type Issuer struct {
	Name         string `json:"name"`
	PubkeySha256 string `json:"pubkey_sha256"`
}

// CertSpotterCertificate is a CertSpotter API Response for the expanded Certificate Object containing
// information about the certificate type, hash of the certificate and base64 encoded certificate data.
type CertSpotterCertificate struct {
	Type       string `json:"type"`
	Sha256Hash string `json:"sha256"`
	Data       string `json:"data"`
}

// Issuance is a CertSpotter API Response for Each Issuance object for a given domain name and contains the expanded objects.
type Issuance struct {
	ID           string                 `json:"id"`            // Identifier representing the issuance object
	TbsShaHash   string                 `json:"tbs_sha256"`    // Hex encoded SHA-256 digest of the TBS Certificate
	DNSNames     []string               `json:"dns_names"`     // DNS names for which the issuance is valid
	PubkeySha256 string                 `json:"pubkey_sha256"` // Subject Public Key Information as Hex encoded SHA256 digest
	Issuer       Issuer                 `json:"issuer"`        // Information about the issuer
	NotBefore    time.Time              `json:"not_before"`    // Not Valid Before Date
	NotAfter     time.Time              `json:"not_after"`     // Not Valid After Date
	Cert         CertSpotterCertificate `json:"cert"`          // Certificate Details
}

// SSLMateResponse is a CertSpotter API Response for a given domain consisting of Issuance objects.
type SSLMateResponse struct {
	Data []Issuance
}

// SSLMateErrorResponse is a CertSpotter API Response obtained in case of Rate Limits and Errors.
type SSLMateErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (issuance *Issuance) marshalJSON() (string, error) {
	s, err := json.Marshal(issuance)
	if err != nil {
		fmt.Println(err)
		return string(s), err
	}
	return string(s), nil
}

func (issuanceList *SSLMateResponse) marshalJSON() (string, error) {
	s, err := json.Marshal(issuanceList)
	if err != nil {
		fmt.Println(err)
		return string(s), err
	}
	return string(s), nil
}

func unmarshalResponse(body []byte) (SSLMateResponse, error) {
	var issuanceResponses []Issuance
	var limitReachedService SSLMateErrorResponse
	err := json.Unmarshal(body, &issuanceResponses)
	if err != nil {
		err := json.Unmarshal(body, &limitReachedService)
		if err != nil {
			return SSLMateResponse{nil}, err
		}
		limitReachedError := fmt.Errorf("%s %s", limitReachedService.Code, limitReachedService.Message)
		return SSLMateResponse{nil}, limitReachedError
	}
	data := SSLMateResponse{Data: issuanceResponses}
	return data, err
}

func request(queryString string, client *http.Client, token string, verbosity bool, c chan APIResponseStatus) {
	req, err := http.NewRequest("GET", queryString, nil)

	if err != nil {
		reqError := fmt.Errorf("Error creating request %v", err)
		c <- APIResponseStatus{
			status:    false,
			issuances: nil,
			err:       reqError,
		}
	}

	if token != "" {
		bearerString := "Bearer " + token
		req.Header.Add("Authorization", bearerString)
	}

	resp, err := client.Do(req)

	if err != nil {
		serviceAPIError := fmt.Errorf("Couldn't Reach SSLMate Service : %v", err)
		c <- APIResponseStatus{
			status:    false,
			issuances: nil,
			err:       serviceAPIError,
		}
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		bodyReadError := fmt.Errorf("Couldn't read the response from service: %v", err)
		c <- APIResponseStatus{
			status:    false,
			issuances: nil,
			err:       bodyReadError,
		}
	}

	data, err := unmarshalResponse(body)

	if err != nil {
		c <- APIResponseStatus{
			status:    false,
			issuances: nil,
			err:       err,
		}
	}

	// Contains the verbose response of each certificate
	certificates := make([]*certinfo.Certificate, 0)
	// Prepare a common response of CTIssuanceObjects
	certIssuances := make([]CTIssuance, 0)
	for _, cert := range data.Data {
		certType := cert.Cert.Type
		b64Decoded, derr := base64.StdEncoding.DecodeString(cert.Cert.Data)
		if derr != nil {
			fmt.Println("Failed to decode base64 string")
		}
		certificate, cerr := helpers.ParseASN1Bytes(b64Decoded)
		certParsed := certinfo.ParseCertificate(certificate)
		if cerr != nil {
			fmt.Printf("Failed to decode cert %v\n", cerr)
		}
		certificates = append(certificates, certParsed)

		certIssuance := CTIssuance{
			ID:               cert.ID,
			PemCert:          certParsed.RawPEM,
			CertType:         certType,
			NotBefore:        certParsed.NotBefore,
			NotAfter:         certParsed.NotAfter,
			SerialNumber:     certParsed.SerialNumber,
			IssuerCommonName: certParsed.Issuer.CommonName,
		}

		if verbosity {
			certIssuance.Cert = certParsed
		}

		certIssuances = append(certIssuances, certIssuance)
	}
	c <- APIResponseStatus{
		status:    true,
		issuances: certIssuances,
		err:       nil,
	}
}

func initOnCertSpotterScan() (http.Client, url.URL, error) {
	client := http.Client{
		Transport:     nil,
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       0,
	}

	sslMateAPIHost := url.URL{
		Scheme:     "https",
		Host:       "api.certspotter.com",
		Path:       "/v1/issuances",
		ForceQuery: false,
	}

	return client, sslMateAPIHost, nil
}

// CertSpotterScan performs the scan on the hostname and retrieves the CT Log entries from the SSLMate API
func CertSpotterScan(addr, hostname string, token string, verbosity bool) (grade Grade, output Output, err error) {
	var client http.Client
	var sslMateAPIHost url.URL

	if client, sslMateAPIHost, err = initOnCertSpotterScan(); err != nil {
		grade = Skipped
		return
	}

	sslMateAPIHost.RawQuery = url.Values{
		"domain":             {hostname},
		"include_subdomains": {"true"},
		"match_wildcards":    {"true"},
		"expand":             {"dns_names", "issuer", "cert"},
	}.Encode()

	var queryString = sslMateAPIHost.String()

	c := make(chan APIResponseStatus)
	response := make([]CTIssuance, 0)

	go request(queryString, &client, token, verbosity, c)
	responses := <-c

	if responses.status {
		for _, issuance := range responses.issuances {
			response = append(response, issuance)
		}
		grade = Good
		err = responses.err
	} else {
		grade = Bad
		err = responses.err
	}

	return grade, response, err
}
