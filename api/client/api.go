package client

// SignResult is the result of signing a CSR.
type SignResult struct {
	Certificate []byte `json:"certificate"`
}

// InfoReq is the request struct for an info API request.
type InfoReq struct {
	Label   string `json:"label"`
	Profile string `json:"profile"`
}

// InfoResp is the response for an Info API request.
type InfoResp struct {
	Certificate  string   `json:"certificate"`
	Usage        []string `json:"usages"`
	ExpiryString string   `json:"expiry"`
}
