package client

// ResponseMessage implements the standard for response errors and
// messages. A message has a code and a string message.
type ResponseMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Response implements the CloudFlare standard for API
// responses. CFSSL does not currently use the messages field, but it
// is provided for compatability.
type Response struct {
	Success  bool              `json:"success"`
	Result   interface{}       `json:"result"`
	Errors   []ResponseMessage `json:"errors"`
	Messages []ResponseMessage `json:"messages"`
}

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
	Certificate string `json:"certificate"`
}
