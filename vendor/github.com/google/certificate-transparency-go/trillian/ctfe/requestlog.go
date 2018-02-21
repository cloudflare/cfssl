// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ctfe

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

const vLevel = 9

// RequestLog allows implementations to do structured logging of CTFE
// request parameters, submitted chains and other internal details that
// are useful for log operators when debugging issues. CTFE handlers will
// call the appropriate methods during request processing. The implementation
// is responsible for collating and storing the resulting logging information.
type RequestLog interface {
	// Start will be called once at the beginning of handling each request.
	// The supplied context will be the one used for request processing and
	// can be used by the logger to set values on the returned context.
	// The returned context should be used in all the following calls to
	// this API. This is normally arranged by the request handler code.
	Start(context.Context) context.Context
	// LogPrefix will be called once per request to set the log prefix.
	LogPrefix(context.Context, string)
	// AddDERToChain will be called once for each certificate in a submitted
	// chain. It's called early in request processing so the supplied bytes
	// have not been checked for validity. Calls will be in order of the
	// certificates as presented in the request with the root last.
	AddDERToChain(context.Context, []byte)
	// AddCertToChain will be called once for each certificate in the chain
	// after it has been parsed and verified. Calls will be in order of the
	// certificates as presented in the request with the root last.
	AddCertToChain(context.Context, *x509.Certificate)
	// FirstAndSecond will be called once for a consistency proof request with
	// the first and second tree sizes involved (if they parse correctly).
	FirstAndSecond(context.Context, int64, int64)
	// StartAndEnd will be called once for a get entries request with the
	// endpoints of the range requested (if they parse correctly).
	StartAndEnd(context.Context, int64, int64)
	// LeafIndex will be called once with the index of a leaf being requested
	// by get entry and proof (if the request params parse correctly).
	LeafIndex(context.Context, int64)
	// TreeSize will be called once with the requested tree size for get entry
	// and proof requests (if the request params parse correctly).
	TreeSize(context.Context, int64)
	// LeafHash will be called once for get proof by hash requests with the
	// requested hash value (if the parameters parse correctly).
	LeafHash(context.Context, []byte)
	// Status will be called once to set the HTTP status code that was the
	// the result after the request has been handled.
	Status(context.Context, int)
}

// DefaultRequestLog is an implementation of RequestLog that does nothing
// except log the calls at a high level of verbosity.
type DefaultRequestLog struct {
}

// Start logs the start of request processing.
func (dlr *DefaultRequestLog) Start(ctx context.Context) context.Context {
	glog.V(vLevel).Info("RL: Start")
	return ctx
}

// LogPrefix logs the prefix of the CT log that this request is for.
func (dlr *DefaultRequestLog) LogPrefix(_ context.Context, p string) {
	glog.V(vLevel).Infof("RL: LogPrefix: %s", p)
}

// AddDERToChain logs the raw bytes of a submitted certificate.
func (dlr *DefaultRequestLog) AddDERToChain(_ context.Context, d []byte) {
	glog.V(vLevel).Infof("RL: Cert DER: %s", hex.EncodeToString(d))
}

// AddCertToChain logs some issuer / subject / timing fields from a
// certificate that is part of a submitted chain.
func (dlr *DefaultRequestLog) AddCertToChain(_ context.Context, cert *x509.Certificate) {
	glog.V(vLevel).Infof("RL: Cert: Sub: %s Iss: %s notBef: %s notAft: %s",
		x509util.NameToString(cert.Subject),
		x509util.NameToString(cert.Issuer),
		cert.NotBefore.Format(time.RFC1123Z),
		cert.NotAfter.Format(time.RFC1123Z))
}

// FirstAndSecond logs request parameters.
func (dlr *DefaultRequestLog) FirstAndSecond(_ context.Context, f, s int64) {
	glog.V(vLevel).Infof("RL: First: %d Second: %d", f, s)
}

// StartAndEnd logs request parameters.
func (dlr *DefaultRequestLog) StartAndEnd(_ context.Context, s, e int64) {
	glog.V(vLevel).Infof("RL: Start: %d End: %d", s, e)
}

// LeafIndex logs request parameters.
func (dlr *DefaultRequestLog) LeafIndex(_ context.Context, li int64) {
	glog.V(vLevel).Infof("RL: LeafIndex: %d", li)
}

// TreeSize logs request parameters.
func (dlr *DefaultRequestLog) TreeSize(_ context.Context, ts int64) {
	glog.V(vLevel).Infof("RL: TreeSize: %d", ts)
}

// LeafHash logs request parameters.
func (dlr *DefaultRequestLog) LeafHash(_ context.Context, lh []byte) {
	glog.V(vLevel).Infof("RL: LeafHash: %s", hex.EncodeToString(lh))
}

// Status logs the response HTTP status code after processing completes.
func (dlr *DefaultRequestLog) Status(_ context.Context, s int) {
	glog.V(vLevel).Infof("RL: Status: %d", s)
}
