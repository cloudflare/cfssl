FROM golang:1.4.2-cross

# TODO: Vendor these `go get` commands using Godep.
RUN go get github.com/mitchellh/gox
RUN go get github.com/tools/godep
RUN go get github.com/cloudflare/cf-tls/tls
RUN go get github.com/cloudflare/go-metrics
RUN go get github.com/cloudflare/redoctober/core
RUN go get github.com/dgryski/go-rc2
RUN go get golang.org/x/crypto/ocsp
RUN go get github.com/GeertJohan/go.rice

ENV GOPATH /go/src/github.com/cloudflare/cfssl:/go
ENV USER root

WORKDIR /go/src/github.com/cloudflare/cfssl

ADD . /go/src/github.com/cloudflare/cfssl
