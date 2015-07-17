FROM golang:1.4.2

WORKDIR /go/src/github.com/cloudflare/cfssl

ENV GOPATH /go/src/github.com/cloudflare/cfssl:/go
ENV USER root

ENTRYPOINT ["cfssl"]

RUN go get github.com/cloudflare/cf-tls/tls
RUN go get github.com/cloudflare/go-metrics
RUN go get github.com/cloudflare/redoctober/core
RUN go get github.com/dgryski/go-rc2
RUN go get golang.org/x/crypto/ocsp

ADD . /go/src/github.com/cloudflare/cfssl

RUN go build cmd/cfssl/cfssl.go && cp cfssl /usr/local/bin

WORKDIR /opt
