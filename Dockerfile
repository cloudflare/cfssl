FROM golang:1.4.2

WORKDIR /go/src/github.com/cloudflare/cfssl

ENV GOPATH /go/src/github.com/cloudflare/cfssl:/go
ENV USER root

EXPOSE 8888

CMD ["cfssl"]

RUN go get github.com/cloudflare/cf-tls/tls
RUN go get github.com/cloudflare/go-metrics
RUN go get github.com/cloudflare/redoctober/core
RUN go get github.com/dgryski/go-rc2
RUN go get golang.org/x/crypto/ocsp
RUN go get github.com/GeertJohan/go.rice

ADD . /go/src/github.com/cloudflare/cfssl

RUN go build cmd/... && \
  cp cfssl /usr/local/bin && \
  cp multirootca /usr/local/bin

WORKDIR /opt
