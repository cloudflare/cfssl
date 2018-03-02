FROM golang:1.9.2

ENV USER root

WORKDIR /go/src/github.com/cloudflare/cfssl
COPY . .

# restore all deps and build
RUN go get github.com/cloudflare/cfssl_trust/... && \
    go get github.com/GeertJohan/go.rice/rice && \
    rice embed-go -i=./cli/serve && \
    cp -R /go/src/github.com/cloudflare/cfssl_trust /etc/cfssl && \
    go install ./cmd/...

EXPOSE 8888

ENTRYPOINT ["cfssl"]
CMD ["--help"]
