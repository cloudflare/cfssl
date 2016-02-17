FROM golang:1.5

ENV USER root

WORKDIR /go/src/github.com/cloudflare/cfssl

RUN git clone https://github.com/cloudflare/cfssl.git /go/src/github.com/cloudflare/cfssl && \
	go get github.com/tools/godep && godep restore && \
	go get github.com/GeertJohan/go.rice/rice && rice embed-go -i=./cli/serve && \
	git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl && \
	go install github.com/cloudflare/cfssl/cmd/cfssl

EXPOSE 80

ENTRYPOINT ["cfssl", "serve"]
CMD ["-address=0.0.0.0", "-port=80", "-ca-bundle=/etc/cfssl/ca-bundle.crt", "-int-bundle=/etc/cfssl/int-bundle.crt", "-metadata=/etc/cfssl/ca-bundle.crt.metadata"]
