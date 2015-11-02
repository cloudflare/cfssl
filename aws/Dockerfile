FROM golang:1.5

ENV USER root

ENV CFSSL_CMD github.com/cloudflare/cfssl/cmd/cfssl

RUN	go get -d $CFSSL_CMD && \
	(go get github.com/GeertJohan/go.rice/rice && go install github.com/GeertJohan/go.rice/rice ) && \
	(cd /go/src/github.com/cloudflare/cfssl/cli/serve && rice embed-go ) && \
	(go build -tags nopkcs11 -o /usr/bin/cfssl $CFSSL_CMD ) && \
	git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl

EXPOSE 80
ENTRYPOINT ["cfssl"]
CMD ["serve", "-address=0.0.0.0", "-port=80"]
