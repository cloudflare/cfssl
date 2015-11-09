FROM golang:1.5

ENV USER root

# Install pkcs11 deps
RUN apt-get update && apt-get install -y \
	libltdl-dev \
	--no-install-recommends \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /go/src/github.com/cloudflare/cfssl
COPY . .

# restore all deps and build
RUN go get github.com/tools/godep && godep restore && \
	go get github.com/GeertJohan/go.rice/rice && rice embed-go -i=./cli/serve && \
	git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl && \
	go install ./cmd/...

EXPOSE 8888

ENTRYPOINT ["cfssl"]
CMD ["--help"]
