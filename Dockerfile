FROM golang:1.4.3

ENV USER root

EXPOSE 8888

# Install pkcs11 deps
RUN apt-get update && apt-get install -y \
	libltdl-dev \
	--no-install-recommends \
	&& rm -rf /var/lib/apt/lists/*

COPY . /go/src/github.com/cloudflare/cfssl

# install all deps and build
RUN cd /go/src/github.com/cloudflare/cfssl && \
	go get -d ./... && \
	(cd cmd/cfssl && go build -o /usr/bin/cfssl . ) && \
	(cd cmd/cfssljson && go build -o /usr/bin/cfssljson . ) && \
	(cd cmd/mkbundle && go build -o /usr/bin/mkbundle . ) && \
	(cd cmd/multirootca && go build -o /usr/bin/multirootca . )

WORKDIR /opt

ENTRYPOINT ["cfssl"]
CMD ["--help"]
