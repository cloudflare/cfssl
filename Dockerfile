FROM --platform=${BUILDPLATFORM} golang:1.19.3

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workdir
COPY . /workdir

RUN git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl && \
    make clean && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} make all && cp bin/* /usr/bin/

EXPOSE 8888

ENTRYPOINT ["cfssl"]
CMD ["--help"]
