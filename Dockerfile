FROM --platform=${BUILDPLATFORM} golang:1.19.3@sha256:d388153691a825844ebb3586dd04d1c60a2215522cc445701424205dffc8a83e

ARG TARGETOS TARGETARCH

WORKDIR /workdir
COPY . /workdir

RUN git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl && \
    make clean && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} make all && cp bin/* /usr/bin/

EXPOSE 8888

ENTRYPOINT ["cfssl"]
CMD ["--help"]
