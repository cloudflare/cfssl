FROM golang:1.20

ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN echo "I am running on $BUILDPLATFORM, building for $TARGETPLATFORM" 

LABEL org.opencontainers.image.source https://github.com/cloudflare/cfssl
LABEL org.opencontainers.image.description "Cloudflare's PKI toolkit"

ARG TARGETOS
ARG TARGETARCH

WORKDIR /workdir
COPY . /workdir

RUN git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl && \
    make clean && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} make all && cp bin/* /usr/bin/

EXPOSE 8888

ENTRYPOINT ["cfssl"]
CMD ["serve"]
