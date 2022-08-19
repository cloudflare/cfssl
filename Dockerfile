FROM golang:1.16.15@sha256:35fa3cfd4ec01a520f6986535d8f70a5eeef2d40fb8019ff626da24989bdd4f1

WORKDIR /workdir
COPY . /workdir

RUN git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl && \
    make clean && \
    make all && cp bin/* /usr/bin/

EXPOSE 8888

ENTRYPOINT ["cfssl"]
CMD ["--help"]
