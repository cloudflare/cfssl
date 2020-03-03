FROM golang:1.14.0

WORKDIR /workdir
COPY . /workdir

RUN git clone https://github.com/cloudflare/cfssl_trust.git /etc/cfssl && \
    make clean && \
    make bin/rice && ./bin/rice embed-go -i=./cli/serve && \
    make all && cp bin/* /usr/bin/

EXPOSE 8888

ENTRYPOINT ["cfssl"]
CMD ["--help"]
