# CFSSL

[![Build Status](https://travis-ci.org/cloudflare/cfssl.png?branch=master)](https://travis-ci.org/cloudflare/cfssl)
[![Coverage Status](https://coveralls.io/repos/cloudflare/cfssl/badge.svg?branch=master)](https://coveralls.io/r/cloudflare/cfssl?branch=master)
[![GoDoc](https://godoc.org/github.com/cloudflare/cfssl?status.png)](https://godoc.org/github.com/cloudflare/cfssl)
## CloudFlare's PKI/TLS toolkit

CFSSL is CloudFlare's PKI/TLS swiss army knife. It is both a command line
tool and an HTTP API server for signing, verifying, and bundling TLS
certificates. It requires Go 1.4 to build.

Note that certain linux distributions have certain algorithms removed
(RHEL-based distributions in particular), so the golang from the
official repositories will not work. Users of these distributions should
[install go manually](//golang.org) to install CFSSL.

### Installation

Installation requires a [working Go
installation](http://golang.org/doc/install) and a properly set `GOPATH`.

```
$ go get -u github.com/cloudflare/cfssl/cmd/cfssl
```

will download and build the CFSSL tool, installing it in
`$GOPATH/bin/cfssl`. To install the other utility programs that are in
this repo:

```
$ go get -u github.com/cloudflare/cfssl/cmd/...
```

This will download, build, and install `cfssl`, `cfssljson`, and
`mkbundle` into `$GOPATH/bin/`.


### Using the Command Line Tool

The command line tool takes a command to specify what operation it
should carry out:

       sign             signs a certificate
       bundle           build a certificate bundle
       genkey           generate a private key and a certificate request
       gencert          generate a private key and a certificate
       serve            start the API server
       version          prints out the current version
       selfsign         generates a self-signed certificate

Use "cfssl [command] -help" to find out more about a command.
The version command takes no arguments.

#### Signing

```
cfssl sign [-ca cert] [-ca-key key] [-hostname comma,separated,hostnames] csr [subject]
```

The csr is the client's certificate request. The `-ca` and `-ca-key`
flags are the CA's certificate and private key, respectively. By
default, they are "ca.pem" and "ca_key.pem". The `-hostname` is
a comma separated hostname list that overrides the DNS names and
IP address in the certificate SAN extension.
For example, assuming the CA's private key is in
`/etc/ssl/private/cfssl_key.pem` and the CA's certificate is in
`/etc/ssl/certs/cfssl.pem`, to sign the `cloudflare.pem` certificate
for cloudflare.com:

```
cfssl sign -ca /etc/ssl/certs/cfssl.pem \
           -ca-key /etc/ssl/private/cfssl_key.pem \
           -hostname cloudflare.com ./cloudflare.pem
```

It is also possible to specify csr through '-csr' flag. By doing so,
flag values take precedence and will overwrite the argument.

The subject is an optional file that contains subject information that
should be used in place of the information from the CSR. It should be
a JSON file with the type:

```
{
    "CN": "example.com",
    "names": [
        {
            "C": "US",
            "L": "San Francisco",
            "O": "Internet Widgets, Inc.",
            "OU": "WWW",
            "ST": "California"
        }
    ]
}
```

#### Bundling

```
cfssl bundle [-ca-bundle bundle] [-int-bundle bundle] \
             [-metadata metadata_file] [-flavor bundle_flavor] \
             -cert certificate_file [-key key_file]
```

The bundles are used for the root and intermediate certificate
pools. In addition, platform metadata is specified through '-metadata'
The bundle files, metadata file (and auxiliary files) can be
found at [cfssl_trust](https://github.com/cloudflare/cfssl_trust)


Specify PEM-encoded client certificate and key through '-cert' and
'-key' respectively. If key is specified, the bundle will be built
and verified with the key. Otherwise the bundle will be built
without a private key. Instead of file path, use '-' for reading
certificate PEM from stdin. It is also acceptable the certificate
file contains a (partial) certificate bundle.

Specify bundling flavor through '-flavor'. There are three flavors:
'optimal' to generate a bundle of shortest chain and most advanced
cryptographic algorithms, 'ubiquitous' to generate a bundle of most
widely acceptance across different browsers and OS platforms, and
'force' to find an acceptable bundle which is identical to the
content of the input certificate file.

Alternatively, the client certificate can be pulled directly from
a domain. It is also possible to connect to the remote address
through '-ip'.

```
cfssl bundle [-ca-bundle bundle] [-int-bundle bundle] \
             [-metadata metadata_file] [-flavor bundle_flavor] \
             -domain domain_name [-ip ip_address]
```

The bundle output form should follow the example

```
{
    "bundle": "CERT_BUNDLE_IN_PEM",
    "crt": "LEAF_CERT_IN_PEM",
    "crl_support": true,
    "expires": "2015-12-31T23:59:59Z",
    "hostnames": ["example.com"],
    "issuer": "ISSUER CERT SUBJECT",
    "key": "KEY_IN_PEM",
    "key_size": 2048,
    "key_type": "2048-bit RSA",
    "ocsp": ["http://ocsp.example-ca.com"],
    "ocsp_support": true,
    "root": "ROOT_CA_CERT_IN_PEM",
    "signature": "SHA1WithRSA",
    "subject": "LEAF CERT SUBJECT",
    "status": {
        "rebundled": false,
        "expiring_SKIs": [],
        "untrusted_root_stores": [],
        "messages": [],
        "code": 0
    }
}
```


#### Generating certificate signing request and private key

```
cfssl genkey csrjson
```

To generate a private key and corresponding certificate request, specify
the key request as a JSON file. This file should follow the form

```
{
    "hosts": [
        "example.com",
        "www.example.com"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "US",
            "L": "San Francisco",
            "O": "Internet Widgets, Inc.",
            "OU": "WWW",
            "ST": "California"
        }
    ]
}
```

#### Generating self-signed root CA certificate and private key

```
cfssl genkey -initca csrjson | cfssljson -bare ca
```

To generate a self-signed root CA certificate, specify the key request as
the JSON file in the same format as in 'genkey'. Three PEM-encoded entities
will appear in the output: the private key, the csr, and the self-signed
certificate.

#### Generating a remote-issued certificate and private key.

```
cfssl gencert -remote=remote_server [-hostname=comma,separated,hostnames] csrjson
```

This is calls genkey, but has a remote CFSSL server sign and issue
a certificate. You may use `-hostname` to override certificate SANs.

#### Generating a local-issued certificate and private key.

```
cfssl gencert -ca cert -ca-key key [-hostname=comma,separated,hostnames] csrjson
```

This is generates and issues a certificate and private key from a local CA
via a JSON request. You may use `-hostname` to override certificate SANs.

### Starting the API Server

CFSSL comes with an HTTP-based API server; the endpoints are
documented in `doc/api.txt`. The server is started with the "serve"
command:

```
cfssl serve [-address address] [-ca cert] [-ca-bundle bundle] \
            [-ca-key key] [-int-bundle bundle] [-port port]   \
            [-remote remote_server]
```

Address and port default to "127.0.0.1:8888". The `-ca` and `-ca-key`
arguments should be the PEM-encoded certificate and private key to use
for signing; by default, they are "ca.pem" and "ca_key.pem". The
`-ca-bundle` and `-int-bundle` should be the certificate bundles used
for the root and intermediate certificate pools, respectively. These
default to "ca-bundle.crt" and "int-bundle." If the "remote" option is
provided, all signature operations will be forwarded to the remote CFSSL.

The amount of logging can be controlled with the `-loglevel` option. This
comes *before* the serve command:

```
cfssl -loglevel 2 serve
```

The levels are:

* 0. DEBUG
* 1. INFO (this is the default level)
* 2. WARNING
* 3. ERROR
* 4. CRITICAL


### The mkbundle Utility

`mkbundle` is used to build the root and intermediate bundles used in
verifying certificates. It can be installed with

```
go get -u github.com/cloudflare/cfssl/cmd/mkbundle
```

It takes a collection of certificates, checks for CRL revocation (OCSP
support is planned for the next release) and expired certificates, and
bundles them into one file. It takes directories of certificates and
certificate files (which may contain multiple certificates). For example,
if the directory `intermediates` contains a number of intermediate
certificates,

```
mkbundle -f int-bundle.crt intermediates
```

will check those certificates and combine valid ones into a single
`int-bundle.crt` file.

The `-f` flag specifies an output name; `-loglevel` specifies the verbosity
of the logging (using the same loglevels above), and `-nw` controls the
number of revocation-checking workers.

### The cfssljson Utility

Most of the output from `cfssl` is in JSON. The `cfssljson` will take
this output and split it out into separate key, certificate, CSR, and
bundle files as appropriate. The tool takes a single flag, `-f`, that
specifies the input file, and an argument that specifies the base name for
the files produced. If the input filename is "-" (which is the default),
`cfssljson` reads from standard input. It maps keys in the JSON file to
filenames in the following way:

* if there is a "cert" (or if not, if there's a "certificate") field, the
  file "basename.pem" will be produced.
* if there is a "key" (or if not, if there's a "private_key") field, the
  file "basename-key.pem" will be produced.
* if there is a "csr" (or if not, if there's a "certificate_request") field,
  the file "basename.csr" will be produced.
* if there is a "bundle" field, the file "basename-bundle.pem" will
  be producd.

### Additional Documentation

Additional documentation can be found in the "doc/" directory:

* `api.txt`: documents the API endpoints
* `bootstrap.txt`: a walkthrough from building the package to getting
  up and running
