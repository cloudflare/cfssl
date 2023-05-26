1. To generate 5min-rsa.pem and 5min-rsa-key.pem

```
$ cfssl gencert -initca ca_csr_rsa.json | cfssljson -bare 5min-rsa
```

2. To generate 5min-ecdsa.pem and 5min-ecdsa-key.pem

```
$ cfssl gencert -initca ca_csr_ecdsa.json | cfssljson -bare 5min-ecdsa
```

2. To generate 5min-ed25519.pem and 5min-ed25519-key.pem

```
$ cfssl gencert -initca ca_csr_ed25519.json | cfssljson -bare 5min-ed25519
```

The above commands will generate 5min-rsa.csr, 5min-ecdsa.csr 5min-ed25519.csr
accordingly, but those files can be ignored.
