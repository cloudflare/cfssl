1. To generate 5min-rsa.pem and 5min-rsa-key.pem
```
$ cfssl gencert -initca ca_csr_rsa.json | cfssljson -bare 5min-rsa
```
2. To generate 5min-ecdsa.pem and 5min-ecdsa-key.pem
```
$ cfssl gencert -initca ca_csr_ecdsa.json | cfssljson -bare 5min-ecdsa
```

The above commands will generate 5min-rsa.csr and 5min-ecdsa.csr as well, but those
files can be ignored.
