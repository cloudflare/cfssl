echo '{ "CN": "Pathlen 0 Issuer", "ca": { "pathlen": 0, "pathlenzero": true } }' | cfssl genkey -initca - | cfssljson -bare pathlen_0
echo '{ "CN": "Pathlen 1 Issuer", "ca": { "pathlen": 1 } }' | cfssl genkey -initca - | cfssljson -bare pathlen_1
echo '{ "CN": "Pathlen Unspecified" }' | cfssl genkey -initca - | cfssljson -bare pathlen_unspecified
