#!/usr/bin/env bash

source config.inc
cd "$basedir/$1"

cat <<-EOF > openssl.cnf
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
C = DE
ST = NRW
L = Bonn
OU = "Demo Post"
OU = PLAPP
CN = qr-code-signer
[v3_req]
keyUsage = digitalSignature, nonRepudiation
EOF

openssl genpkey -algorithm rsa \
-pkeyopt rsa_keygen_bits:3072 \
-out "$keyfile" 2>&1

openssl req -new \
-out "$certfile".csr \
-key "$keyfile" \
-config openssl.cnf 2>&1

# The next step self signs the certificate -- in real life a CA would do that
openssl x509 -req \
-days 365 \
-in "$certfile".csr \
-signkey "$keyfile" \
-out "$certfile"