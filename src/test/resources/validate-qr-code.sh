#!/usr/bin/env bash

source config.inc
cd "$basedir"

openssl cms \
-verify \
-certfile "$certfile" \
-CAfile "$certfile" \
-inkey "$keyfile" \
-binary \
-content "$data" \
-inform pem \
-in "$signature" 2>&1
