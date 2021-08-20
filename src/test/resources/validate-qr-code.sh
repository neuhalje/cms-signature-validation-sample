#!/usr/bin/env bash

source config.inc
cd "$basedir/$1"


openssl cms \
-verify \
-certfile "$certfile" \
-CAfile "$certfile" \
-binary \
-content "$data" \
-inform pem \
-in "$signature" 2>&1
