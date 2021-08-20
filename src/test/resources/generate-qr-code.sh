#!/usr/bin/env bash

source config.inc
cd "$basedir/$1"



raw="PLAP01Demo2021-03-08T19:54:51Z|23413804-e180-45b3-a077-3ce73045d7c3|U|demo_ast_id|021234"

echo -n $raw > "$data"

openssl cms -sign -signer "$certfile" \
-inkey "$keyfile" \
-binary \
-md sha256 \
-in "$data" \
\
-outform pem \
-out "$signature" \
-nocerts \
-noattr
echo "Signed data:"
cat "$data"
echo
echo "Signature size: " $(stat -c%s "$signature") " bytes"
echo "Signature:"
cat "${signature}"
oneline_sig=$(sed -e '/^----/d' "$signature" |tr -d '\n')
printf "\n\n-----------------------------------\nQR Code:\n%s|%s\n" "$raw" "$oneline_sig"
printf "%s|%s" "$raw" "$oneline_sig" > "$finalqrcode"