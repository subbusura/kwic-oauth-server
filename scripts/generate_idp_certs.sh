#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-secrets}"
mkdir -p "$OUT_DIR"

echo "Generating IdP signing key/cert in $OUT_DIR ..."
openssl req -x509 -newkey rsa:2048 -keyout "$OUT_DIR/idp_private.pem" -out "$OUT_DIR/idp_cert.pem" -days 365 -nodes -subj "/CN=IdP"

echo "Done."
echo "Private key: $OUT_DIR/idp_private.pem"
echo "Certificate: $OUT_DIR/idp_cert.pem"
