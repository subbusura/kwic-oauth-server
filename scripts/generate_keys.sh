#!/usr/bin/env bash
openssl genrsa -out secrets/jwks_private.pem 2048
openssl rsa -in secrets/jwks_private.pem -pubout -out secrets/jwks_public.pem
echo "Keys written to secrets/"
