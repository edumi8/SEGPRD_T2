#!/bin/bash
echo "Environment is: $ENVIRONMENT"

openssl ecparam -genkey -name prime256v1 -out ca_root.key
openssl req -new -key ca_root.key -out ca_root.csr
openssl x509 -req -days 365 -extensions v3_ca -signkey ca_root.key -in ca_root.csr -out ca_root.crt
