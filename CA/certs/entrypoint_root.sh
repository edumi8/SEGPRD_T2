#!/bin/bash

echo "Environment is: $ENVIRONMENT"

openssl ecparam -genkey -name prime256v1 -out root_ca/ca_root_ca.key
openssl req -new -key root_ca/ca_root_ca.key -out root_ca/ca_root_ca.csr -subj "/C=PT/ST=Porto/L=Porto/O=isep.ipp.pt/OU=SEGPRD/CN=root_ca/emailAddress=root_ca@org.org"
openssl x509 -req -days 365 -extensions v3_ca -signkey root_ca/ca_root_ca.key -in root_ca/ca_root_ca.csr -out root_ca/ca_root_ca.crt
