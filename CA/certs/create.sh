#!/bin/bash

ROOT_CA_KEY=root_ca.key
ROOT_CA_CERT=root_ca.crt
ROOT_CA_CRL=root_ca.crl
ROOT_CA_CONF=root_ca.conf
ROOT_CA_SUBJECT="/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=Root CA"
ROOT_CA_VALID_DAYS=3650
CRL_DAYS=365

openssl genrsa -out $ROOT_CA_KEY 4096

openssl req -new -key $ROOT_CA_KEY -out root_ca.csr -subj "$ROOT_CA_SUBJECT"

openssl req -x509 -days $ROOT_CA_VALID_DAYS -key $ROOT_CA_KEY -in root_ca.csr -out $ROOT_CA_CERT

# Configuração do arquivo de configuração da CA raiz
cat << EOF > $ROOT_CA_CONF
[ca]
default_ca = root_ca

[root_ca]
dir = .
certificate = $ROOT_CA_CERT
database = \$dir/index.txt
private_key = $ROOT_CA_KEY
new_certs_dir = \$dir/certs
serial = \$dir/serial
crl = $ROOT_CA_CRL
crlnumber = \$dir/crlnumber
default_days = $CRL_DAYS
default_crl_days = $CRL_DAYS
default_md = sha256
policy = root_ca_policy

[root_ca_policy]
commonName = Seguranca 
stateOrProvinceName = Porto
countryName = Portugal
emailAddress = seguranca@sec.pt
organizationName = 
organizationalUnitName = Security

[usr_cert]
basicConstraints=CA:FALSE
nsCertType = client, email
EOF

mkdir certs
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber
# Gerar CRL 
openssl ca -gencrl -config $ROOT_CA_CONF -out $ROOT_CA_CRL


