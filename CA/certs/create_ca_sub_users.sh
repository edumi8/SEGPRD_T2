#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo " $0 <caminho_da_chave_privada_da_ca_raiz> <caminho_do_certificado_da_ca_raiz>"
    exit 1
fi

ROOT_CA_KEY="$1"
ROOT_CA_CERT="$2"

SUB_CA_KEY=sub_ca_users.key
SUB_CA_CSR=sub_ca_users.csr
SUB_CA_CERT=sub_ca_users.crt
SUB_CA_CONF=sub_ca_users.conf
SUB_CA_CRL=sub_ca_users.crl
SUB_CA_SUBJECT="/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=Subordinate CA"
SUB_CA_VALID_DAYS=365
CRL_DAYS=30

openssl genrsa -out $SUB_CA_KEY 2048

openssl req -new -key $SUB_CA_KEY -out $SUB_CA_CSR -subj "$SUB_CA_SUBJECT"

openssl x509 -req -days $SUB_CA_VALID_DAYS -in $SUB_CA_CSR -CA $ROOT_CA_CERT -CAkey $ROOT_CA_KEY \
    -CAcreateserial -out $SUB_CA_CERT

cat <<EOF >$SUB_CA_CONF
[ca]
default_ca = sub_ca

[sub_ca]
dir = .
certificate = $SUB_CA_CERT
database = \$dir/index.txt
private_key = $SUB_CA_KEY
new_certs_dir = \$dir/certs
serial = \$dir/serial
crl = $SUB_CA_CRL
crlnumber = \$dir/crlnumber
default_days = $CRL_DAYS
default_crl_days = $CRL_DAYS
default_md = sha256
policy = sub_ca_policy

[sub_ca_policy]
commonName = User_Server 
stateOrProvinceName = Porto
countryName = Portugal
emailAddress = user@server.pt
organizationName = 
organizationalUnitName = Security

[usr_cert]
basicConstraints=CA:FALSE
nsCertType = client, email
EOF

mkdir -p certs
touch index.txt
echo 1000 >serial
echo 1000 >crlnumber

openssl ca -gencrl -config $SUB_CA_CONF -out $SUB_CA_CRL
