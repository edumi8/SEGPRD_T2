openssl genrsa -out ca.key 2048
openssl req -new -x509 -nodes -sha256 -days 365 -subj "/C=PT/ST=Porto/L=Paranhos/O=IPP/OU=ISEP/CN=Nuno Bettencourt/emailAddress=nuno@mail.com" -key ca.key -out ca.crt 
openssl genrsa -out server.key 2048 

openssl req -new -subj "/C=PT/ST=Porto/L=Paranhos/O=IPP/OU=ISEP" -key server.key -out server.csr 

openssl x509 -req -CAkey ca.key -CA ca.crt -CAcreateserial -days 365 -sha256 -in server.csr -out server.crt 

openssl genrsa -out erica.key 2048 
r
openssl req -new -subj "/C=PT/ST=Vila Real/L=Chaves/CN=Erica Lopes/emailAddress=erica@mail.com" -key erica.key -out erica.csr 

openssl x509 -req -CAkey ca.key -CA ca.crt -CAcreateserial -days 365 -sha256 -in erica.csr -out erica.crt 

openssl pkcs12 -export -inkey erica.key -in erica.crt -out erica.p12 

openssl x509 -in erica.crt -text -noout