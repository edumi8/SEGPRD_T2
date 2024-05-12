from flask import Flask, request, send_file, jsonify
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import os
import json
import Autoridade_Certificadora
import tempfile

app = Flask(__name__)
certs = Autoridade_Certificadora.autoridade_certificacao("ca_root.key","ca_root.crt","crl.pem","./certs")

@app.route('/generate/<data>')
def test(data):
    data = data.split('_')
    print(data)
    data[1] = int(data[1])
    cert = certs.emitir_certificado(data[0],data[1],data[2],data[3])
    
    subject = cert.subject
    subject_values = {attr.oid._name: attr.value for attr in subject}

    # Get the certificate itself
    certificate = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Prepare JSON response
    response = {
        "key" : certs.chave_privada_certificado,
        "subject_values": subject_values,
        "certificate": certificate,
    }

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
