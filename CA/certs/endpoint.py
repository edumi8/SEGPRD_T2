from flask import Flask, request, send_file, jsonify
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import os
import json
import Autoridade_Certificadora
import tempfile
import argparse

app = Flask(__name__)

@app.route('/generate/<data>')
def test(data):
    data = data.split('_')
    print(data)
    data[1] = int(data[1])
    cert = certs.emitir_certificado(data[0],data[1],data[2],data[3],data[4])
    
    print(cert.serial_number)
    
    subject = cert.subject
    subject_values = {attr.oid._name: attr.value for attr in subject}

    # Get the certificate itself
    certificate = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Prepare JSON response
    response = {
        "key" : certs.chave_privada_certificado,
        "subject_values": subject_values,
        "certificate": certificate,
        "serial": ":".join("{:02x}".format(byte) for byte in cert.serial_number.to_bytes(20, 'big'))
    }

    return jsonify(response)

def main(ca_key, ca_cert, crl_file, certs_dir):
    # Your main code here
    print("CA Key:", ca_key)
    print("CA Cert:", ca_cert)
    print("CRL File:", crl_file)
    print("Certificates Directory:", certs_dir)
    
if __name__ == '__main__':
        # Create argument parser
    parser = argparse.ArgumentParser(description="Description of your program")

    # Add arguments
    parser.add_argument("ca_key", type=str, help="Path to CA key file")
    parser.add_argument("ca_cert", type=str, help="Path to CA certificate file")
    parser.add_argument("crl_file", type=str, help="Path to CRL file")
    parser.add_argument("certs_dir", type=str, help="Path to certificates directory")

    # Parse arguments
    args = parser.parse_args()

    # Call main function with provided arguments debug call
    main(args.ca_key, args.ca_cert, args.crl_file, args.certs_dir)

    certs = Autoridade_Certificadora.autoridade_certificacao(args.ca_key, args.ca_cert,args.crl_file,args.certs_dir)
    app.run(debug=False, host='0.0.0.0')
