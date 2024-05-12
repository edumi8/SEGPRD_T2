import os
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_crl
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta



class autoridade_certificacao:
    # Carrega a chave, certificado e crl da CA, alem do diretorio para os certificados emitidos
    def __init__(self, ca_chave, ca_cert, crl_file, diretorio_certificados_emitidos):
        with open(ca_chave, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(ca_cert, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        self.crl_file = crl_file
        self.diretorio_certificados_emitidos = diretorio_certificados_emitidos
        self.crl = self.carrega_crl()

    def criar_crl(self, ficheiro_destino):
        crl_file = (x509.CertificateRevocationListBuilder().issuer_name(self.ca_cert.subject).
                    last_update(datetime.utcnow()).next_update(datetime.utcnow() + timedelta(days=30)))
        crl_file = crl_file.sign(self.ca_key, hashes.SHA512(), default_backend())
        if not os.path.exists(ficheiro_destino):
            os.makedirs(ficheiro_destino)
        crl_caminho = os.path.join(ficheiro_destino, "crl.pem")
        with open(crl_caminho, "wb") as crl_arquivo:
            crl_arquivo.write(crl_file.public_bytes(serialization.Encoding.PEM))

    # Carrega a CRL
    def carrega_crl(self):
        with open(self.crl_file, "rb") as f:
            crl_list = f.read()
        return load_pem_x509_crl(crl_list, default_backend())

    # Salva a CRL
    def salva_crl(self, crl):
        with open(self.crl_file, "wb") as f:
            f.write(crl.public_bytes(encoding=serialization.Encoding.PEM))

    def relatorio_validade_certificados(self):
        certificados_info = []
        for arquivo in os.listdir(self.diretorio_certificados_emitidos):
            if arquivo.endswith(".pem"):
                caminho_arquivo = os.path.join(self.diretorio_certificados_emitidos, arquivo)
                with open(caminho_arquivo, "rb") as f:
                    certificado_bytes = f.read()
                    certificado = x509.load_pem_x509_certificate(certificado_bytes, default_backend())
                data_validade = certificado.not_valid_after.strftime("%d/%m/%Y")
                nome = certificado.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                serial = certificado.serial_number.to_bytes((certificado.serial_number.bit_length() + 7) // 8,
                                                            'big').hex(':')
                certificado_info = f"Sujeito: {nome}, Data de Validade: {data_validade}, Serial: {serial}\n"
                certificados_info.append(certificado_info)
        #certificados_info = sorted(certificados_info,key=lambda x: datetime.strptime(x.split(", Data de Validade: ")[1].split(",")[0],
        return "".join(certificados_info)

    # retorna uma lista com os certificados que venceram
    def certificados_a_vencer_e_vencidos(self):
        serials_a_vencer = []
        hoje = datetime.now().date()
        for arquivo in os.listdir(self.diretorio_certificados_emitidos):
            if arquivo.endswith(".pem"):
                caminho_arquivo = os.path.join(self.diretorio_certificados_emitidos, arquivo)
                with open(caminho_arquivo, "rb") as file:
                    certificado = x509.load_pem_x509_certificate(file.read(), default_backend())
                # ver validade
                data_validade = certificado.not_valid_after.date()
                # Os vencidos e que vencem na data da verificacao
                if data_validade <= hoje:
                    # transforma em hexa:
                    serial = certificado.serial_number.to_bytes((certificado.serial_number.bit_length() + 7) // 8, 'big').hex(':')
                    #serial = certificado.serial_number     #esse esta em inteiro
                    serials_a_vencer.append(serial)
        # numero de serie em hexadecimal
        return serials_a_vencer

    # Deve-se atribuir o numero serial e data de revogacao do certificado
    def revogar_certificado(self, numero_serial, data_revogacao):
        ca_key = self.ca_key
        ca_cert = self.ca_cert
        numero_serial_int = int(numero_serial.replace(":", ""), 16)
        for certificado_revogado in self.crl:
            if certificado_revogado.serial_number == numero_serial_int:
                print("O certificado já está revogado.")
                return
        certificado_revogado = x509.RevokedCertificateBuilder().serial_number(numero_serial_int).revocation_date(
            data_revogacao).build(default_backend())
        list_certificados_revogados = list(self.crl)
        list_certificados_revogados.append(certificado_revogado)
        gerador_nova_lista = x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject).last_update(
            datetime.utcnow()).next_update(datetime.utcnow() + timedelta(days=7))
        for cert in list_certificados_revogados:
            gerador_nova_lista = gerador_nova_lista.add_revoked_certificate(cert)
        crl = gerador_nova_lista.sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())
        self.salva_crl(crl)

    # Deve-se atribuir o numero serial
    def verificar_revocacao(self, numero_serial):
        numero_serial_int = int(numero_serial.replace(":", ""), 16)
        for revoked_cert in self.crl:
            if revoked_cert.serial_number == numero_serial_int:
                return True, print("O certificado está revogado.")
        return False

    def recuperar_certificado_revogado(self, serial_number, validade):
        for filename in os.listdir(self.diretorio_certificados_emitidos):
            with open(os.path.join(self.diretorio_certificados_emitidos, filename), "rb") as f:
                cert = load_pem_x509_certificate(f.read(), default_backend())
                formatted_serial = ":".join("{:02x}".format(byte) for byte in cert.serial_number.to_bytes(20, 'big'))
                if formatted_serial == serial_number:
                    for informacoes in cert.subject:
                        if informacoes.oid == x509.NameOID.COMMON_NAME:
                            nome = informacoes.value
                        elif informacoes.oid == x509.NameOID.USER_ID:
                            user_id = informacoes.value
                        elif informacoes.oid == x509.NameOID.EMAIL_ADDRESS:
                            email = informacoes.value
        self.emitir_certificado(nome, validade, user_id, email)

    def emitir_certificado(self, nome_cert, validade_dias, user_id, email, departamento):
        private_key = self.gerar_private_key()
        #print("Chave privada gerada:")
        self.chave_privada_certificado = private_key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()).decode()
        #A saida da chave privada pode ser uma arquivo txt
        print(chave_privada_certificado)
        solicitacao_certificado, builder = self.gerar_requisicao_certificado(private_key, nome_cert, user_id, email, departamento)
        return self.assinar_certificado(solicitacao_certificado, validade_dias)

    # Foi usado curvas elipticas
    def gerar_private_key(self):
        print("sdfhskjfhdj ")
        p_key = ec.generate_private_key(ec.BrainpoolP512R1(), default_backend())
        return p_key

    def gerar_requisicao_certificado(self, ca_key, nome, user_id, email, departamento):
        sujeito_certificado = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nome),
                                         x509.NameAttribute(NameOID.USER_ID, user_id), x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
                                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, departamento)])
        builder = x509.CertificateSigningRequestBuilder().subject_name(sujeito_certificado)
        return builder.sign(ca_key, hashes.SHA512(), default_backend()), builder

    def assinar_certificado(self, solicitacao_certificado, validade_dias):
        emissor = self.ca_cert.subject
        sujeito = solicitacao_certificado.subject
        builder = (x509.CertificateBuilder().subject_name(sujeito).issuer_name(emissor).public_key(solicitacao_certificado.public_key()).
                   serial_number(x509.random_serial_number()).not_valid_before(datetime.utcnow()).
                   not_valid_after(datetime.utcnow() + timedelta(days=validade_dias)))
        certificado = builder.sign(private_key=self.ca_key,algorithm=hashes.SHA512(),backend=default_backend())
        self.salvar_certificado(certificado)
        return certificado

    def salvar_certificado(self, certificado, nome_arquivo=None):
        serial_number = certificado.serial_number
        os.makedirs(self.diretorio_certificados_emitidos, exist_ok=True)
        if not nome_arquivo:
            nome_arquivo = f"certificate_{serial_number}.pem"
        with open(os.path.join(self.diretorio_certificados_emitidos, nome_arquivo), "wb") as f:
            f.write(certificado.public_bytes(encoding=serialization.Encoding.PEM))


    def extrair_chave_publica(self, serial_number):
        for filename in os.listdir(self.diretorio_certificados_emitidos):
            with open(os.path.join(self.diretorio_certificados_emitidos, filename), "rb") as f:
                cert = load_pem_x509_certificate(f.read(), default_backend())
                formatted_serial = ":".join("{:02x}".format(byte) for byte in cert.serial_number.to_bytes(20, 'big'))
                if formatted_serial == serial_number:
                    chave_public = cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization
                                                                  .PublicFormat.SubjectPublicKeyInfo)
        return chave_public.decode()

    # Busca certificado pelo número de série
    def encontrar_certificado_serial(self, serial_number):
        for filename in os.listdir(self.diretorio_certificados_emitidos):
            with open(os.path.join(self.diretorio_certificados_emitidos, filename), "rb") as f:
                cert = load_pem_x509_certificate(f.read(), default_backend())
                formatted_serial = ":".join("{:02x}".format(byte) for byte in cert.serial_number.to_bytes(20, 'big'))
                if formatted_serial == serial_number:
                    for informacoes in cert.subject:
                        if informacoes.oid == x509.NameOID.COMMON_NAME:
                            nome = informacoes.value
                        elif informacoes.oid == x509.NameOID.USER_ID:
                            user_id = informacoes.value
                        elif informacoes.oid == x509.NameOID.EMAIL_ADDRESS:
                            email = informacoes.value
                    print("Certificado encontrado!")
                    print("Informações do certificado:")
                    print("Proprietário:", nome)
                    print("ID:", user_id)
                    print("E-mail:", email)
                    for info_emissor in cert.issuer:
                        if info_emissor.oid == x509.NameOID.COMMON_NAME:
                            nome_emissor = info_emissor.value
                            break
                    print("Emissor: ", nome_emissor)
                    print("Validade - De:", cert.not_valid_before_utc, ", Até:", cert.not_valid_after_utc)
                    print("Local:", cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value)
                    self.verificar_revocacao(formatted_serial)
                    return cert
        print("Certificado não encontrado.")
        return None

