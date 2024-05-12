from datetime import datetime
from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_crl
from cryptography.hazmat.backends import default_backend
from Autoridade_Certificadora import autoridade_certificacao

ca = autoridade_certificacao("/home/junior/CAs/client_ca/private/client_ca.key",
                                        "/home/junior/CAs/client_ca/certs/client_ca_crt",
                             "/home/junior/CAs/client_ca/crl/crl.pem", "/home/junior/CAs/client_ca/certificados_emitidos")

#ca.emitir_certificado("Teste", 0, "33333", "teste02@teste.com")
#ca.revogar_certificado("47:09:10:bd:3d:4f:2c:cd:d1:e1:37:6f:11:8e:60:3f:ea:28:77:a6", datetime.now())
#ca.verificar_revocacao("47:09:10:bd:3d:4f:2c:cd:d1:e1:37:6f:11:8e:60:3f:ea:28:77:a6")
#ca.extrair_chave_publica("39:80:b5:e9:1a:92:1a:cd:54:c1:89:c4:f9:89:d5:a2:06:1b:2b:bb")
#ca.encontrar_certificado_serial("39:80:b5:e9:1a:92:1a:cd:54:c1:89:c4:f9:89:d5:a2:06:1b:2b:bb")
#ca.revogacao_automatica() SEM USO
#print(ca.certificados_a_vencer_e_vencidos())
#print(ca.relatorio_validade_certificados())










