# servidor.py
import socket
import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# NOVAS IMPORTAÇÕES PARA CRYPTOGRAPHY E PBKDF2
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Importações para ECDSA
from ecdsa_utils import assinar, verificar, carregar_chave_privada, carregar_chave_publica

# Configuração da Rede
HOST = '0.0.0.0'
PORT = 5000
USERNAME = b'servidor'

# Parâmetros PBKDF2 (devem ser consistentes entre cliente e servidor)
salt = b'um_salt_seguro_e_aleatorio_para_as_chaves_derivadas'
iterations = 100000

# --- Carregar Chaves ECDSA do Servidor ---
try:
    sk_servidor = carregar_chave_privada("keys/server_private.pem")
    vk_servidor_publica = carregar_chave_publica("keys/server_public.pem") # Para referência/depuração
    # Carregar a chave pública do cliente para verificar suas assinaturas
    vk_cliente_para_verificar = carregar_chave_publica("keys/client_public.pem")
except FileNotFoundError:
    print("ERRO: Arquivos de chave ECDSA não encontrados.")
    print("Por favor, execute 'python gerar_chaves.py' primeiro para criar as chaves.")
    exit()

# --- Configuração dos Parâmetros Diffie-Hellman ---
# Gerar parâmetros DH (g e p) para a sessão.
# Usamos generator=2 e um tamanho de chave de 2048 bits.
parameters = dh.generate_parameters(generator=2, key_size=2048)
parameter_bytes = parameters.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)

# Criar socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(1)
print('[+] Servidor aguardando conexão...')

conn, addr = sock.accept()
print(f'[+] Conexão recebida de {addr}')

# --- Handshake Diffie-Hellman e Verificação ECDSA ---
# PASSO 1: Servidor envia seus parâmetros DH (g, p)
conn.sendall(parameter_bytes)
print('[+] Parâmetros DH enviados ao cliente.')

# PASSO 2: Receber a chave pública DH do cliente (A_public_bytes) e sua assinatura
data = conn.recv(4096)
if not data:
    print("[-] Cliente desconectou inesperadamente durante o handshake.")
    conn.close()
    exit()

try:
    A_public_bytes, assinatura_cliente, user_cliente = data.split(b'||')
    # Deserializar a chave pública do cliente
    A_public_key = serialization.load_pem_public_key(A_public_bytes)
except (ValueError, TypeError) as e:
    print(f"[-] Formato de handshake inválido recebido do cliente: {e}")
    conn.close()
    exit()

print(f'[+] Recebido Chave Pública DH do Cliente.')
print(f'[+] Cliente: {user_cliente.decode()}')

# A mensagem que o cliente assinou é a sua chave pública DH em bytes + seu username
mensagem_verificar_cliente = A_public_bytes + user_cliente

# Verificar assinatura do cliente
if not verificar(mensagem_verificar_cliente, assinatura_cliente, vk_cliente_para_verificar):
    print('[-] Assinatura do cliente inválida. Encerrando.')
    conn.close()
    exit()
print('[+] Assinatura do cliente válida.')

# --- Geração e Envio da Chave Pública DH do Servidor ---
# Gerar chave privada do servidor com base nos parâmetros
server_private_key = parameters.generate_private_key()
server_public_key = server_private_key.public_key()

# Serializar a chave pública do servidor para enviar
B_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Mensagem a ser assinada pelo servidor: sua chave pública DH em bytes + seu username
mensagem_assinar_servidor = B_public_bytes + USERNAME
assinatura_servidor = assinar(mensagem_assinar_servidor, sk_servidor)

# Enviar a chave pública DH do servidor e sua assinatura
conn.sendall(B_public_bytes + b'||' + assinatura_servidor + b'||' + USERNAME)
print(f'[+] Enviado Chave Pública DH do Servidor (B).')

# --- Cálculo da Chave Secreta Compartilhada DH ---
# A chave compartilhada é o resultado do DH exchange
shared_key = server_private_key.exchange(A_public_key)
print(f'[+] Chave secreta compartilhada S gerada.')

# --- Derivação de Chaves AES e HMAC ---
# Usando o mesmo salt e iterations para garantir que cliente e servidor derivem as mesmas chaves
# O shared_key já é bytes, então não precisa de str().encode()
kdf_aes = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=iterations,
)
Key_AES = kdf_aes.derive(shared_key)

kdf_hmac = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=iterations,
)
Key_HMAC = kdf_hmac.derive(shared_key)

print('[+] Chaves AES e HMAC derivadas.')

# --- Receber e Descriptografar Mensagem Criptografada ---
pacote_completo = conn.recv(4096)
if not pacote_completo:
    print("[-] Cliente desconectou inesperadamente ao enviar mensagem criptografada.")
    conn.close()
    exit()

hmac_tag = pacote_completo[:32]
iv = pacote_completo[32:48]
criptografada = pacote_completo[48:]

# Verificar HMAC
hmac_calculado = hmac.new(Key_HMAC, iv + criptografada, hashlib.sha256).digest()
if not hmac.compare_digest(hmac_tag, hmac_calculado):
    print('[-] HMAC inválido. Mensagem comprometida ou alterada.')
    conn.close()
    exit()
print('[+] HMAC verificado.')

# Descriptografar AES
cipher = Cipher(algorithms.AES(Key_AES), modes.CBC(iv))
decryptor = cipher.decryptor()
mensagem_descriptografada_com_padding = decryptor.update(criptografada) + decryptor.finalize()

# No servidor.py, na seção de remoção de padding
try:
    pad = mensagem_descriptografada_com_padding[-1]
    if pad < 1 or pad > 16:
        raise ValueError("Padding inválido: Tamanho do padding fora do intervalo válido.")
    if mensagem_descriptografada_com_padding[-pad:] != bytes([pad]) * pad: 
        raise ValueError("Padding inválido: Bytes de padding inconsistentes.")
    mensagem_final = mensagem_descriptografada_com_padding[:-pad]
except ValueError as e:
    print(f"[-] Erro ao remover padding: {e}. Possível falha na descriptografia ou alteração da mensagem.")
    conn.close()
    exit()

print('[+] Mensagem recebida:', mensagem_final.decode())

conn.close()
sock.close()
print('[+] Conexão encerrada.')