# cliente.py
import socket
import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from ecdsa_utils import assinar, verificar, carregar_chave_privada, carregar_chave_publica

# Configuração da Rede
SERVER = '127.0.0.1'
PORT = 5000
USERNAME = b'cliente'

# Parâmetros PBKDF2 (devem ser consistentes entre cliente e servidor)
salt = b'um_salt_seguro_e_aleatorio_para_as_chaves_derivadas'
iterations = 100000

# --- Carregar Chaves ECDSA do Cliente ---
try:
    sk_cliente = carregar_chave_privada("keys/client_private.pem")
    vk_cliente_publica = carregar_chave_publica("keys/client_public.pem") 
    vk_servidor_para_verificar = carregar_chave_publica("keys/server_public.pem")
except FileNotFoundError:
    print("ERRO: Arquivos de chave ECDSA não encontrados.")
    print("Por favor, execute 'python gerar_chaves.py' primeiro para criar as chaves.")
    exit()

# Criar socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((SERVER, PORT))
    print('[+] Conectado ao servidor.')
except ConnectionRefusedError:
    print("[-] Erro: Conexão recusada. O servidor pode não estar rodando ou a porta está incorreta.")
    exit()

# --- Handshake Diffie-Hellman e Verificação ECDSA ---
# PASSO 1: Cliente recebe os parâmetros DH (g, p) do servidor
parameter_bytes = sock.recv(4096)
if not parameter_bytes:
    print("[-] Servidor desconectou inesperadamente ao enviar parâmetros DH.")
    sock.close()
    exit()
try:
    parameters = serialization.load_pem_parameters(parameter_bytes)
    print('[+] Parâmetros DH recebidos do servidor.')
except ValueError as e:
    print(f"[-] Erro ao carregar parâmetros DH do servidor: {e}")
    sock.close()
    exit()

# PASSO 2: Geração da Chave Pública DH do Cliente
client_private_key = parameters.generate_private_key()
client_public_key = client_private_key.public_key()

# Serializar a chave pública do cliente para enviar
A_public_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Mensagem a ser assinada pelo cliente: sua chave pública DH em bytes + seu username
mensagem_assinar_cliente = A_public_bytes + USERNAME
assinatura_cliente = assinar(mensagem_assinar_cliente, sk_cliente)

# Enviar a chave pública DH do cliente e sua assinatura
sock.sendall(A_public_bytes + b'||' + assinatura_cliente + b'||' + USERNAME)
print(f'[+] Enviado Chave Pública DH do Cliente (A).')

# PASSO 3: Receber a chave pública DH do servidor (B_public_bytes) e sua assinatura
data = sock.recv(4096)
if not data:
    print("[-] Servidor desconectou inesperadamente ao enviar chave pública DH.")
    sock.close()
    exit()

try:
    B_public_bytes, assinatura_servidor, user_servidor = data.split(b'||')
    # Deserializar a chave pública do servidor
    B_public_key = serialization.load_pem_public_key(B_public_bytes)
except (ValueError, TypeError) as e:
    print(f"[-] Formato de handshake inválido recebido do servidor: {e}")
    sock.close()
    exit()

print(f'[+] Recebido Chave Pública DH do Servidor (B).')
print(f'[+] Servidor: {user_servidor.decode()}')

# A mensagem que o servidor assinou é a sua chave pública DH em bytes + seu username
mensagem_verificar_servidor = B_public_bytes + user_servidor

# Verificar assinatura do servidor
if not verificar(mensagem_verificar_servidor, assinatura_servidor, vk_servidor_para_verificar):
    print('[-] Assinatura do servidor inválida. Encerrando.')
    sock.close()
    exit()
print('[+] Assinatura do servidor válida.')

# --- Cálculo da Chave Secreta Compartilhada DH ---
# A chave compartilhada é o resultado do DH exchange
shared_key = client_private_key.exchange(B_public_key)
print('[+] Chave secreta compartilhada S gerada.')

# --- Derivação de Chaves AES e HMAC ---
# Usando o mesmo salt e iterations para garantir que cliente e servidor derivem as mesmas chaves
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

# --- Enviar Mensagem Criptografada ---
iv = os.urandom(16)
mensagem_original = b'Mensagem secreta do cliente para o servidor'

pad = 16 - len(mensagem_original) % 16
mensagem_com_padding = mensagem_original + bytes([pad]) * pad

cipher = Cipher(algorithms.AES(Key_AES), modes.CBC(iv))
encryptor = cipher.encryptor()
criptografada = encryptor.update(mensagem_com_padding) + encryptor.finalize()

hmac_tag = hmac.new(Key_HMAC, iv + criptografada, hashlib.sha256).digest()

pacote_completo = hmac_tag + iv + criptografada
sock.sendall(pacote_completo)

print('[+] Mensagem criptografada e autenticada enviada com sucesso!')
sock.close()
print('[+] Conexão encerrada.')