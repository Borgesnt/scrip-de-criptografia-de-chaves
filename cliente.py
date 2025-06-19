# cliente.py
import socket
import os # Necessário para os.urandom para o IV
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Importações atualizadas para ECDSA e Diffie-Hellman
from ecdsa_utils import assinar, verificar, carregar_chave_privada, carregar_chave_publica
from diffiehellman.diffiehellman import DiffieHellman

# Configuração da Rede
SERVER = '127.0.0.1'
PORT = 5000
USERNAME = b'cliente'

# Parâmetros PBKDF2 (devem ser consistentes entre cliente e servidor)
salt = b'um_salt_seguro_e_aleatorio_para_as_chaves_derivadas' # Mesmo salt do servidor
iterations = 100000 # Mesmo número de iterações do servidor

# --- Carregar Chaves ECDSA do Cliente ---
try:
    sk_cliente = carregar_chave_privada("keys/client_private.pem")
    vk_cliente_publica = carregar_chave_publica("keys/client_public.pem") # Para referência/depuração
    # Carregar a chave pública do servidor para verificar suas assinaturas
    vk_servidor_para_verificar = carregar_chave_publica("keys/server_public.pem")
except FileNotFoundError:
    print("ERRO: Arquivos de chave ECDSA não encontrados.")
    print("Por favor, execute 'python gerar_chaves.py' primeiro para criar as chaves.")
    exit()

# --- Geração da Chave Pública DH do Cliente ---
dh_client = DiffieHellman(group=14)
A_public = dh_client.generate_public_key()

# Mensagem a ser assinada pelo cliente: sua chave pública DH + seu username
mensagem_assinar_cliente = str(A_public).encode() + USERNAME
assinatura_cliente = assinar(mensagem_assinar_cliente, sk_cliente)

# Criar socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((SERVER, PORT))
    print('[+] Conectado ao servidor.')
except ConnectionRefusedError:
    print("[-] Erro: Conexão recusada. O servidor pode não estar rodando ou a porta está incorreta.")
    exit()

# --- Enviar Chave Pública DH do Cliente e sua Assinatura ---
sock.sendall(str(A_public).encode() + b'||' + assinatura_cliente + b'||' + USERNAME)
print(f'[+] Enviado Chave Pública DH do Cliente (A): {A_public}')

# --- Receber Chave Pública DH do Servidor (B) e sua Assinatura ---
data = sock.recv(4096)
if not data:
    print("[-] Servidor desconectou inesperadamente durante o handshake.")
    sock.close()
    exit()

try:
    B_public_str, assinatura_servidor, user_servidor = data.split(b'||')
    B_public = int(B_public_str.decode())
except ValueError:
    print("[-] Formato de handshake inválido recebido do servidor.")
    sock.close()
    exit()

print(f'[+] Recebido Chave Pública DH do Servidor (B): {B_public}')
print(f'[+] Servidor: {user_servidor.decode()}')

# A mensagem que o servidor assinou é a sua chave pública DH + seu username
mensagem_verificar_servidor = B_public_str + user_servidor

# Verificar assinatura do servidor com a chave pública do servidor carregada
if not verificar(mensagem_verificar_servidor, assinatura_servidor, vk_servidor_para_verificar):
    print('[-] Assinatura do servidor inválida. Encerrando.')
    sock.close()
    exit()
print('[+] Assinatura do servidor válida.')

# --- Cálculo da Chave Secreta Compartilhada DH ---
S = dh_client.generate_shared_key(B_public)
print('[+] Chave secreta compartilhada S gerada.')

# --- Derivação de Chaves AES e HMAC ---
# Usando o mesmo salt e iterations para garantir que cliente e servidor derivem as mesmas chaves
kdf_aes = PBKDF2HMAC(
    algorithm=hashlib.sha256(),
    length=32,
    salt=salt,
    iterations=iterations,
)
Key_AES = kdf_aes.derive(str(S).encode())

kdf_hmac = PBKDF2HMAC(
    algorithm=hashlib.sha256(),
    length=32,
    salt=salt,
    iterations=iterations,
)
Key_HMAC = kdf_hmac.derive(str(S).encode())

print('[+] Chaves AES e HMAC derivadas.')

# --- Enviar Mensagem Criptografada ---
iv = os.urandom(16) # Vetor de inicialização (IV) aleatório
mensagem_original = b'Mensagem secreta do cliente para o servidor'

# Aplicar padding (PKCS7) para garantir que o texto cifrado tenha um tamanho múltiplo do bloco AES (16 bytes)
pad = 16 - len(mensagem_original) % 16
mensagem_com_padding = mensagem_original + bytes([pad]) * pad

cipher = Cipher(algorithms.AES(Key_AES), modes.CBC(iv))
encryptor = cipher.encryptor()
criptografada = encryptor.update(mensagem_com_padding) + encryptor.finalize()

# Gerar HMAC da mensagem criptografada (IV + Criptografada)
hmac_tag = hmac.new(Key_HMAC, iv + criptografada, hashlib.sha256).digest()

# Enviar pacote: HMAC || IV || Criptografada
pacote_completo = hmac_tag + iv + criptografada
sock.sendall(pacote_completo)

print('[+] Mensagem criptografada e autenticada enviada com sucesso!')
sock.close()
print('[+] Conexão encerrada.')