# servidor.py
import socket
import os # Ainda necessário para os.urandom, mas para IV, não para DH
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Importações atualizadas para ECDSA e Diffie-Hellman
from ecdsa_utils import assinar, verificar, carregar_chave_privada, carregar_chave_publica
from diffiehellman.diffiehellman import DiffieHellman

# Configuração da Rede
HOST = '0.0.0.0'
PORT = 5000
USERNAME = b'servidor'

# Parâmetros PBKDF2 (devem ser consistentes entre cliente e servidor)
# Em um cenário real, o salt seria gerado aleatoriamente por sessão ou chave e compartilhado.
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

# Criar socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((HOST, PORT))
sock.listen(1)
print('[+] Servidor aguardando conexão...')

conn, addr = sock.accept()
print(f'[+] Conexão recebida de {addr}')

# --- Handshake Diffie-Hellman e Verificação ECDSA ---
# Receber a chave pública DH do cliente (A_public) e sua assinatura
data = conn.recv(4096)
if not data:
    print("[-] Cliente desconectou inesperadamente durante o handshake.")
    conn.close()
    exit()

try:
    A_public_str, assinatura_cliente, user_cliente = data.split(b'||')
    A_public = int(A_public_str.decode())
except ValueError:
    print("[-] Formato de handshake inválido recebido do cliente.")
    conn.close()
    exit()


print(f'[+] Recebido Chave Pública DH do Cliente (A): {A_public}')
print(f'[+] Cliente: {user_cliente.decode()}')

# A mensagem que o cliente assinou é a sua chave pública DH + seu username
mensagem_verificar_cliente = A_public_str + user_cliente

# Verificar assinatura do cliente com a chave pública do cliente carregada
if not verificar(mensagem_verificar_cliente, assinatura_cliente, vk_cliente_para_verificar):
    print('[-] Assinatura do cliente inválida. Encerrando.')
    conn.close()
    exit()
print('[+] Assinatura do cliente válida.')

# --- Geração e Envio da Chave Pública DH do Servidor ---
dh_server = DiffieHellman(group=14)
# GERAÇÃO DA CHAVE PRIVADA - PASSO ADICIONADO AQUI
dh_server.generate_private_key() # <--- ADICIONE ESTA LINHA
B_public = dh_server.generate_public_key() # Agora deve retornar um valor

# Mensagem a ser assinada pelo servidor: sua chave pública DH + seu username
mensagem_assinar_servidor = str(B_public).encode() + USERNAME
assinatura_servidor = assinar(mensagem_assinar_servidor, sk_servidor)

# Enviar a chave pública DH do servidor e sua assinatura
conn.sendall(str(B_public).encode() + b'||' + assinatura_servidor + b'||' + USERNAME)
print(f'[+] Enviado Chave Pública DH do Servidor (B): {B_public}')

# --- Cálculo da Chave Secreta Compartilhada DH ---
S = dh_server.generate_shared_key(A_public)
print(f'[+] Chave secreta compartilhada S gerada.')

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

# --- Receber e Descriptografar Mensagem Criptografada ---
pacote_completo = conn.recv(4096)
if not pacote_completo:
    print("[-] Cliente desconectou inesperadamente ao enviar mensagem criptografada.")
    conn.close()
    exit()

# O pacote é HMAC || IV || Criptografada
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

# Remover padding (PKCS7)
try:
    pad = mensagem_descriptografada_com_padding[-1]
    if pad < 1 or pad > 16: # Validação básica do padding
        raise ValueError("Padding inválido.")
    # Verificar se todos os bytes de padding são iguais ao valor do padding
    if not all(mensagem_descriptografada_com_padding[-pad:] == bytes([pad]) * pad):
        raise ValueError("Padding inválido.")
    mensagem_final = mensagem_descriptografada_com_padding[:-pad]
except ValueError as e:
    print(f"[-] Erro ao remover padding: {e}. Possível falha na descriptografia ou alteração da mensagem.")
    conn.close()
    exit()

print('[+] Mensagem recebida:', mensagem_final.decode())

conn.close()
sock.close()
print('[+] Conexão encerrada.')