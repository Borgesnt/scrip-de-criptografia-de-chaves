# gerar_chaves.py
from ecdsa_utils import gerar_chave_ecdsa, salvar_chave_privada, salvar_chave_publica
import os

# Certifique-se de que a pasta 'keys' existe
if not os.path.exists('keys'):
    os.makedirs('keys')

print("Gerando chaves ECDSA...")

# Chaves do Servidor
sk_server, vk_server = gerar_chave_ecdsa()
salvar_chave_privada(sk_server, "keys/server_private.pem")
salvar_chave_publica(vk_server, "keys/server_public.pem")

# Chaves do Cliente
sk_client, vk_client = gerar_chave_ecdsa()
salvar_chave_privada(sk_client, "keys/client_private.pem")
salvar_chave_publica(vk_client, "keys/client_public.pem")

print("\nChaves ECDSA geradas e salvas na pasta 'keys'.")
print("Certifique-se de que 'server_public.pem' e 'client_public.pem' estão disponíveis para o outro lado, respectivamente.")