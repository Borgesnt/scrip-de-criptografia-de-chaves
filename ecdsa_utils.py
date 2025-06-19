# ecdsa_utils.py
from ecdsa import SigningKey, VerifyingKey, NIST384p

def gerar_chave_ecdsa():
    """Gera um novo par de chaves ECDSA."""
    sk = SigningKey.generate(curve=NIST384p)
    vk = sk.verifying_key
    return sk, vk

def assinar(mensagem, sk):
    """Assina uma mensagem com a chave privada."""
    # A biblioteca ecdsa espera bytes, então a mensagem deve ser bytes.
    return sk.sign(mensagem)

def verificar(mensagem, assinatura, vk):
    """Verifica uma assinatura com a chave pública."""
    # A biblioteca ecdsa espera bytes para a mensagem.
    try:
        return vk.verify(assinatura, mensagem)
    except Exception as e:
        #print(f"Erro na verificação da assinatura: {e}") # Para depuração
        return False

def salvar_chave_privada(sk, filename):
    """Salva a chave privada em um arquivo PEM."""
    with open(filename, "wb") as f:
        f.write(sk.to_pem())
    print(f"Chave privada salva em: {filename}")

def carregar_chave_privada(filename):
    """Carrega a chave privada de um arquivo PEM."""
    with open(filename, "rb") as f:
        return SigningKey.from_pem(f.read())

def salvar_chave_publica(vk, filename):
    """Salva a chave pública em um arquivo PEM."""
    with open(filename, "wb") as f:
        f.write(vk.to_pem())
    print(f"Chave pública salva em: {filename}")

def carregar_chave_publica(filename):
    """Carrega a chave pública de um arquivo PEM."""
    with open(filename, "rb") as f:
        return VerifyingKey.from_pem(f.read())

# As linhas que geravam as chaves foram removidas daqui para evitar regeneração em cada importação.
# As chaves serão gerenciadas pelos scripts do servidor e cliente.