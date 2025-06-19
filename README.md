# Comunicação Segura com Diffie-Hellman e ECDSA

Este projeto demonstra uma comunicação cliente-servidor segura utilizando a troca de chaves Diffie-Hellman (DH) para estabelecer uma chave secreta compartilhada, combinada com assinaturas digitais ECDSA (Elliptic Curve Digital Signature Algorithm) para autenticação das partes. A criptografia de mensagens é realizada com AES no modo CBC e a integridade é garantida com HMAC.

## Funcionalidades

* **Troca de Chaves Diffie-Hellman:** Utiliza a biblioteca `diffiehellman` para uma troca de chaves DH segura e padronizada (grupo 14).
* **Autenticação mútua com ECDSA:**
    * O cliente verifica a identidade do servidor através de uma assinatura digital.
    * O servidor verifica a identidade do cliente através de uma assinatura digital.
    * As chaves ECDSA são geradas e armazenadas em arquivos `.pem` para uso persistente.
* **Criptografia de Mensagens:** AES no modo CBC para garantir a confidencialidade dos dados transmitidos.
* **Integridade e Autenticidade da Mensagem:** HMAC-SHA256 para garantir que a mensagem não foi alterada e que veio da parte autêntica.
* **Derivação de Chaves:** PBKDF2HMAC para derivar as chaves de sessão (AES e HMAC) a partir da chave secreta DH compartilhada.

## Estrutura do Projeto

O projeto é composto pelos seguintes arquivos:

* `ecdsa_utils.py`: Módulo auxiliar que encapsula as funções de geração, salvamento, carregamento, assinatura e verificação de chaves ECDSA.
* `gerar_chaves.py`: Script autônomo para gerar os pares de chaves ECDSA (`.pem`) para o cliente e o servidor. **Deve ser executado uma única vez antes de rodar os outros scripts.**
* `servidor.py`: Implementa o lado do servidor que aguarda conexões, realiza o handshake seguro e recebe mensagens criptografadas.
* `cliente.py`: Implementa o lado do cliente que se conecta ao servidor, realiza o handshake seguro e envia uma mensagem criptografada.
* `keys/`: Diretório que será criado por `gerar_chaves.py` para armazenar as chaves ECDSA geradas (`server_private.pem`, `server_public.pem`, `client_private.pem`, `client_public.pem`).

## Requisitos

Você precisará do Python 3.6 ou superior e das seguintes bibliotecas Python:

* `pycryptography`
* `ecdsa`
* `diffiehellman`

## Instalação

1.  **Clone o repositório** (ou crie os arquivos manualmente em uma pasta):
    ```bash
    git clone <URL_DO_SEU_REPOSITORIO>
    cd <nome_da_pasta_do_projeto>
    ```

2.  **Instale as dependências** via pip:
    ```bash
    pip install pycryptography ecdsa diffiehellman
    ```

## Como Executar

Siga os passos abaixo na ordem para configurar e executar a comunicação segura.

### Passo 1: Gerar as Chaves ECDSA

Este passo é **fundamental** e deve ser executado **apenas uma vez** para criar os arquivos de chave ECDSA que serão usados pelo cliente e pelo servidor.

Abra seu terminal na raiz do projeto e execute:

```bash
python gerar_chaves.py