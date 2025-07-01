# Comunicação Segura com Diffie-Hellman e ECDSA em Python

Este projeto demonstra uma comunicação cliente-servidor segura, incorporando múltiplos princípios de criptografia para garantir confidencialidade, integridade e autenticidade. Ele utiliza a troca de chaves Diffie-Hellman (DH) para estabelecer uma chave secreta compartilhada, combinada com assinaturas digitais ECDSA (Elliptic Curve Digital Signature Algorithm) para autenticação mútua das partes. A criptografia das mensagens é realizada com AES no modo CBC, e a integridade e autenticidade das mensagens são garantidas com HMAC.

## Histórico de Evolução e Correções

Este projeto passou por diversas etapas de refinamento e depuração para garantir seu funcionamento robusto:

* **Início com DH Manual:** A versão inicial implementava o Diffie-Hellman manualmente, definindo parâmetros `p` e `g` e gerando expoentes secretos.
* **Transição para `diffiehellman`:** Migramos para a biblioteca `diffiehellman` para simplificar a implementação do DH.
* **Depuração da `diffiehellman`:** Encontramos e corrigimos problemas com a API da `diffiehellman` (ex: `get_public_key` para `generate_public_key`, necessidade de chamar `generate_private_key`, e o parâmetro `key_bits`).
* **Problemas com `diffiehellman` e Transição para `cryptography`:** Devido a comportamentos inconsistentes da biblioteca `diffiehellman` (como retornar `None` para chaves públicas mesmo após a geração), optou-se por migrar a implementação de Diffie-Hellman para a biblioteca padrão e mais robusta do Python, `cryptography`.
* **Ajustes na `cryptography`:** Corrigimos o uso do algoritmo de hash (`hashlib.sha256()` para `hashes.SHA256()`) para PBKDF2HMAC, que é o formato esperado pela `cryptography`.
* **Padronização de Envio de Chaves:** A troca de chaves públicas DH agora envolve a serialização e deserialização dos objetos de chave pública da `cryptography` para bytes (formato PEM) para transmissão via socket.
* **Validação de Padding:** A lógica de remoção de padding (PKCS7) no servidor foi aprimorada para uma validação mais robusta, evitando erros de tipo (`TypeError: 'bool' object is not iterable`).
* **Gerenciamento de Chaves ECDSA:** A geração de chaves ECDSA foi isolada em um script separado (`gerar_chaves.py`) e o carregamento/salvamento das chaves passou a ser feito via arquivos `.pem` no diretório `keys/`, garantindo que cliente e servidor usem as chaves corretas para autenticação.
* **Documentação Detalhada:** Este `README.md` foi criado para guiar o usuário através de todas as etapas de configuração e execução.

## Funcionalidades Chave

* **Troca de Chaves Diffie-Hellman (DH):** Utiliza a biblioteca `cryptography.hazmat.primitives.asymmetric.dh` para estabelecer uma chave secreta compartilhada entre cliente e servidor. Os parâmetros DH (gerador e módulo primo) são negociados ou pré-configurados (gerados dinamicamente pelo servidor neste exemplo, com um tamanho de 2048 bits, equivalente a grupos padrão).
* **Autenticação Mútua com ECDSA:**
    * **Autenticidade:** Cliente e servidor assinam suas respectivas chaves públicas DH e nomes de usuário com suas chaves privadas ECDSA.
    * **Verificação:** A parte receptora verifica a assinatura usando a chave pública ECDSA da outra parte. Isso impede ataques Man-in-the-Middle (MitM) ao garantir a identidade dos comunicantes.
    * **Gerenciamento de Chaves:** As chaves ECDSA (privadas e públicas) são geradas uma única vez e armazenadas de forma persistente em arquivos `.pem` na pasta `keys/`.
* **Criptografia de Mensagens (AES-256-CBC):**
    * A chave simétrica (AES Key) é derivada da chave secreta DH compartilhada usando PBKDF2HMAC.
    * Mensagens são cifradas utilizando o algoritmo AES (Advanced Encryption Standard) com chave de 256 bits, operando no modo CBC (Cipher Block Chaining) para confidencialidade. Um Vetor de Inicialização (IV) aleatório é gerado para cada mensagem.
* **Integridade e Autenticidade de Mensagens (HMAC-SHA256):**
    * Uma chave de autenticação de mensagens (HMAC Key) é derivada da mesma chave secreta DH compartilhada.
    * Um HMAC-SHA256 é calculado sobre o IV e o texto cifrado, garantindo que a mensagem não foi adulterada em trânsito e que foi enviada pela parte autêntica.
* **Derivação de Chaves (PBKDF2HMAC):** Utiliza PBKDF2HMAC com SHA256 para derivar as chaves de sessão (AES Key e HMAC Key) de forma segura a partir da chave secreta DH gerada. Um `salt` e um número de `iterations` (100.000) são usados para aumentar a resistência a ataques de força bruta.

## Estrutura do Projeto

O projeto é organizado nos seguintes arquivos e diretórios:

.
├── ecdsa_utils.py          # Módulo auxiliar para funções ECDSA (gerar, salvar, carregar, assinar, verificar).
├── gerar_chaves.py         # Script para gerar e salvar os pares de chaves ECDSA (.pem).
├── servidor.py             # Implementa o lado do servidor, aguardando conexões e processando a comunicação segura.
├── cliente.py              # Implementa o lado do cliente, conectando-se ao servidor e iniciando a comunicação.
├── README.md               # Este arquivo de documentação.
└── keys/                   # Diretório onde as chaves ECDSA geradas serão armazenadas:
├── client_private.pem  # Chave privada do cliente.
├── client_public.pem   # Chave pública do cliente.
├── server_private.pem  # Chave privada do servidor.
└── server_public.pem   # Chave pública do servidor.


## Requisitos de Software

Você precisará do **Python 3.6 ou superior** e das seguintes bibliotecas Python, que devem ser instaladas no seu ambiente virtual:

* `cryptography`: Biblioteca principal para funcionalidades criptográficas (AES, PBKDF2, Diffie-Hellman).
* `ecdsa`: Biblioteca para implementação do algoritmo de assinatura digital de Curva Elíptica.

## Instalação e Configuração Detalhada

Siga estes passos para configurar seu ambiente e o projeto:

1.  **Clone o repositório** (ou crie os arquivos manualmente em uma pasta dedicada ao projeto):
    ```bash
    git clone [https://github.com/Borgesnt/scrip-de-criptografia-de-chaves.git](https://github.com/Borgesnt/scrip-de-criptografia-de-chaves.git)
    cd scrip-de-criptografia-de-chaves
    ```

2.  **Crie um Ambiente Virtual (Altamente Recomendado):**
    É altamente recomendável usar um ambiente virtual para isolar as dependências do projeto da sua instalação global do Python, prevenindo conflitos de pacotes.
    ```bash
    python -m venv venv
    ```

3.  **Ative o Ambiente Virtual:**
    Este passo é **crucial** e deve ser realizado **sempre que você abrir um novo terminal** para trabalhar neste projeto. A ativação garante que os comandos `pip` e `python` usem o ambiente virtual do projeto.

    * **No Linux / macOS (Bash, Zsh, ou Terminal do VS Code):**
        ```bash
        source venv/bin/activate
        ```
    * **No Windows (Prompt de Comando - `cmd.exe`):**
        ```cmd
        venv\Scripts\activate.bat
        ```
    * **No Windows (PowerShell):**
        ```powershell
        .\venv\Scripts\Activate.ps1
        ```
        **Observação para PowerShell:** Se você receber um erro como "Set-ExecutionPolicy" ou "cannot be loaded because running scripts is disabled on this system", pode ser necessário ajustar a política de execução. Abra o PowerShell **como administrador** e execute:
        ```powershell
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
        ```
        Confirme com `S` ou `Y`. Depois de ativar o ambiente virtual e terminar de usar o projeto, você pode reverter a política (opcional): `Set-ExecutionPolicy Restricted -Scope CurrentUser`.

    Após a ativação bem-sucedida, o prompt do seu terminal deve mudar para algo como `(venv) seu_usuario@sua_maquina:~/caminho/do/projeto$`, indicando que o ambiente virtual está ativo.

4.  **Instale as Dependências do Projeto:**
    Com o ambiente virtual **ativo** no seu terminal, instale as bibliotecas necessárias:
    ```bash
    pip install cryptography ecdsa
    ```
    Confirme que as instalações foram bem-sucedidas.

## Como Executar o Projeto

Agora que o ambiente está configurado e as dependências instaladas, siga a ordem exata para executar o servidor e o cliente.

### Passo 1: Gerar as Chaves ECDSA

Este passo é **fundamental** e deve ser executado **apenas uma vez** para criar os arquivos de chave ECDSA (`.pem`) para o cliente e o servidor. Se você já executou e tem a pasta `keys/` com os arquivos, pode pular este passo.

No seu terminal, com o ambiente virtual ativado e na raiz do projeto, execute:

```bash
python gerar_chaves.py
Você verá mensagens confirmando a criação dos arquivos de chave na pasta keys/.

Passo 2: Iniciar o Servidor
O servidor deve ser iniciado primeiro para que o cliente possa se conectar a ele.

Abra um novo terminal (ou aba do terminal).

Navegue até a pasta raiz do projeto (scrip-de-criptografia-de-chaves).

Exemplo Linux/macOS: cd /home/ufc/Documentos/SI/scrip de criptografia de chaves

Exemplo Windows: cd C:\Users\alfre\Documentos\SI\scrip de criptografia de chaves

Ative o ambiente virtual (conforme a seção "Como Ativar o Ambiente Virtual" acima).

Execute o script do servidor:

Bash

python servidor.py
O servidor aguardará a conexão do cliente e exibirá [+] Servidor aguardando conexão....

Passo 3: Iniciar o Cliente
Após o servidor estar aguardando, inicie o cliente.

Abra outro terminal (ou aba do terminal).

Navegue até a pasta raiz do projeto (a mesma pasta do servidor).

Exemplo Linux/macOS: cd /home/ufc/Documentos/SI/scrip de criptografia de chaves

Exemplo Windows: cd C:\Users\alfre\Documentos\SI\scrip de criptografia de chaves

Ative o ambiente virtual (conforme a seção "Como Ativar o Ambiente Virtual" acima).

Execute o script do cliente:

Bash

python cliente.py
O cliente tentará se conectar ao servidor. Ambos os terminais deverão exibir uma série de mensagens detalhando o handshake criptográfico (troca de parâmetros DH, troca de chaves públicas, verificação de assinaturas, derivação de chaves) e, finalmente, a mensagem secreta sendo enviada pelo cliente e recebida/descriptografada pelo servidor.

Saída Esperada (Exemplo)
Terminal do Servidor:

[+] Servidor aguardando conexão...
[+] Conexão recebida de ('127.0.0.1', <porta_aleatória>)
[+] Parâmetros DH enviados ao cliente.
[+] Recebido Chave Pública DH do Cliente.
[+] Cliente: cliente
[+] Assinatura do cliente válida.
[+] Enviado Chave Pública DH do Servidor (B).
[+] Chave secreta compartilhada S gerada.
[+] Chaves AES e HMAC derivadas.
[+] HMAC verificado.
[+] Mensagem recebida: Mensagem secreta do cliente para o servidor
[+] Conexão encerrada.
Terminal do Cliente:

[+] Conectado ao servidor.
[+] Parâmetros DH recebidos do servidor.
[+] Enviado Chave Pública DH do Cliente (A).
[+] Recebido Chave Pública DH do Servidor (B).
[+] Servidor: servidor
[+] Assinatura do servidor válida.
[+] Chave secreta compartilhada S gerada.
[+] Chaves AES e HMAC derivadas.
[+] Mensagem criptografada e autenticada enviada com sucesso!
[+] Conexão encerrada.
Observações Importantes sobre Segurança e Boas Práticas
Gerenciamento de Chaves em Produção: Este projeto demonstra o uso de chaves ECDSA persistentes em arquivos. Em um ambiente de produção real, o gerenciamento de chaves é um aspecto de segurança crítico e muito mais complexo. Envolveria técnicas como armazenamento seguro (HSMs, KMS), rotação de chaves, revogação, e possivelmente uma Infraestrutura de Chaves Públicas (PKI) para distribuição e validação de certificados. Nunca use chaves privadas expostas em arquivos como neste exemplo em produção.

Parâmetros PBKDF2 (salt e iterations): No exemplo, o salt e o número de iterations para PBKDF2 são fixos. Para derivação de chaves a partir de senhas de usuário, o salt deve ser gerado aleatoriamente e ser único para cada usuário/senha, e armazenado junto ao hash da senha. Para derivação de chaves de sessão como aqui (a partir da chave secreta DH), o salt e iterations devem ser consistentes entre as partes, o que é garantido por serem hardcoded. O número de iterações (100000) é um valor razoável para a maioria dos usos, mas pode precisar ser ajustado com o tempo.

Tratamento de Erros: O código inclui tratamento básico de erros para falhas de conexão, formatação de dados e verificação criptográfica. Para aplicações robustas, um tratamento de erros mais abrangente, incluindo logging detalhado e mecanismos de recuperação ou renegociação, seria essencial.

Segurança de Produção: Este projeto serve como uma demonstração conceitual e educacional. Ele ilustra princípios criptográficos fundamentais. Não é recomendado usá-lo diretamente em ambientes de produção sem uma revisão de segurança aprofundada, auditoria por especialistas e implementação de todas as práticas recomendadas da indústria para sistemas criptográficos e de rede.

Ataques de Replay: Este protocolo, como está, não se defende contra ataques de replay (onde um invasor pode retransmitir uma mensagem capturada). Para se defender contra isso, seriam necessários nonces ou números de sequência em cada mensagem.

Forward Secrecy: O uso do Diffie-Hellman para derivar chaves de sessão oferece Forward Secrecy, o que significa que, mesmo que a chave privada ECDSA de longo prazo de uma das partes seja comprometida no futuro, as chaves de sessão passadas não podem ser recuperadas, protegendo a confidencialidade das comunicações anteriores.

Licença
Este projeto é de código aberto. Sinta-se à vontade para usá-lo, modificá-lo e aprender com ele.