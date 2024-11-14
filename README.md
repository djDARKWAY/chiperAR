# CipherAR - Aplicação para confidencialidade e integridade

## Descrição
CipherAR é uma aplicação em Python desenvolvida para realizar diversas operações de criptografia e segurança de dados. Este projeto foi desenhado para explorar métodos de segurança digital e oferecer uma ferramenta prática para operações de criptografia simétrica e assimétrica, verificação de assinaturas digitais, geração de chaves e integridade de dados através de hashes.

## Funcionalidades principais
A arquitetura da aplicação é composta por diversos módulos principais, cada um desempenhando um papel crucial na segurança e integridade dos dados. Entre os módulos, destacam-se aqueles responsáveis pela criptografia, verificação de integridade e assinatura digital. A seguir, apresento as principais implementações:
- **Criptografia simétrica**: Utiliza uma única chave simétrica para cifrar e decifrar dados, implementando algoritmos como AES-128, AES-256, ChaCha20 e TripleDES. Os principais passos incluem a geração de chaves com `generateKey()`, a cifração de dados com `encryptFile()`, a remoção de padding quando necessário e a verificação de integridade através de hashes.
- **Criptografia assimétrica**: Utiliza duas chaves, uma pública e outra privada. A geração da chave AES-256 é feita com `get_random_bytes()`, e os dados são cifrados no modo EAX. A chave AES é cifrada com RSA-2048 através de `encryptRsa2048()`, permitindo uma troca segura de chaves.
- **Verificação de integridade**: Implementa hashing utilizando a biblioteca hashlib para gerar e verificar hashes dos dados. Isso não apenas assegura que os dados não foram alterados, mas também suporta a criação de assinaturas digitais para verificar se realmente deriva do emissor, que serão detalhadas posteriormente.

## Funcionalidades secundárias
Além das implementações principais, o sistema oferece diversas funcionalidades que melhoram a usabilidade e a segurança, incluindo:
- Identificação da extensão do ficheiro
- Geração e armazenamento de pares de chaves RSA
- Pesquisa automática de ficheiros
- Remoção de ficheiros residuais
- Interface para carregamento de ficheiros via tkinter
- Instalação automática de dependências
- Gestão de chaves públicas em menu

## Estrutura do projeto
- **/assets**: Contém recursos auxiliares e ficheiros usados pela aplicação.
- **encryptAsy.py / decryptAsy.py**: Scripts para operações de criptografia e descriptografia assimétrica.
- **encryptSy.py / decryptSy.py**: Scripts para operações de criptografia e descriptografia simétrica.
- **keyGenerator.py**: Ferramenta para gerar chaves de criptografia.
- **hashVerifier.py**: Utilitário para verificação de integridade dos dados usando hashes.
- **verifyKeys.py**: Ferramenta para verificação da validade das chaves de criptografia.
- **verifySignature.py**: Utilitário para verificação de assinaturas digitais.
- **logo.py**: Configura o logotipo ou a interface gráfica do projeto.
- **main.py**: Interface principal para aceder às funcionalidades do projeto.
- **requirements.txt**: Ficheiro que lista as dependências externas necessárias para executar o projeto.

## Pré-requisitos
- **Python 3.8 ou superior**: Certifique-se de que o Python está instalado.
    - Pode verificar a versão instalada com o comando: `python --version`.

## Instalação das dependências
### Modo automático
Para facilitar este processo, o programa utiliza um ficheiro chamado `requirements.txt`, que lista todos os pacotes necessários. Assim, sempre que o programa é iniciado, ele verifica e instala automaticamente as dependências:
### Modo manual
Se preferir, pode instalar cada biblioteca manualmente com um destes scripts:
```bash
pip install -r requirements.txt
pip install cryptography qrcode Pillow pycryptodome tk
```

### Bibliotecas externas
- **cryptography**: Para operações de criptografia e descriptografia avançada.
- **qrcode**: Para geração de códigos QR, permitindo a partilha de chaves ou mensagens de forma segura.
- **Pillow**: Utilizada para manipulação de imagens, especialmente no suporte a códigos QR.
- **pycryptodome**: Fornece implementações de algoritmos de criptografia de alto desempenho.
- **tk**: Interface gráfica Tkinter, usada para implementar a interface interativa do projeto.

## Como usar
### Configuração inicial
Instale as dependências usando o comando `pip install -r requirements.txt` para garantir que todos os pacotes necessários estão disponíveis.
### Iniciar a interface de consola
O ponto de entrada do projeto é o ficheiro `main.py`, que proporciona uma interface de consola interativa. Pode ser executado com o comando:
```bash
python main.py
```
### Navegação na interface de consola
Uma vez iniciado o `main.py`, a interface de consola guiará o utilizador através das opções de criptografia, descriptografia, verificação e geração de chaves. Selecione a opção desejada e siga as instruções para concluir a operação.

### Exemplos de uso
Para realizar operações específicas, siga os passos conforme guiado pela interface de consola no `main.py`. Seguem alguns exemplos típicos:
- **Symmetric cryptography**: Esta opção permite ao utilizador encriptar ficheiros usando criptografia simétrica, provavelmente utilizando um algoritmo como o AES. A criptografia simétrica é útil para proteger rapidamente os dados com uma única chave de encriptação.
- **Asymmetric cryptography (RSA)**: Aqui, o utilizador pode encriptar ficheiros utilizando criptografia assimétrica com o algoritmo RSA. Este tipo de criptografia utiliza um par de chaves (pública e privada), permitindo que dados encriptados com uma chave pública só possam ser decifrados pela chave privada correspondente, ideal para partilha de informações seguras.
- **Decrypt symmetric encryption**: Esta funcionalidade serve para decifrar ficheiros que foram encriptados com criptografia simétrica. O utilizador precisa de fornecer a mesma chave simétrica que foi utilizada para encriptar o ficheiro originalmente, para que os dados possam ser restaurados ao seu estado original.
- **Decrypt asymmetric encryption**: Esta opção permite ao utilizador decifrar ficheiros encriptados com criptografia assimétrica (RSA). O ficheiro encriptado com uma chave pública pode ser decifrado aqui, utilizando a chave privada correspondente, garantindo que apenas o detentor da chave privada possa aceder ao conteúdo original.
- **Generate encryption keys**: Aqui, o utilizador pode gerar um novo par de chaves para criptografia assimétrica (RSA). Esta funcionalidade cria uma chave pública e uma chave privada, essenciais para o processo de encriptação e assinatura digital.
- **Public keys management**: Esta funcionalidade permite ao utilizador gerir chaves públicas. O utilizador pode adicionar, remover ou visualizar chaves públicas de outros utilizadores, o que facilita a partilha de informações encriptadas de forma segura com múltiplos contactos.
- **Fix Dependencies**: Esta opção destina-se a resolver possíveis dependências de software necessárias para a aplicação funcionar corretamente. Pode envolver a instalação ou atualização de bibliotecas e ferramentas que a aplicação utiliza.
- **Exit**: Esta opção encerra a aplicação.

## Contribuições
Este projeto é de código aberto e as contribuições são bem-vindas. Para contribuir:
1. Faça um fork do projeto.
2. Crie uma nova branch com as suas alterações.
3. Abra um pull request com uma descrição detalhada da contribuição.

## Licença
Este projeto é distribuído sob a licença MIT. Consulte o ficheiro LICENSE para mais detalhes.