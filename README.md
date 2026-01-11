# 🧩 Hsyst Peer-to-Peer Service (HPS)

# Está em uma distribuição Linux?

* Temos a versão compilada do software, baixe e execute!
* [Clique aqui](https://github.com/Hsyst-Eleuthery/hps/releases)

# ⚠️ AVISO

* Este projeto **não é open-source**, verifique a [licença](https://github.com/Hsyst-Eleuthery/hps/blob/main/LICENSE.md) antes de executar ou replicar.
- Utilizando pela primeira vez? Nosso servidor oficial é:
- - Conecte-se primeiro no: `server2.hps.hsyst.org` (HTTPS/TLS)
  - Caso não encontre o arquivo que procura, além do de testes, tente acessar em `server1.hps.hsyst.org` (HTTP/Backup do HTTPS/TLS)
  - Ou, caso não encontre em nenhum deles, tente acessar `server3.hps.hsyst.org` (*HTTP/Backup* do `HTTP/Backup do HTTPS/TLS`)

# Manual Técnico

* Quer saber a parte mais profunda do projeto? [Clique Aqui](https://github.com/Hsyst-Eleuthery/hps/blob/main/tecnico.md)

---

# 🧭 Manual do Usuário — Hsyst Peer-to-Peer Service (HPS)

## Introdução

O **HPS (Hsyst Peer-to-Peer Service)** é um sistema de comunicação e distribuição de conteúdo **pseudo-descentralizado**, que combina criptografia, rede P2P e autenticação digital.
Ele é composto por dois aplicativos principais:

* **HPS Browser** — o cliente gráfico, que permite ao usuário interagir com a rede HPS: publicar, buscar, verificar e consumir conteúdo.
* **HPS Server** — o nó servidor, que armazena conteúdo, autentica clientes e sincroniza informações entre outros servidores.

Este manual descreve, de forma didática e sequencial, o uso correto de ambos os componentes.

---

## 🖥️ Parte 1 — Navegador HPS (Browser)

### 🔹 Visão Geral

O **HPS Browser** é uma aplicação gráfica (interface em **Tkinter**) que atua como cliente da rede Hsyst, permitindo que o usuário:

* Crie ou acesse uma conta HPS;
* Envie (upload) e baixe (download) conteúdo;
* Registre domínios descentralizados (DDNS);
* Pesquise arquivos e serviços na rede;
* Verifique a autenticidade de dados e assinaturas;
* Reporte conteúdos irregulares;
* Sincronize dados com múltiplos servidores HPS.

---

### 🔹 Requisitos

* Python **3.10 ou superior**
* Bibliotecas necessárias:

  ```bash
  pip install aiohttp python-socketio cryptography pillow qrcode
  ```
* Sistema operacional compatível com `tkinter` (Windows, Linux, macOS).

---

### 🔹 Iniciando o Navegador

Execute o seguinte comando no terminal:

```bash
python3 hps_browser.py
```

O navegador abrirá uma janela gráfica principal, com a seguinte estrutura:

```
╔══════════════════════════════════════════════════════════════════╗
║      Navegador Hsyst P2P — Interface Principal                   ║
╠══════════════════════════════════════════════════════════════════╣
║ [Barra superior]   Barra de endereço HPS:// + Botões Navegação   ║
║ [Painel esquerdo]  Histórico, Uploads, DNS, Reportes, Pesquisa   ║
║ [Área principal]   Exibição de conteúdo e resultados             ║
║ [Rodapé]           Status de rede e reputação                    ║
╚══════════════════════════════════════════════════════════════════╝
```

---

### 🔹 Primeiros Passos

#### 🔸 Criar ou acessar uma conta

1. No menu superior, selecione **“Login / Registrar”**.
2. Insira um nome de usuário, senha e gere uma chave RSA automaticamente (opcional).
3. O navegador executará uma **prova de trabalho (PoW)** antes de autenticar, para evitar abusos na rede.
4. Após o login, a reputação inicial será exibida no rodapé.

#### 🔸 Buscar conteúdo

1. Clique em **“Buscar”** no painel lateral esquerdo.
2. Use termos livres ou filtros por tipo (`imagem`, `vídeo`, `documento`, `texto`, etc).
3. Resultados exibem:

   * Título e autor;
   * Hash de conteúdo (único);
   * Verificação digital (verde = verificado; laranja = não verificado);
   * Reputação do autor.

#### 🔸 Verificar segurança do conteúdo

Ao clicar em um item, abrirá o **“Verificador de Segurança”** com:

* Hash completo;
* Assinatura digital e chave pública do autor;
* Reputação e integridade.

Você pode copiar o hash, abrir o arquivo localmente, ou reportar conteúdo.

#### 🔸 Reportar conteúdo

1. Clique em **“Reportar Conteúdo”** dentro da janela de verificação.
2. Confirme a ação — somente usuários com reputação ≥ 20 podem reportar.
3. O servidor registra o reporte e, após análise, pode penalizar o autor.

#### 🔸 Registrar um domínio descentralizado (DDNS)

1. Acesse a aba **DNS**.
2. Escolha um nome de domínio (ex.: `meuarquivo.hps`).
3. Vincule ao hash do conteúdo (arquivo publicado).
4. O servidor registrará a entrada no **serviço DDNS**, tornando o conteúdo acessível via `hps://meuarquivo.hps`.

#### 🔸 Enviar (upload) um conteúdo

1. Clique em **“Upload”**.
2. Escolha um arquivo local.
3. O HPS Browser calculará o hash, assinará o arquivo e realizará upload via conexão segura (TLS, se disponível).
4. O progresso pode ser acompanhado na janela “Upload em Progresso”.

#### 🔸 Sincronizar rede

1. Vá até o menu de opções e selecione **“Sincronizar Rede”**.
2. Uma janela mostrará o progresso de sincronização entre servidores conhecidos (lista de peers e nós ativos).


#### 🔸 Transferir Domínios

1. No menu de opções, clique em **“Upload”**.
2. Crie um arquivo em sua máquina com o formato abaixo:
```
# HSYST P2P SERVICE
### START:
# USER: <DONO(A) ATUAL DO DOMINIO>
### :END START
### DNS:
# NEW_DNAME: DOMAIN = <NOME_DO_DOMINIO>
# NEW_DOWNER: OWNER = <NOVO_DONO_DO_DOMINIO>
### :END DNS
### MODIFY:
# change_dns_owner = true
# proceed = true
### :END MODIFY
```
3. Realize upload do arquivo com o formato acima, com o título `(HPS!dns_change){change_dns_owner=true, proceed=true}`
4. Pronto! Ao finalizar o upload, o domínio já estará transferido.

#### 🔸 Criando API Apps

1. No menu de opções, clique em **“Upload”**.
2. Selecione o arquivo que deseja realizar upload (e poder modifica-lo no futuro)
3. Realize upload com o título `(HPS!api){app}:{"NOME QUE QUER DAR PARA A APLICACAO"}`
4. Pronto! Ao realizar o upload, ele estará disponível para acesso normal.

### 🔸 Atualizando API Apps

1. Crie o API App
2. No menu de opções, clique em **“Upload”**.
3. Selecione o arquivo que deseja substituir pelo atual
4. Realize upload com o título `(HPS!api){app}:{"NOME DA APLICACAO QUE CRIOU"}`
5. Pronto! Ao realizar o upload, quem acessar o hash antigo, será notificado(a) da mudança!

---

### 🔹 Janelas e Diálogos Importantes

| Janela / Componente       | Finalidade                                       |
| ------------------------- | ------------------------------------------------ |
| **UploadProgressWindow**  | Exibe o progresso do envio de conteúdo           |
| **SearchDialog**          | Realiza buscas avançadas e ordenações            |
| **ContentSecurityDialog** | Mostra detalhes de verificação digital           |
| **ReportProgressWindow**  | Gerencia o envio de reportes de conteúdo         |
| **DDNSProgressWindow**    | Acompanha o registro de domínio descentralizado  |
| **NetworkSyncDialog**     | Sincroniza a base local com a rede de servidores |

---

## ⚙️ Parte 2 — Servidor HPS

### 🔹 Visão Geral

O **HPS Server** é o núcleo da rede Hsyst.
Ele gerencia usuários, reputação, conteúdo, sincronização com outros servidores, e a camada de autenticação P2P.

Cada instância do servidor:

* Gera suas próprias chaves RSA (4096 bits);
* Mantém um banco de dados SQLite com usuários e conteúdos;
* Comunica-se via **Socket.IO** e **HTTP(S)**;
* Oferece uma **Admin Console** interativa.

---

### 🔹 Iniciando o Servidor

Execução padrão:

```bash
python3 hps_server.py
```

Execução com TLS/SSL autoassinado:

```bash
python3 hps_server.py --cert server.crt --key server.key
```

Execução com certificado Let’s Encrypt:

```bash
python3 hps_server.py \
  --cert /etc/letsencrypt/live/seusite/fullchain.pem \
  --key /etc/letsencrypt/live/seusite/privkey.pem
```

---

### 🔹 Estrutura Padrão de Pastas

```
hps_server/
├── hps_server.py          # Código principal do servidor
├── hps_files/             # Diretório de armazenamento de conteúdo
├── hps_server.db          # Banco de dados SQLite local
├── logs/                  # (opcional) Registros de log
└── ssl/                   # (opcional) Certificados TLS
```

---

### 🔹 Console de Administração (Admin Console)

Ao iniciar o servidor, o console interativo é ativado automaticamente:

```
HPS Administration Console
Type "help" for commands
(hps-admin)
```

#### 🧾 Lista de Comandos

| Comando                                  | Descrição                                                       |          |                                |
| ---------------------------------------- | --------------------------------------------------------------- | ----------------------- | ------------------------------ |
| `online_users`                           | Lista usuários online e autenticados                            |                         |                                |
| `ban_user <username> <duração> <motivo>` | Bane um usuário temporariamente                                 |                         |                                |
| `reputation <username> [nova_reputação]` | Consulta ou altera a reputação                                  |                         |                                |
| `server_stats`                           | Mostra estatísticas do servidor (usuários, conteúdo, DNS, etc.) |                         |                                |
| `content_stats`                          | Lista estatísticas por tipo MIME (imagens, vídeos, etc.)        |                         |                                |
| `node_stats`                             | Exibe estatísticas de nós online e reputações médias            |                         |                                |
| `list_reports`                           | Lista reportes pendentes de moderação                           |                         |                                |
| `resolve_report <id>`                    | Resolve os reports realizados                                   | `[ban, warn ou ignore]` | Resolve um reporte manualmente |
| `sync_network`                           | Inicia sincronização com outros servidores conhecidos           |                         |                                |
| `exit`                                   | Encerra o servidor com segurança                                |                         |                                |
| `help`                                   | Exibe lista de comandos disponíveis                             |                         |                                |

---

### 🔹 Gerenciamento de TLS/SSL

O HPS Server suporta dois modos de operação segura:

#### 🔸 Certificado Autoassinado

Ideal para ambientes de teste ou uso pessoal.
Gere o certificado com:

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```

Em seguida, execute o servidor apontando para os arquivos `.crt` e `.key`.

#### 🔸 Certificado Let’s Encrypt

Para ambientes públicos (HTTPS válido e confiável).
O certificado deve ser gerado e renovado externamente (ex.: via `certbot`).

---

### ⚙️ 🔹 **Sincronização entre Servidores (HTTP + TLS Autoassinado)**

O sistema HPS utiliza um modelo híbrido, no qual **servidores TLS autoassinados** e **servidores HTTP** coexistem para garantir redundância, acessibilidade e independência de autoridades externas.

* Servidores **com certificados autoassinados** **não conseguem se sincronizar diretamente via HTTPS** com outros servidores.
* Por esse motivo, a arquitetura **recomenda rodar duas instâncias do mesmo servidor**:

  * Uma **com TLS ativo** (para usuários do navegador);
  * Outra **sem TLS (HTTP)** (para sincronização entre servidores).

Ambos compartilham o mesmo banco de dados e estrutura de arquivos, garantindo consistência completa.

#### ✅ Estrutura Recomendada

| Servidor        | Porta      | Função                               | Acesso |
| --------------- | ---------- | ------------------------------------ | ------ |
| `Servidor TLS`  | 443 / 8443 | Atendimento ao público (navegadores) | HTTPS  |
| `Servidor HTTP` | 8080       | Sincronização interna entre nós      | HTTP   |

#### 🔁 Comportamento de Sincronização

* Arquivos e registros **DDNS** são propagados **somente entre servidores**, **nunca por clientes**.
* O servidor TLS pode solicitar dados ao servidor HTTP se um conteúdo solicitado **não for encontrado** localmente.
* Assim, usuários conectados ao servidor TLS podem acessar arquivos recém-propagados da rede HTTP.
* O servidor HTTP, por sua vez, sincroniza com outros nós, propagando o conteúdo de volta ao servidor TLS.

💡 **Em resumo:**

> O servidor HTTP age como uma “espinha dorsal” da rede, propagando dados entre servidores.
> O servidor TLS autoassinado é a “porta de entrada” segura para usuários comuns.

#### 🌐 Independência de Autoridades Certificadoras (CA)

A rede Hsyst **não depende de CAs confiáveis externas**.
Toda autenticação entre servidores é feita com **hashes de chave pública** — não com certificados verificados por terceiros.

Como prática oficial:

* Use **um servidor sem HTTPS** para sincronização federada;
* Use **um servidor TLS autoassinado** para o público;
* Ou, caso prefira simplificar, utilize um **certificado válido** (Let’s Encrypt).

Essa abordagem mantém a integridade criptográfica da rede, ao mesmo tempo em que **preserva a autonomia** e **independência técnica**.

---

### 🔹 Benefícios do Sistema Pseudo-descentralizado

O modelo adotado combina **servidores federados** e **clientes colaborativos**, permitindo:

* Alta **resiliência** (servidores sincronizam entre si);
* **Autonomia local** (cada servidor pode operar isoladamente);
* **Verificação de conteúdo distribuída**;
* **Escalabilidade horizontal** (qualquer usuário pode hospedar um nó adicional);
* **Independência total de CAs externas**.

---

### 🔹 Recomportamento Esperado do Usuário

Ao utilizar o navegador conectado a um servidor TLS autoassinado:

* Caso o conteúdo requisitado **não esteja disponível** naquele servidor, o usuário deve conectar-se ao **servidor HTTP equivalente**, se conhecido.
* Esse servidor HTTP buscará o arquivo na rede, sincronizando-o automaticamente com o servidor TLS.
* Assim, o conteúdo passa a estar disponível para **todos os usuários da camada TLS**.

📌 *Ambas as instâncias são o mesmo servidor — apenas executadas duas vezes, em modos diferentes (com e sem TLS).*

---

### 🔹 Operações Automáticas do Servidor

* **Verificação de integridade** de uploads;
* **Controle de reputação** e bloqueio automático;
* **Proof-of-Work adaptativo** por tipo de ação (login, upload, DNS, reporte);
* **Sincronização periódica** com outros nós (`sync_with_network`);
* **Registro detalhado de logs e conexões**.

---

### 🔹 Diagnóstico e Logs

O sistema utiliza `logging` nativo do Python com níveis:

* INFO → Operações gerais;
* WARNING → Ações suspeitas ou limites de taxa atingidos;
* ERROR → Falhas críticas de conexão, banco de dados ou criptografia.

Os registros são impressos no terminal e podem ser redirecionados para arquivo.

---

### 🔹 Encerramento

O **HPS Server** e o **HPS Browser** operam conjuntamente para formar a rede Hsyst —
um ecossistema descentralizado de dados, reputações e assinaturas digitais.

O uso responsável e ético da tecnologia garante a integridade, privacidade e longevidade da rede.
