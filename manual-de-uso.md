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

### 🔹 Requisitos

* Python **3.10 ou superior**
* Bibliotecas necessárias:

  ```bash
  pip install aiohttp python-socketio cryptography pillow qrcode
  ```
* Sistema operacional compatível com `tkinter` (Windows, Linux, macOS).

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
║ [Área principal]   Exibição de conteúdo e resultados              ║
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
| ---------------------------------------- | --------------------------------------------------------------- | -------- | ------------------------------ |
| `online_users`                           | Lista usuários online e autenticados                            |          |                                |
| `ban_user <username> <duração> <motivo>` | Bane um usuário temporariamente                                 |          |                                |
| `reputation <username> [nova_reputação]` | Consulta ou altera a reputação                                  |          |                                |
| `server_stats`                           | Mostra estatísticas do servidor (usuários, conteúdo, DNS, etc.) |          |                                |
| `content_stats`                          | Lista estatísticas por tipo MIME (imagens, vídeos, etc.)        |          |                                |
| `node_stats`                             | Exibe estatísticas de nós online e reputações médias            |          |                                |
| `list_reports`                           | Lista reportes pendentes de moderação                           |          |                                |
| `resolve_report <id> [ban                | warn                                                            | ignore]` | Resolve um reporte manualmente |
| `sync_network`                           | Inicia sincronização com outros servidores conhecidos           |          |                                |
| `exit`                                   | Encerra o servidor com segurança                                |          |                                |
| `help`                                   | Exibe lista de comandos disponíveis                             |          |                                |

---

### 🔹 Gerenciamento de TLS/SSL

O HPS Server suporta dois modos de operação segura:

#### 🔸 Certificado Autoassinado

Ideal para ambientes de teste ou uso pessoal.

* Gere o certificado com:

  ```bash
  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
  ```
* Execute o servidor apontando para os arquivos `.crt` e `.key`.

#### 🔸 Certificado Let’s Encrypt

Para ambientes públicos (HTTPS válido e confiável).
O certificado deve ser gerado e renovado externamente (ex.: via `certbot`).

---

### 🔹 Benefícios do Sistema Pseudo-descentralizado

O modelo adotado combina **servidores federados** e **clientes colaborativos**, permitindo:

* Alta **resiliência** (servidores sincronizam entre si);
* **Autonomia local** (cada servidor pode operar isoladamente);
* **Verificação de conteúdo distribuída**;
* **Escalabilidade horizontal** (qualquer usuário pode hospedar um nó adicional).

---

### 🔹 Operações Automáticas do Servidor

* **Verificação de integridade** de uploads;
* **Controle de reputação** e bloqueio automático;
* **Proof-of-Work adaptativo** por tipo de ação (login, upload, DNS, reporte);
* **Sincronização periódica** com outros nós (`sync_with_network`);
* **Registro detalhado de logs e conexões**.

---

### 🔹 Finalização e Parada Segura

Para encerrar o servidor corretamente:

```
(hps-admin) exit
```

Isso garante que todos os processos assíncronos e sincronizações em andamento sejam finalizados antes do desligamento.

---

### 🔹 Recomendações de Operação

* Sempre mantenha uma cópia de segurança do banco `hps_server.db`.
* Se possível, use certificados TLS válidos (Let’s Encrypt) para conexões externas.
* Evite modificar diretamente os arquivos `.dat` em `hps_files/`.
* Revise periodicamente reputações e reportes via console administrativo.
* Caso utilize múltiplos servidores, sincronize-os manualmente ao menos uma vez por semana com `sync_network`.

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

O uso responsável e ético da tecnologia garante a integridade e longevidade da rede.
