# AVISO
- Este projeto não é open-source, verifique a [licença](https://github.com/Hsyst/hps/blob/main/LICENSE.md) antes de executar ou replicar


# ⚙️ Manual Técnico — Hsyst Peer-to-Peer Service (HPS)

## 1. Introdução Técnica

O **HPS (Hsyst Peer-to-Peer Service)** é uma plataforma **pseudo-descentralizada**, projetada para permitir **comunicação, autenticação e distribuição de conteúdo** em uma rede de servidores independentes, porém interoperáveis.

A arquitetura da rede HPS foi construída para **funcionar sem dependência de autoridades certificadoras (CA)**, preservando a autonomia e a natureza experimental do projeto, sem comprometer a segurança dos usuários.

A estrutura do código foi escrita integralmente em **Python assíncrono**, utilizando `aiohttp` e `python-socketio` para comunicação em tempo real, e **SQLite** como camada de persistência local.

O sistema é composto por dois componentes fundamentais:

* **Servidor HPS** (`hps_server.py`) — implementa a camada lógica, autenticação, armazenamento e sincronização.
* **Navegador HPS** (`hps_browser.py`) — cliente gráfico peer-to-peer, responsável por interface e interação.

---

## 2. Arquitetura Interna

A arquitetura do HPS segue um modelo **híbrido federado**:

* **Servidores** são responsáveis por armazenar, validar e propagar conteúdo;
* **Clientes** (navegadores) interagem com servidores confiáveis, mas **e atuam como retransmissores de dados (mas não de DDNS)**;
* A propagação de registros DNS descentralizados ocorre **exclusivamente entre servidores**, porém, os conteúdos são transmitidos pelos clientes, ou seja, caso o servidor não tenha, ele pode pedir aos clientes que tem aquele arquivo.

Essa separação garante:

* Maior segurança e controle sobre integridade;
* Prevenção de vazamento ou falsificação de dados por clientes;
* Isolamento entre camadas de operação.

---

## 3. Estrutura do Código-Fonte

### 3.1. `HPSServer`

Classe central do servidor.
Responsável por inicializar banco de dados, criar rotas HTTP/Socket.IO, validar PoW e gerenciar sincronizações.

Métodos principais:

| Método                       | Descrição                                                                     |
| ---------------------------- | ----------------------------------------------------------------------------- |
| `__init__()`                 | Inicializa o servidor e carrega as chaves criptográficas                      |
| `generate_server_keys()`     | Gera par RSA (4096 bits) se não existir                                       |
| `init_database()`            | Cria estrutura de tabelas em SQLite (`users`, `content`, `dns_records`, etc.) |
| `setup_handlers()`           | Registra eventos de socket e endpoints REST                                   |
| `handle_login()`             | Gerencia autenticação de clientes com verificação PoW                         |
| `register_content()`         | Registra novo conteúdo e o indexa por hash                                    |
| `register_dns_record()`      | Armazena domínios descentralizados (DDNS)                                     |
| `sync_with_network()`        | Inicia sincronização entre servidores conhecidos                              |
| `verify_pow_solution()`      | Valida prova de trabalho enviada por cliente                                  |
| `ban_client()`               | Aplica bloqueios automáticos ou manuais                                       |
| `make_remote_request_json()` | Realiza requisições seguras a outros nós HPS                                  |

### 3.2. `HPSAdminConsole`

Subclasse de `cmd.Cmd`.
Permite execução interativa de comandos administrativos dentro do terminal.

Internamente, o console executa métodos do `HPSServer` de forma segura e sincronizada, validando permissões e bloqueios.

### 3.3. `HPSBrowser`

Implementa a interface Tkinter, gerencia eventos gráficos e conexão cliente-servidor via WebSocket e HTTP.

Principais componentes:

* `LoginDialog`, `SearchDialog`, `UploadProgressWindow`, `ContentSecurityDialog`
* Módulo de PoW cliente-side (`PowSolver`)
* Camada de sincronização de metadados
* Sistema de cache local

---

## 4. Banco de Dados

O HPS utiliza **SQLite** como base local.
O banco é criado automaticamente na primeira execução do servidor e inclui as seguintes tabelas principais:

| Tabela          | Finalidade                                                         |
| --------------- | ------------------------------------------------------------------ |
| `users`         | Contém informações de autenticação, reputação e chaves públicas    |
| `content`       | Indexa arquivos registrados por hash e tipo MIME                   |
| `dns_records`   | Armazena domínios descentralizados (DDNS) e seus hashes associados |
| `reports`       | Guarda reportes de conteúdo para moderação                         |
| `network_nodes` | Lista de servidores conhecidos e seus metadados                    |
| `pow_history`   | Histórico de provas de trabalho resolvidas por cliente             |

Cada registro de conteúdo contém:

* `hash` — identificador único;
* `owner` — nome do usuário autor;
* `signature` — assinatura RSA sobre o conteúdo;
* `timestamp` — data de registro;
* `mime_type` — tipo do arquivo;
* `trust_score` — pontuação média derivada de reputação e verificações.

---

## 5. Sistema de Sincronização de Servidores

### 5.1. Mecanismo Geral

A sincronização entre servidores HPS é feita através de requisições **HTTP ou HTTPS**, baseadas em endpoints REST padronizados, transmitindo objetos JSON.

Os endpoints típicos incluem:

* `/sync/content`
* `/sync/dns`
* `/sync/users`
* `/ping`
* `/status`

O servidor iniciador da sincronização envia um conjunto de hashes e registros, e o servidor remoto responde com metadados ausentes ou divergentes.

A operação ocorre em ambas as direções, garantindo **consistência federada** da rede.

---

### 5.2. Restrições e Certificados

Por padrão, **servidores com certificados autoassinados não podem se sincronizar com outros servidores via HTTPS**, uma vez que a verificação de certificado falha durante o handshake TLS.

**Entretanto, isso não é um erro de projeto**, e sim **um comportamento intencional**.
A rede HPS **não depende de CAs confiáveis** — a autenticação entre servidores é feita com base em **hashes de chave pública**, não em certificados externos.

Por motivos de interoperabilidade, a arquitetura recomenda **rodar dois servidores simultaneamente**:

| Instância                        | Finalidade                                      | Tipo de Conexão |
| -------------------------------- | ----------------------------------------------- | --------------- |
| **Servidor TLS autoassinado**    | Interface principal para usuários (Browser HPS) | HTTPS           |
| **Servidor HTTP puro (sem TLS)** | Canal interno de sincronização entre servidores | HTTP            |

Ambos podem (e devem) operar no mesmo host, mas em **portas diferentes**.

---

### 5.3. Configuração Recomendada de Sincronização

#### Estrutura típica:

```
Servidor A:
- HTTPS (porta 443 ou 8443)  -> para usuários via navegador
- HTTP  (porta 8080)         -> para sincronização entre servidores

Servidor B:
- HTTP  (porta 8080)
```

#### Fluxo:

1. Usuários acessam o servidor A via **TLS autoassinado**.
2. Caso um conteúdo solicitado **não exista** localmente, o servidor A consulta os pares via **HTTP**, sincronizando novos arquivos e metadados.
3. Após sincronização, o conteúdo fica disponível também no servidor TLS.
4. O navegador do usuário (HPS Browser) acessa o conteúdo como se fosse local, sem perceber a origem externa.

Esse mecanismo permite que a rede **propague conteúdo entre nós confiáveis**, sem depender de uma infraestrutura de autoridade certificadora (CA).

---

### 5.4. Sobre o DDNS Descentralizado

Os registros **DDNS** são um dos pilares do HPS.
Eles funcionam como um mapeamento distribuído entre **nomes simbólicos** e **hashes de conteúdo**.

**Importante:**
Os registros DDNS **não são propagados pelos clientes (Browsers)**.
A replicação desses dados ocorre **somente entre servidores**, para evitar:

* Alterações maliciosas ou corrupção de nomes;
* Sobrecarga desnecessária em clientes;
* Vazamentos de tabelas DNS descentralizadas.

Assim, apenas servidores em modo de sincronização HTTP trocam registros DDNS, garantindo integridade e controle sobre o namespace.

---

### 5.5. Comportamento Esperado do Usuário Final

Quando um usuário estiver conectado a um servidor **TLS autoassinado** e tentar acessar um conteúdo inexistente naquele servidor:

1. O navegador HPS exibirá que o conteúdo não foi encontrado;
2. O usuário poderá, manualmente ou automaticamente, **reconectar-se ao servidor HTTP equivalente**, caso este seja conhecido;
3. O servidor HTTP buscará o arquivo na rede (via sincronização federada);
4. Assim que o conteúdo for encontrado, será sincronizado de volta ao servidor TLS;
5. Todo o ecossistema HPS conectado ao servidor TLS passará a ter acesso ao novo conteúdo.

💡 Em termos simples:

> O servidor HTTP atua como “ponte” de sincronização para o servidor TLS autoassinado, garantindo que os usuários em HTTPS possam acessar toda a rede sem sair de seu ambiente seguro.

---

## 6. Criptografia e Autenticação

* **Assinaturas Digitais:**
  Todas as ações (upload, registro, DNS, reporte) são assinadas com chaves RSA 4096 bits.

* **Verificação Local:**
  Cada cliente valida assinaturas usando a chave pública do autor.

* **Prova de Trabalho (PoW):**
  O cliente realiza cálculos baseados em `sha256(prefix + nonce)` até atingir uma dificuldade estabelecida pelo servidor.
  Isso previne abusos (login massivo, flood, spam).

* **Transmissão Segura:**
  Quando TLS está ativo, todo tráfego entre cliente e servidor é criptografado.
  Quando em HTTP, apenas comunicações entre servidores são permitidas, reduzindo risco de interceptação.

---

## 7. Recomendações Oficiais de Operação

| Cenário                                    | Recomendação                                                                               |
| ------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Ambiente de testes ou rede privada         | Utilizar apenas TLS autoassinado                                                           |
| Ambiente federado com múltiplos nós        | Rodar duas instâncias: uma com TLS autoassinado (usuários) e outra sem TLS (sincronização) |
| Ambiente público de grande escala          | Pode-se usar certificados válidos (Let’s Encrypt), mas não é obrigatório                   |
| Clientes com restrições de verificação TLS | Preferir servidores sem CA (autoassinados) ou HTTP interno                                 |

Essa política garante **independência de CAs externas** e **compatibilidade entre servidores de diferentes níveis de autenticação**.

---

## 8. Estrutura de Endpoints (Resumo)

| Método | Endpoint          | Descrição                                 |
| ------ | ----------------- | ----------------------------------------- |
| `POST` | `/login`          | Autenticação via PoW e assinatura digital |
| `POST` | `/upload`         | Registro de conteúdo e assinatura         |
| `POST` | `/report`         | Envio de reporte de conteúdo              |
| `GET`  | `/content/<hash>` | Download de conteúdo                      |
| `GET`  | `/dns/<domain>`   | Consulta de domínio descentralizado       |
| `POST` | `/sync/content`   | Sincronização de metadados de conteúdo    |
| `POST` | `/sync/dns`       | Sincronização de registros DDNS           |
| `GET`  | `/status`         | Consulta de status do servidor            |
| `GET`  | `/ping`           | Verificação de disponibilidade            |

---

## 9. Segurança, Integridade e Auditoria

* Logs de auditoria são registrados em tempo real.
* Cada operação crítica é assinada e registrada.
* Sincronizações parciais são verificadas por hash cumulativo.
* A reputação é calculada dinamicamente com base em comportamento e tempo de atividade.

---

## 10. Conclusão Técnica

O **Hsyst Peer-to-Peer Service** foi projetado para ser **autônomo, criptograficamente íntegro e independente de infraestruturas centralizadas**.
Sua filosofia é clara: **cada servidor é soberano, mas colaborativo**, e cada cliente é livre, mas seguro.

A execução paralela de instâncias HTTP e HTTPS cria um **ecossistema híbrido de alta redundância**, em que:

* Servidores HTTP garantem propagação e sincronização de dados;
* Servidores TLS (autoassinados) garantem privacidade e confiança dos usuários.

Essa abordagem preserva a **natureza descentralizada e livre da rede**, sem depender de certificação externa ou estruturas corporativas.
