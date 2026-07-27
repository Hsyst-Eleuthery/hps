# Aplicativos do Ecossistema HPS

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** todos os guias anteriores ([1](userguide.md), [2](userguide2.md), [3](userguide3.md), [4](userguide4.md), [5](userguide5.md))

---

## Sumário

- [Visão geral dos aplicativos](#visão-geral-dos-aplicativos)
- [HPS Browser (Desktop)](#hps-browser-desktop)
- [HPS CLI (Linha de Comando)](#hps-cli-linha-de-comando)
- [HPS Miner (Mineração)](#hps-miner-mineração)
- [HPS Mobile (Android)](#hps-mobile-android)
- [HPS Wallet (Android)](#hps-wallet-android)
- [HPS Server](#hps-server)
- [HPS Proxy](#hps-proxy)
- [Instalação e requisitos](#instalação-e-requisitos)
- [Primeiros passos](#primeiros-passos)
- [Solução de problemas comuns](#solução-de-problemas-comuns)

---

## Visão geral dos aplicativos

O HPS não é um único programa — é um **ecossistema** de aplicativos que se comunicam.

| Aplicativo | Plataforma | Linguagem | Função principal |
|---|---|---|---|
| **Browser** | Windows, Linux | C# (Avalonia UI) | Navegação, publicação, gestão completa |
| **CLI** | Windows, Linux | C# (.NET) | Automação e comandos avançados |
| **Miner** | Windows, Linux | C# (Avalonia UI) | Mineração de vouchers |
| **Mobile** | Android | C# (.NET MAUI) | Navegação e carteira no celular |
| **Wallet** | Android | C# (.NET MAUI) | Carteira dedicada (QR code) |
| **Server** | Windows, Linux | Go | Infraestrutura da rede |
| **Proxy** | Windows, Linux | Go | Ponte entre web e HPS |

### Quem precisa de qual?

-   **Usuário comum:** Browser (desktop) ou Mobile (Android)
-   **Quem quer minerar:** adicione o Miner ao Browser
-   **Quem quer automatizar:** CLI
-   **Quem só quer gerenciar vouchers:** Wallet (Android)
-   **Quem quer rodar a infraestrutura:** Server + Proxy

---

## HPS Browser (Desktop)

O **HPS Browser** é o principal aplicativo para usuários. É uma janela que parece um navegador web, mas com superpoderes.

### Interface

-   **Barra de navegação:** digite `hps://` ou um hash para acessar conteúdo
-   **Abas:** navegue em múltiplos sites HPS simultaneamente
-   **Painéis laterais:** acesso rápido à carteira, contratos, configurações

### Funcionalidades principais

#### Navegação (`hps://`)

-   Digite `hps://thais` e veja o site
-   O Browser resolve o domínio, busca o conteúdo, e exibe
-   Suporta HTML, imagens, texto puro

#### Carteira

-   Veja seu saldo de vouchers HPS
-   Veja cada voucher individualmente (com histórico)
-   Envie vouchers para outros usuários
-   Receba vouchers (com confirmação)

#### Publicação

-   Selecione um arquivo do computador
-   O Browser calcula o hash automaticamente
-   Faz upload com assinatura digital
-   Mostra o hash gerado

#### Registro de Domínio

-   Registre nomes `hps://`
-   Associe a conteúdo publicado
-   Transfira domínios para outros usuários

#### Contratos

-   Veja todos os seus contratos
-   Inspecione contratos antes de assinar
-   Verifique assinaturas
-   Acompanhe histórico

#### Exchange

-   Troque vouchers entre servidores
-   Veja taxas e cotações
-   Acompanhe operações pendentes

#### Mensagens e Contatos

-   Envie mensagens diretas para outros usuários
-   Gerencie lista de contatos
-   Solicitações de conversa

#### Inventário

-   Gerencie itens digitais
-   Pedidos de transferência de inventário

#### Relatórios Econômicos

-   Gráficos de mint, burn, inflação
-   Métricas do servidor
-   Saúde econômica

#### Auditoria

-   Consistência entre vouchers
-   Estado da rede
-   Verificações de integridade

### Arquitetura interna

O Browser usa o padrão **MVVM** (Model-View-ViewModel) com a biblioteca **ReactiveUI**. Isso significa que a interface reage automaticamente a mudanças nos dados.

O ViewModel principal tem cerca de **16.000 linhas de código** — é onde mora a maior parte da lógica do Browser.

### Conexão com o servidor

-   **HTTP REST:** para operações discretas (upload, consultas)
-   **Socket.IO WebSocket:** para eventos em tempo real (atualizações de carteira, notificações)

---

## HPS CLI (Linha de Comando)

O **CLI** (Command Line Interface) é para quem prefere **texto** em vez de interface gráfica. É usado principalmente para automação.

### Para que serve

-   Scripts e automação
-   Integração com outros sistemas
-   Operações avançadas que não estão no Browser
-   Administração de servidores

### Comandos (70+)

O CLI tem comandos organizados em categorias:

#### Identidade
| Comando | O que faz |
|---|---|
| `whoami` | Mostra seu usuário atual |
| `login` | Faz login no servidor |
| `logout` | Faz logout |
| `keys` | Gerencia chaves criptográficas |

#### Servidores
| Comando | O que faz |
|---|---|
| `servers list` | Lista servidores conhecidos |
| `servers add` | Adiciona um servidor |
| `servers connect` | Conecta a um servidor |

#### Conteúdo
| Comando | O que faz |
|---|---|
| `upload` | Publica um arquivo |
| `get` | Baixa um conteúdo pelo hash |
| `download` | Baixa e salva um arquivo |
| `search` | Busca conteúdo |
| `resolve` | Resolve um domínio hps:// |

#### DNS
| Comando | O que faz |
|---|---|
| `dns-reg` | Registra um domínio |

#### Contratos
| Comando | O que faz |
|---|---|
| `contract search` | Busca contratos |
| `contract get` | Obtém um contrato específico |
| `contract analyze` | Analisa um contrato |
| `contract sign` | Assina um contrato |
| `contract verify` | Verifica uma assinatura |

#### Vouchers
| Comando | O que faz |
|---|---|
| `voucher get` | Obtém detalhes de um voucher |
| `voucher audit` | Audita vouchers |
| `voucher spend` | Gasta um voucher |

#### Exchange
| Comando | O que faz |
|---|---|
| `exchange validate` | Valida uma operação de exchange |
| `exchange confirm` | Confirma uma exchange |

#### Economia
| Comando | O que faz |
|---|---|
| `economy` | Mostra relatório econômico |
| `pow` | Informações sobre PoW |

#### Carteira
| Comando | O que faz |
|---|---|
| `wallet refresh` | Atualiza saldo |
| `wallet list` | Lista vouchers |
| `wallet show` | Mostra detalhes |
| `wallet mint` | Mineira novos vouchers |
| `wallet transfer` | Transfere vouchers |

#### Rede
| Comando | O que faz |
|---|---|
| `network` | Informações da rede |
| `security` | Status de segurança |

#### Ações
| Comando | O que faz |
|---|---|
| `actions transfer-file` | Transfere arquivo |
| `actions transfer-domain` | Transfere domínio |

#### Cancelamento
| Comando | O que faz |
|---|---|
| `cancel content` | Cancela publicação |
| `cancel dns` | Cancela domínio |
| `cancel flow` | Cancela fluxo |

#### Relatórios
| Comando | O que faz |
|---|---|
| `report` | Gera relatório |
| `fraud-report` | Reporta fraude |

#### Sincronização
| Comando | O que faz |
|---|---|
| `sync` | Sincroniza com servidor |
| `state` | Estado atual |
| `stats` | Estatísticas |
| `health` | Saúde do servidor |

---

## HPS Miner (Mineração)

O **HPS Miner** é o aplicativo dedicado a minerar vouchers.

### Modos de operação

#### Modo GUI (Interface Gráfica)

-   Janela com controles visuais
-   Configuração de threads com slider
-   Visualização de status em tempo real
-   Gráficos de desempenho

#### Modo CLI (Linha de Comando)

-   Opera sem interface gráfica
-   Ideal para servidores (headless)
-   Pode ser controlado por scripts

### Funcionalidades

-   **Mineração contínua:** resolve PoW automaticamente sem parar
-   **Threads ajustáveis:** configure quantas threads de CPU usar
-   **Agendamento:** programe horários para minerar
-   **Monitoramento:** veja hash rate, tentativas, sucessos
-   **Relatórios:** histórico de mineração

### PHPS (Títulos)

O Miner também permite:

-   Comprar títulos PHPS
-   Resgatar títulos PHPS
-   Monitorar mercado de taxas (fee market)

---

## HPS Mobile (Android)

O **HPS Mobile** leva o HPS para o seu celular Android.

### Interface

São **5 abas** na parte inferior da tela:

#### Aba 1: Navegar

-   Navegador de conteúdo `hps://`
-   Resolução de domínios
-   Inspeção de contratos
-   Toque para acessar links HPS

#### Aba 2: Carteira

-   Saldo de vouchers
-   Enviar vouchers
-   Receber vouchers
-   Histórico de transações
-   Cotações de exchange

#### Aba 3: Mineração

-   Mineração PoW diretamente no celular
-   **Slider de threads:** ajuste quantas threads usar (mais = mais rápido, menos = economia de bateria)
-   Mineração contínua (pode deixar rodando em segundo plano)
-   Estatísticas de mineração

#### Aba 4: Rede

-   Status da rede
-   Lista de nós conectados
-   Estabilidade dos servidores
-   Informações de conexão

#### Aba 5: Ajuda

-   Configurações
-   Informações do sistema
-   Suporte e links úteis

### Características técnicas

-   **Autenticação:** challenge-response com verificação mútua
-   **Reconexão automática:** backoff exponencial (1s → 30s, até 10 tentativas)
-   **Keepalive:** timeout de 120 segundos para detectar conexão perdida
-   **Armazenamento seguro:** credenciais guardadas no SecureStorage do Android

---

## HPS Wallet (Android)

O **HPS Wallet** é um aplicativo exclusivamente para gerenciar vouchers no celular.

### Diferente do Mobile

O Mobile é um navegador HPS completo. O Wallet é **só a carteira** — mas com funcionalidades extras:

-   **Leitura de QR Code:** escaneie QR codes para receber endereços sem digitar
-   **Saldo em tempo real:** atualização automática
-   **Envio e recebimento:** com confirmação por assinatura
-   **Cotações de exchange:** obtidas diretamente do servidor
-   **Transferências pendentes:** aceite ou rejeite transferências
-   **Notificações:** alerta de ofertas de vouchers

### QR Code

O Wallet usa a biblioteca **ZXing.Net.Maui** para ler e gerar QR codes. Cada voucher ou endereço pode ser representado como QR code para facilitar transferências.

---

## HPS Server

O **Server** é o coração da infraestrutura HPS. Se você quer rodar seu próprio servidor, é ele que precisa instalar.

### Requisitos

-   Go 1.25 ou superior
-   Acesso a um servidor (VPS, dedicado, ou local)
-   Conexão de rede estável

### O que o Server faz

-   Valida contratos
-   Armazena conteúdo (com criptografia)
-   Gerencia vouchers (mint, burn, transfer)
-   Mantém DNS descentralizado
-   Sincroniza com outros servidores
-   Processa PoW
-   Gera relatórios econômicos
-   Auditoria e verificação de integridade

### Configuração

O servidor é configurado por linha de comando:

```
hps-server --db hps_server.db --files hps_files --port 8080
```

### Banco de Dados

Usa **SQLite** com criptografia opcional. Todas as tabelas relevantes têm triggers de auditoria.

### Modo de armazenamento

-   **Padrão:** banco SQLite em disco com WAL
-   **Seguro:** banco em memória RAM com snapshots criptografados no disco

### Endpoints da API

Mais de **50 endpoints HTTP**:

| Categoria | Endpoints |
|---|---|
| **Saúde** | `/health`, `/server_info`, `/node/status` |
| **Conteúdo** | `/upload`, `/content/{hash}`, `/content/register` |
| **DNS** | `/dns/{domain}`, `/ddns/{domain}` |
| **Vouchers** | `/voucher/{id}`, `/voucher/confirm`, `/voucher/lock` |
| **Exchange** | `/exchange/validate`, `/exchange/confirm`, `/exchange/complete` |
| **Economia** | `/economy_report`, `/phps/market`, `/fee/quotes` |
| **Sincronização** | `/sync/content`, `/sync/dns`, `/sync/users`, `/sync/contracts` |
| **Handshake** | `/handshake/init`, `/handshake/complete` |
| **Auditoria** | `/server/audit`, `/server/integrity`, `/server/verify` |
| **PHPS** | `/phps/title/purchase`, `/phps/title/redeem` |

Também expõe eventos **Socket.IO** em tempo real (40+ eventos).

---

## HPS Proxy

O **Proxy** é um componente auxiliar que permite acessar conteúdo HPS de navegadores comuns.

### Como funciona

1.  Você acessa `http://proxy:8080/hps://algumdominio`
2.  O Proxy resolve o domínio HPS consultando um servidor
3.  Baixa o conteúdo
4.  Renderiza como HTML comum
5.  Serve para seu navegador

### Para que serve

-   **Compatibilidade:** qualquer navegador (Chrome, Firefox, Edge) pode acessar HPS
-   **Compartilhamento:** envie links HPS para quem não tem o Browser
-   **Transição:** facilita a migração da web tradicional para a HPS

### Cache

O Proxy mantém um **cache local** de conteúdo acessado recentemente, acelerando acessos repetidos.

---

## Instalação e requisitos

### Pré-requisitos comuns

-   **.NET 8.0+** (para Browser, CLI, Miner)
-   **.NET 10.0+** (para Mobile, Wallet)
-   **Go 1.25+** (para Server, Proxy)
-   **Windows:** MSYS2 com GCC (para compilar nativamente)

### Instalação do Windows

1.  Baixe o [MSYS2](https://github.com/msys2/msys2-installer/releases/download/2026-03-22/msys2-x86_64-20260322.exe)
2.  Abra o **MSYS2 UCRT64**
3.  Execute: `pacman -S mingw-w64-ucrt-x86_64-gcc`
4.  Adicione `C:\msys64\ucrt64\bin` ao PATH do Windows

### Compilação

#### Server
```bash
cd HPS-SERVER/server-go
go run main.go
```

#### Browser
```bash
cd HPS-BROWSER/browser-cs
dotnet run --project HpsBrowser.csproj
```

#### CLI
```bash
cd HPS-CLI/HPS-CLI
dotnet run --project HPS.Cli.csproj
```

#### Mobile
```bash
cd HPS-MOBILE/hps-mobile
dotnet build -f net10.0-android
```

#### Wallet
```bash
cd HPS-WALLET/hps-wallet
dotnet build -f net10.0-android
```

#### Miner
```bash
cd HPS-MINER/hps-miner
dotnet run --project HpsMiner.csproj
```

#### Proxy
```bash
cd HPS-PROXY/hps-proxy
go run ./cmd
```

---

## Primeiros passos

### 1. Conecte-se a um servidor

Use um dos servidores oficiais:

| Prioridade | Servidor | Protocolo |
|---|---|---|
| Principal | `https://server2.hps.hsyst.org` | HTTPS/TLS |
| Backup 1 | `http://server1.hps.hsyst.org` | HTTP |
| Backup 2 | `http://server3.hps.hsyst.org` | HTTP |

### 2. Teste a conexão

Abra `thais.hps` ou o hash `6dd7e54839da3f054e601af886b62f747aba300673bf2f2a9c224e680793382a`

### 3. Crie sua conta

-   O Browser gera suas chaves automaticamente na primeira execução
-   Escolha uma **senha forte** para proteger suas chaves locais
-   **Anote essa senha em um local seguro**

### 4. Explore

-   Navegue por conteúdos HPS
-   Veja sua carteira (inicialmente vazia)
-   Conheça a interface

### 5. Mineire vouchers

-   Abra o Miner ou a aba de mineração
-   Ajuste as threads conforme seu hardware
-   Comece a minerar
-   Em alguns minutos você terá seus primeiros vouchers

### 6. Publique algo

-   Crie uma página HTML simples
-   Publique pelo Browser
-   Registre um domínio `hps://`
-   Compartilhe com amigos

---

## Solução de problemas comuns

### "Não consigo conectar ao servidor"

-   Verifique sua conexão de internet
-   Tente um servidor diferente da lista oficial
-   Verifique se o firewall não está bloqueando a porta

### "Meu login não funciona"

-   Certifique-se de que está usando a chave privada correta
-   Refaça o processo de login (challenge-response)
-   Verifique se a chave pública está registrada no servidor

### "A mineração está muito lenta"

-   Aumente o número de threads (se seu hardware aguentar)
-   Feche outros programas pesados
-   A dificuldade do PoW aumenta com o uso — é normal

### "Meus vouchers sumiram"

-   Verifique se você está conectado ao servidor correto
-   Vouchers são específicos de cada servidor
-   Faça exchange se mudou de servidor
-   Verifique o histórico de contratos

### "Erro de instalação no Windows"

-   Certifique-se de que o MSYS2 está instalado
-   Verifique se o GCC está no PATH
-   Tente reinstalar o .NET SDK

---

## Termos importantes

| Termo | Definição simples |
|---|---|
| **Avalonia UI** | Framework de interface gráfica usado no Browser e Miner |
| **.NET MAUI** | Framework para apps mobile (Android) |
| **MVVM** | Padrão de arquitetura do Browser |
| **ReactiveUI** | Biblioteca para interfaces reativas |
| **Socket.IO** | Protocolo de tempo real (WebSocket) |
| **REST** | API HTTP tradicional |
| **Headless** | Operar sem interface gráfica |
| **Thread** | Linha de processamento da CPU |
| **Backoff Exponencial** | Estratégia de reconexão (espera cada vez mais) |
| **Keepalive** | Sinal para manter conexão ativa |
| **SecureStorage** | Área segura do Android para guardar credenciais |
| **ZXing** | Biblioteca de leitura de QR code |
| **Qi/Chi** | Roteador HTTP usado no servidor Go |

---

**Fim da série de guias do usuário HPS.**

Documentação técnica completa: [tecnico.md](tecnico.md)

---

*HPS — Descentralizado. Verificável. Soberano.*
