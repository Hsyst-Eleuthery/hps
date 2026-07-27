# Hsyst Peer-to-Peer Service (HPS)

> Uma infraestrutura P2P federada para publicação, contratos digitais, identidade, DNS descentralizado e economia nativa — sem autoridade central.

---

> **[Read in English](README.md)**

---

> **[Leia o Manual Técnico (Português do Brasil)](https://github.com/Hsyst-Eleuthery/hps/blob/main/docs/tecnico.md)**

---

> **[Leia o Guia de Usuário em Português do Brasil](https://github.com/Hsyst-Eleuthery/hps/blob/main/docs/userguide.md)**

---

## Capturas de tela

<table>
<tr>
<td><img src="docs/images/images1.PNG" width="400"></td>
<td><img src="docs/images/images2.png" width="400"></td>
</tr>
<tr>
<td><img src="docs/images/images3.png" width="400"></td>
<td><img src="docs/images/images4.png" width="400"></td>
</tr>
</table>

---

## ⚠️ AVISO

- Este projeto **não é totalmente de código aberto (open-source)**. Por favor, revise a [licença](LICENSE.md) antes de executar ou replicar o projeto.
- É a sua primeira vez usando? Nossos servidores oficiais são:

| Prioridade | Servidor | Protocolo | 
|----------|--------|----------| 
| Principal | `https://server2.hps.hsyst.org` | HTTPS/TLS | 
| Backup 1 | `http://server1.hps.hsyst.org` | HTTP (Backup do HTTPS/TLS) | 
| Backup 2 | `http://server3.hps.hsyst.org` | HTTP (Backup do Backup) |

- Você pode testar a conexão abrindo a URL "thais.hps" ou "6dd7e54839da3f054e601af886b62f747aba300673bf2f2a9c224e680793382a"

---

# Download
Se você deseja fazer o download, temos uma versão compilada para Windows e Linux! - [Clique aqui!](https://github.com/Hsyst-Eleuthery/hps/releases)

---

## Visão Geral

O HPS é uma **plataforma federada ponto a ponto (P2P)** que permite aos usuários:

- Publicar conteúdo
- Possuir identidades próprias
- Usar domínios `hps://`
- Criar e verificar contratos
- Transferir valor (vouchers)

Tudo isso sem uma autoridade central.

---

## Objetivos

- Controle dos dados pelo usuário
- Ausência de censura oculta
- Ações transparentes
- Sistema verificável

---

## Arquitetura

### Servidor (Go)
Gerencia armazenamento, contratos e sincronização.

### Navegador (C# — Avalonia UI)
Interface do usuário e navegação. Aplicativo desktop para Windows e Linux.

### Dispositivos Móveis (C# — .NET MAUI)
Cliente Android para navegação, login, carteira e operações de rede.

### CLI (C#)
Interação avançada e automação.

### Carteira (C# — .NET MAUI)
Carteira Android independente para gerenciamento de tokens HPS, com leitura de código de barras.

### Minerador (Opcional)
Gera vouchers (Prova de Trabalho/PoW). Pode ser executado em modo GUI ou CLI.

### Proxy (Opcional)
Melhora a comunicação na rede por meio de cache local.

---

## Modelo de Rede

- Sem servidor central
- Múltiplos servidores
- Usuários podem alternar livremente
- Identidade portátil

---

## Modelo de Segurança

- Identidade baseada em chaves pública/privada
- Ações assinadas
- Verificação automática

---

## Sistema de Contratos

Tudo o que é importante é um contrato:

- Uploads
- Transferências
- Domínios

Sem contrato = sem confiança. ---

## Conteúdo Distribuído

Os arquivos são armazenados com:

- Hash
- Assinatura
- História

---

## DNS descentralizado

```
hps://exemplo.site
```

- Domínios próprios
- Transferível
- Sem registrador

---

## Sistema de reputação

- Afeta o uso
- Dinâmico e visível

---

## Economia HPS (Vouchers)

Usado para:

- Envios
- Contratos
- Domínios
- Antispam

---

##Interface do navegador

- Navegação
- Alertas
- Verificação

---

## Começando

### Requisitos

- .NET 8.0+ (para navegador, CLI, minerador)
- .NET 10.0+ (para celular, carteira)
- Vá para 1,25+ (para servidor, proxy)
- Caso você esteja no Windows, instale o [MSYS2](https://github.com/msys2/msys2-installer/releases/download/2026-03-22/msys2-x86_64-20260322.exe)
- Para configurar o MSYS2, abra o MSYS2 UCRT64, e digite o seguinte comando: "pacman -S mingw-w64-ucrt-x86_64-gcc"
- Ao finalizar, adicione o diretório "C:\msys64\ucrt64\bin" ao seu PATH do Windows
- Utilize uma aplicação normalmente!

### Servidor

```bash
cd HPS-SERVER/server-go
go run main.go
```

### Navegador

```bash
cd HPS-BROWSER/browser-cs
dotnet run --project HpsBrowser.csproj
```

### CLI

```bash
cd HPS-CLI/HPS-CLI
dotnet run --project HPS.Cli.csproj
```

### Mobile

```bash
cd HPS-MOBILE/hps-mobile
dotnet build -f net10.0-android
```

### Carteira

```bash
cd HPS-WALLET/hps-wallet
dotnet build -f net10.0-android
```

### Minerador

```bash
cd HPS-MINER/hps-miner
dotnet run --project HpsMiner.csproj
```

### Proxy

```bash
cd HPS-PROXY/hps-proxy
go run ./cmd
```

---

## Estrutura do Projeto

```
HPS/
├── HPS-BROWSER/browser-cs/       # Cliente desktop (Avalonia UI, .NET 8)
├── HPS-MOBILE/hps-mobile/         # Cliente Android (.NET MAUI, .NET 10)
├── HPS-WALLET/hps-wallet/         # Carteira Android (.NET MAUI, .NET 10)
├── HPS-CLI/HPS-CLI/               # Interface de linha de comando (.NET 8)
├── HPS-MINER/hps-miner/           # Minerador PoW (Avalonia UI + CLI, .NET 8)
├── HPS-SERVER/server-go/          # Servidor backend (Go)
├── HPS-PROXY/hps-proxy/           # Proxy HTTP com cache (Go)
```

## Filosofia

- Nada é confiável por padrão
- Tudo é verificável

---

## Licença e Créditos

Criado por [Thaís](https://github.com/op3ny).

---

<p align="center">
<strong>HPS — Descentralizado. Verificável. Soberano.</strong>
</p>
