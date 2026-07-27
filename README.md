# Hsyst Peer-to-Peer Service (HPS)

> A federated P2P infrastructure for publishing, digital contracts, identity, decentralized DNS, and native economy — with no central authority.

---

> **[Leia em Português (Brasil)](README.pt-BR.md)**

---

> **[Leia o Manual Técnico (Português do Brasil)](https://github.com/Hsyst-Eleuthery/hps/blob/main/docs/tecnico.md)**

---

> **[Leia o Guia de Usuário em Português do Brasil](https://github.com/Hsyst-Eleuthery/hps/blob/main/docs/userguide.md)**

---

## Screenshots

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

## ⚠️ WARNING

- This project **is not fully open-source**. Please review the [license](LICENSE.md) before running or replicating.
- First time using it? Our official servers are:

  | Priority | Server | Protocol |
  |----------|--------|----------|
  | Primary | `https://server2.hps.hsyst.org` | HTTPS/TLS |
  | Backup 1 | `http://server1.hps.hsyst.org` | HTTP (Backup of HTTPS/TLS) |
  | Backup 2 | `http://server3.hps.hsyst.org` | HTTP (Backup of Backup) |

- You can test the connection opening the URL "thais.hps" or "6dd7e54839da3f054e601af886b62f747aba300673bf2f2a9c224e680793382a"

---

# Download
If you'd like to download, we have a compiled version for Windows and Linux!

- [Click here!](https://github.com/Hsyst-Eleuthery/hps/releases)

---

## Overview

HPS is a **federated peer-to-peer platform** that allows users to:

- Publish content
- Own identities
- Use `hps://` domains
- Create and verify contracts
- Transfer value (vouchers)

All without a central authority.

---

## Goals

- User control over data  
- No hidden censorship  
- Transparent actions  
- Verifiable system  

---

## Architecture

### Server (Go)
Handles storage, contracts and sync.

### Browser (C# — Avalonia UI)
User interface and navigation. Desktop application for Windows and Linux.

### Mobile (C# — .NET MAUI)
Android client for browsing, login, wallet, and network operations.

### CLI (C#)
Advanced interaction and automation.

### Wallet (C# — .NET MAUI)
Standalone Android wallet for HPS token management with barcode scanning.

### Miner (Optional)
Generates vouchers (Proof-of-Work). Can run as GUI or CLI mode.

### Proxy (Optional)
Improves network communication via local caching.

---

## Network Model

- No central server  
- Multiple servers  
- Users can switch freely  
- Identity is portable  

---

## Security Model

- Public/private key identity  
- Signed actions  
- Automatic verification  

---

## Contract System

Everything important is a contract:

- Uploads  
- Transfers  
- Domains  

No contract = no trust.

---

## Distributed Content

Files are stored with:

- Hash  
- Signature  
- History  

---

## Decentralized DNS

```
hps://example.site
```

- Owned domains  
- Transferable  
- No registrar  

---

## Reputation System

- Affects usage  
- Dynamic and visible  

---

## HPS Economy (Vouchers)

Used for:

- Uploads  
- Contracts  
- Domains  
- Anti-spam  

---

## Browser Interface

- Navigation  
- Alerts  
- Verification  

---

## Getting Started

### Requirements

- .NET 8.0+ (for Browser, CLI, Miner)
- .NET 10.0+ (for Mobile, Wallet)
- Go 1.25+ (for Server, Proxy)
- Caso esteja no Windows, instale o [MSYS2](https://github.com/msys2/msys2-installer/releases/download/2026-03-22/msys2-x86_64-20260322.exe)
- Para configurar o MSYS2, abra o MSYS2 UCRT64, e digite o seguinte comando: "pacman -S mingw-w64-ucrt-x86_64-gcc"
- Ao finalizar, adicione o diretório "C:\msys64\ucrt64\bin" a sua PATH do Windows
- Utilize a aplicação normalmente!

### Server

```bash
cd HPS-SERVER/server-go
go run main.go
```

### Browser

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

### Wallet

```bash
cd HPS-WALLET/hps-wallet
dotnet build -f net10.0-android
```

### Miner

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

## Project Structure

```
HPS/
├── HPS-BROWSER/browser-cs/       # Desktop client (Avalonia UI, .NET 8)
├── HPS-MOBILE/hps-mobile/         # Android client (.NET MAUI, .NET 10)
├── HPS-WALLET/hps-wallet/         # Android wallet (.NET MAUI, .NET 10)
├── HPS-CLI/HPS-CLI/               # Command-line interface (.NET 8)
├── HPS-MINER/hps-miner/           # PoW miner (Avalonia UI + CLI, .NET 8)
├── HPS-SERVER/server-go/          # Backend server (Go)
├── HPS-PROXY/hps-proxy/           # HTTP proxy with caching (Go)
```

## Philosophy

- Nothing is trusted by default  
- Everything is verifiable  

---

## License & Credits

Created by [Thaís](https://github.com/op3ny).

---

<p align="center">
  <strong>HPS — Decentralized. Verifiable. Sovereign.</strong>
</p>
