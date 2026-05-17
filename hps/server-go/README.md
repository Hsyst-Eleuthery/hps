# HPS Server

## Requisitos para build e execução

### Windows

1. **Instalar Build Tools for Visual Studio**
   - Download: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio
   - Selecionar: "Desktop development with C++"

2. **Abrir Developer Command Prompt**
   - Menu Iniciar > Visual Studio > "Developer Command Prompt for VS"

3. **Build e run**
   ```cmd
   cd HPS-SERVER\server-go
   go build -o hps_server.exe .
   .\hps_server.exe
   ```

### Linux

1. **Instalar dependências**
   ```bash
   sudo apt install build-essential libssl-dev tcl-dev
   ```

2. **Build e run**
   ```bash
   cd HPS-SERVER/server-go
   go build -o hps_server .
   ./hps_server
   ```

### macOS

1. **Instalar Xcode Command Line Tools**
   ```bash
   xcode-select --install
   ```

2. **Instalar OpenSSL (se necessário)**
   ```bash
   brew install openssl
   ```

3. **Build e run**
   ```bash
   cd HPS-SERVER/server-go
   go build -o hps_server .
   ./hps_server
   ```

## Nota sobre CGO

Este projeto requer **CGO** para SQLite com criptografia (SQLCipher). Isso significa que é necessário um compilador C (MSVC/GCC/Clang) na máquina de build. Não é necessário na máquina de execução após compilar.