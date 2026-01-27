# 🧩 Hsyst Peer-to-Peer Service (HPS)

# Está em uma distribuição Linux?

* Temos a versão compilada do software, baixe e execute!
* [Clique aqui](https://github.com/Hsyst-Eleuthery/hps/releases)

# ⚠️ AVISO

* Este projeto **não é totalmente open-source**, verifique a [licença](https://github.com/Hsyst-Eleuthery/hps/blob/main/LICENSE.md) antes de executar ou replicar.
- Utilizando pela primeira vez? Nosso servidor oficial é:
- - Conecte-se primeiro no: `server2.hps.hsyst.org` (HTTPS/TLS)
  - Caso não encontre o arquivo que procura, além do de testes, tente acessar em `server1.hps.hsyst.org` (HTTP/Backup do HTTPS/TLS)
  - Ou, caso não encontre em nenhum deles, tente acessar `server3.hps.hsyst.org` (*HTTP/Backup* do `HTTP/Backup do HTTPS/TLS`)

# Manual Técnico

* Quer saber a parte mais profunda do projeto? [Clique Aqui](https://github.com/Hsyst-Eleuthery/hps/blob/main/tecnico.md)

---

# HPS

## **Hsyst Peer-to-Peer Service**

> Uma infraestrutura P2P para publicação, contratos digitais, identidade, DNS descentralizado e economia nativa — sem autoridade central.

---

## 📖 Visão Geral

O **HPS (Hsyst Peer-to-Peer Service)** é uma plataforma **peer-to-peer descentralizada**, escrita em **Python**, projetada para permitir que usuários publiquem, transfiram e validem conteúdos digitais de forma **auditável, verificável e resistente a censura**.

O sistema combina conceitos de:

* Redes P2P
* Criptografia assimétrica
* Contratos digitais assinados
* DNS descentralizado
* Reputação distribuída
* Economia interna baseada em esforço criptográfico

Tudo isso **sem depender de servidores centrais, autoridades externas ou confiança implícita**.

---

## 🎯 Objetivos do Projeto

O HPS foi projetado para resolver problemas reais de sistemas centralizados:

* Falta de soberania sobre conteúdo
* Dependência de intermediários
* Censura arbitrária
* Falta de transparência em decisões
* Dificuldade de auditoria
* Abuso por spam ou automação

O objetivo **não é substituir a internet tradicional**, mas **oferecer uma camada alternativa**, onde regras são explícitas, registradas e verificáveis.

---

## 🧩 Arquitetura Geral

O HPS é composto por **dois componentes principais**:

### 🔹 Servidor HPS

Responsável por:

* Armazenamento distribuído
* Validação de contratos
* Sincronização entre nós
* Gestão de usuários e reputação
* Registro de domínios
* Economia HPS (vouchers)

### 🔹 Cliente / Browser HPS

Responsável por:

* Interface gráfica
* Publicação e consumo de conteúdo
* Assinatura de contratos
* Verificação visual de segurança
* Navegação via `hps://`

Ambos são escritos em Python e se comunicam via **Socket.IO + HTTP**.

---

## 🌐 Modelo de Rede

* Não existe “servidor mestre”
* Qualquer servidor pode entrar ou sair
* Servidores sincronizam dados entre si
* Clientes podem mudar de servidor sem perder identidade
* O estado da rede emerge da soma dos contratos válidos

A rede prioriza **consistência verificável**, não autoridade.

---

## 🔐 Modelo de Segurança

### Identidade

Cada usuário possui:

* Uma chave pública
* Uma chave privada

A identidade **não depende de e-mail, IP ou provedor externo**.

---

### Assinaturas Digitais

São assinados criptograficamente:

* Conteúdos
* Domínios
* Contratos
* Transferências
* Operações econômicas

Qualquer alteração posterior invalida a assinatura.

---

### Verificação

O cliente HPS:

* Valida hashes
* Confere assinaturas
* Detecta adulterações
* Bloqueia automaticamente conteúdos inválidos

A segurança é **ativa**, não opcional.

---

## 📜 Sistema de Contratos

O **contrato** é a unidade central de confiança do HPS.

Um contrato define:

* Quem executou a ação
* Qual foi a ação
* Sobre qual alvo (conteúdo, domínio, app, valor)
* Em qual contexto
* Em qual momento
* Com qual assinatura

### Exemplos de contratos

* Upload de conteúdo
* Transferência de domínio
* Mudança de proprietário
* Certificação de material
* Emissão ou transferência de vouchers

Se uma ação **não possui contrato válido**, ela **não é confiável**.

---

## ⚠️ Violações Contratuais

Quando um contrato é violado:

* O conteúdo pode ser bloqueado
* O domínio perde garantia
* A interface alerta o usuário
* Um novo contrato pode ser exigido
* Um certificador pode intervir

Nada é apagado silenciosamente.
Tudo deixa rastro.

---

## 📁 Conteúdo Distribuído

O HPS suporta qualquer tipo de arquivo:

* Texto
* Imagem
* Vídeo
* Áudio
* Binários

Cada conteúdo possui:

* Hash imutável
* Autor
* Dono
* Assinatura
* Histórico
* Reputação associada

A confiança não vem do arquivo — vem do **contexto contratual**.

---

## 🌍 DNS Descentralizado (`hps://`)

O HPS implementa um sistema de nomes próprio.

Exemplo:

```
hps://meuprojeto.docs
```

Características:

* Domínios têm dono
* Transferências exigem contrato
* Histórico é preservado
* Não depende de ICANN ou registradores

Um domínio é apenas um **contrato apontando para um hash**.

---

## ⭐ Sistema de Reputação

Cada usuário possui uma reputação dinâmica.

Ela influencia:

* Capacidade de publicar
* Poder de reportar
* Prioridade na rede
* Economia HPS

A reputação é:

* Transparente
* Ajustável
* Registrada
* Auditável

---

## 🪙 Economia HPS (Vouchers)

O HPS possui uma economia interna simples, mas robusta.

### HPS Vouchers

* Créditos digitais assinados
* Transferíveis
* Rastreáveis
* Usados para operações sensíveis

### Usos

* Uploads
* Registros DNS
* Contratos
* Proteção contra spam
* Prova de esforço (PoW)

Não é um sistema especulativo — é **funcional**.

---

## 🖥️ Interface Gráfica (Browser)

O Browser HPS oferece:

* Navegação visual
* Alertas claros
* Análise de contratos
* Comparação de versões
* Confirmações explícitas

A ideia é simples:

> O usuário **entende o que está assinando**.

---

## ▶️ Execução do Projeto

### Requisitos

* Python 3.10+
* Sistema operacional comum (Linux, Windows, macOS)

### Instalação de dependências

```bash
pip install aiohttp python-socketio cryptography pillow qrcode
```

### Iniciar servidor

```bash
python hps_server.py
```

### Iniciar navegador

```bash
python hps_browser.py
```

---

## 🧠 Filosofia do Projeto

O HPS parte de três princípios:

1. **Nada é confiável por padrão**
2. **Tudo deve ser verificável**
3. **Autoridade deve ser explícita, não implícita**

Não é uma plataforma de promessas.
É uma plataforma de **provas**.

---

## 📌 Status do Projeto

* Arquitetura funcional
* Sistema de contratos completo
* Segurança criptográfica madura
* Interface gráfica operacional
* Economia interna ativa
* Pronto para testes, forks e experimentação

---

## 📄 Licença & Créditos
Projeto criado pela [Thaís](https://github.com/op3ny) para a Hsyst Eleuthery! Verifique a licença em [https://github.com/Hsyst-Eleuthery/hps/blob/main/LICENSE.md](https://github.com/Hsyst-Eleuthery/hps/blob/main/LICENSE.md).
