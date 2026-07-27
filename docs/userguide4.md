# DNS, Conteúdo e Publicação

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** [userguide.md](userguide.md), [userguide2.md](userguide2.md), [userguide3.md](userguide3.md)
**Próximo:** [userguide5.md](userguide5.md) (Rede e Segurança)

---

## Sumário

- [O que é DNS descentralizado?](#o-que-é-dns-descentralizado)
- [Domínios hps://](#domínios-hps)
- [Como registrar um domínio](#como-registrar-um-domínio)
- [DNS Dinâmico (DDNS)](#dns-dinâmico-ddns)
- [Publicação de Conteúdo](#publicação-de-conteúdo)
- [Hash: a impressão digital do arquivo](#hash-a-impressão-digital-do-arquivo)
- [Como o conteúdo é armazenado](#como-o-conteúdo-é-armazenado)
- [Busca e descoberta de conteúdo](#busca-e-descoberta-de-conteúdo)
- [Sincronização entre servidores](#sincronização-entre-servidores)
- [Assinatura dupla (dual signature)](#assinatura-dupla-dual-signature)
- [Verificação de integridade](#verificação-de-integridade)
- [Censura: como o HPS protege contra](#censura-como-o-hps-protege-contra)
- [Redirecionamento de conteúdo](#redirecionamento-de-conteúdo)
- [Contratos de violação](#contratos-de-violação)
- [Proxy: navegando hps:// de qualquer browser](#proxy-navegando-hps-de-qualquer-browser)
- [Termos importantes](#termos-importantes)

---

## O que é DNS descentralizado?

DNS significa **Domain Name System** (Sistema de Nomes de Domínio). É o sistema que traduz nomes fáceis de lembrar (como `google.com`) em números de IP (como `142.250.218.78`).

Na internet tradicional, o DNS é **centralizado**: empresas como a ICANN controlam os domínios `.com`, `.org`, etc. Você não é dono do seu domínio — você **aluga** ele de um registrar (GoDaddy, Namecheap...).

No HPS, o DNS é **descentralizado**:

-   Não existe uma autoridade central de domínios
-   Cada servidor mantém seus registros
-   Os registros são assinados e verificáveis
-   Você é **dono de verdade** do seu domínio
-   Pode transferir o domínio para outro usuário

---

## Domínios hps://

Os domínios no HPS usam o prefixo `hps://` em vez de `http://` ou `https://`.

### Exemplos

-   `hps://thais` — o site pessoal da Thaís
-   `hps://meublog` — seu blog
-   `hps://6dd7e54839da3f054e601af886b62f747aba300673bf2f2a9c224e680793382a` — acesso por hash (funciona sempre)

### Como um domínio funciona

Cada domínio `hps://` aponta para um **hash de conteúdo**. Quando você acessa `hps://meusite`:

1.  O Browser consulta o servidor: "qual o hash de `meusite`?"
2.  O servidor responde: "é `abc123...`"
3.  O Browser busca o conteúdo com hash `abc123...`
4.  O conteúdo é exibido

### Regras de domínio

-   Um domínio só pode ter um dono por vez
-   O dono pode transferir o domínio para outro usuário
-   O dono pode atualizar o conteúdo para qual o domínio aponta
-   Domínios não expiram (diferente de `.com` que você precisa renovar todo ano)

---

## Como registrar um domínio

### Pré-requisitos

-   Você precisa ter o HPS Browser instalado
-   Precisa ter uma conta (chave pública registrada)
-   Precisa ter vouchers HPS suficientes (ou poder minerar para pagar o PoW)

### Passo a passo

1.  **Prepare o conteúdo:** tenha o arquivo que será associado ao domínio
2.  **Publique o conteúdo:** faça upload pelo Browser (isso gera um hash)
3.  **Registre o domínio:** use a opção de registrar DNS, informando:
    -   O nome do domínio (ex: `meusite`)
    -   O hash do conteúdo
4.  **Pague o custo:** o PoW é resolvido automaticamente
5.  **Pronto:** agora `hps://meusite` aponta para seu conteúdo

### Custo

Registrar um domínio custa **4 unidades de PoW** (mais a taxa de inflação). O minerador do Browser resolve isso em alguns segundos.

### Transferência de domínio

Para transferir um domínio para outro usuário:

1.  Acesse o contrato do domínio
2.  Use a opção de transferência
3.  Informe a chave pública do novo dono
4.  Ambos assinam o contrato de transferência
5.  O domínio muda de dono

---

## DNS Dinâmico (DDNS)

O HPS também suporta **DDNS** (DNS Dinâmico) — conteúdo que muda com frequência.

### Para que serve?

-   Sites que atualizam constantemente (blogs, portais)
-   Conteúdo gerado dinamicamente
-   Aplicações web dentro do HPS

### Como funciona

Além do hash principal, o registro DNS pode ter um **ddns_hash** — um hash que aponta para conteúdo dinâmico. Esse conteúdo pode ser atualizado sem precisar recriar o registro DNS.

---

## Publicação de Conteúdo

Publicar no HPS é o ato de **armazenar um arquivo** no servidor e **registrar um contrato** comprovando a publicação.

### O que pode ser publicado?

Qualquer tipo de arquivo:

-   Páginas HTML (sites completos)
-   Imagens (JPEG, PNG, GIF)
-   Documentos (PDF, TXT)
-   Vídeos e áudio
-   Aplicações web
-   Qualquer dado digital

### Limites

-   **Tamanho máximo:** 100 MB por arquivo (configurável)
-   **Quota de disco:** cada usuário tem um limite (configurado pelo servidor)

### Processo de publicação

```
1. Selecionar arquivo → 2. Browser calcula hash → 3. Monta contrato de upload
→ 4. Browser assina contrato → 5. Envia arquivo + contrato → 6. Servidor verifica
→ 7. Servidor armazena (criptografado) → 8. Contrato registrado → 9. Hash retornado
```

---

## Hash: a impressão digital do arquivo

**Hash** é uma função matemática que transforma qualquer arquivo (de qualquer tamanho) em uma **sequência fixa de caracteres**.

### Características do hash

-   **Determinístico:** mesmo arquivo sempre produz o mesmo hash
-   **Unidirecional:** não dá para "reverter" o hash para recuperar o arquivo
-   **Avalanche:** mudar 1 bit do arquivo muda completamente o hash
-   **Tamanho fixo:** 64 caracteres (SHA-256), independente do tamanho do arquivo

### Para que serve no HPS

-   **Identificação:** cada conteúdo é identificado pelo seu hash
-   **Integridade:** qualquer um pode verificar se o conteúdo foi alterado
-   **Endereçamento:** você pode acessar conteúdo pelo hash (ex: `hps://abc123...`)
-   **Deduplicação:** se dois usuários publicam o mesmo arquivo, ele é armazenado uma vez só

---

## Como o conteúdo é armazenado

### No disco

Os arquivos são armazenados no diretório de arquivos do servidor, em subpastas organizadas por hash. Os nomes dos arquivos são os próprios hashes.

### Criptografia

Os arquivos são **criptografados** em disco usando AES-256-GCM. Mesmo que alguém tenha acesso físico ao servidor, não consegue ler o conteúdo sem a chave de armazenamento.

### Metadados

Além do arquivo, o servidor guarda metadados:

-   Hash
-   Título
-   Descrição
-   Tipo MIME (ex: `text/html`, `image/png`)
-   Tamanho
-   Usuário que publicou
-   Data de publicação
-   Chave pública do publicador
-   Número de replicações
-   Registros de integridade

---

## Busca e descoberta de conteúdo

### Por hash

O método mais básico: você sabe o hash, você acessa o conteúdo.

### Por domínio

`hps://nomedodominio` resolve para o hash registrado.

### Sincronização entre servidores

Quando você acessa um conteúdo que não está no servidor que você usa, o servidor pode:

1.  Verificar se conhece o conteúdo (tem no banco de dados)
2.  Se não tiver, perguntar para servidores conhecidos
3.  Se um servidor conhecido tiver, baixar e servir para você

### Endpoints de sincronização

O servidor expõe APIs para outros servidores consultarem:

-   `/sync/content` — lista de conteúdos
-   `/sync/dns` — lista de domínios
-   `/sync/users` — lista de usuários e reputações
-   `/sync/contracts` — lista de contratos

---

## Sincronização entre servidores

Servidores na rede HPS **compartilham** informações entre si.

### O que é sincronizado

-   Conteúdo (arquivos)
-   Registros DNS
-   Reputação de usuários
-   Contratos
-   Vouchers (para validação)
-   Estados de auditoria

### Como funciona

1.  Servidor A registra novo conteúdo
2.  Servidor A anuncia para servidores conhecidos
3.  Servidor B (conhecido) pode baixar e armazenar o conteúdo
4.  Servidor C (conhecido de B) também pode acessar
5.  A rede inteira eventualmente tem acesso

### Filtros de exposição

Nem todo conteúdo é exposto para toda a rede. O servidor verifica:

-   O emissor do conteúdo é confiável?
-   O servidor de origem é conhecido?
-   Existem violações de contrato associadas?

---

## Assinatura dupla (dual signature)

Um dos mecanismos mais importantes contra censura é a **assinatura dupla de conteúdo**.

### Como funciona

1.  Você publica conteúdo no Servidor A. O Servidor A gera um contrato assinado.
2.  O Servidor A pode **replicar** o conteúdo para o Servidor B.
3.  O Servidor B também gera um contrato assinado.
4.  O conteúdo agora tem **duas assinaturas** — uma de cada servidor.

### Por que isso ajuda contra censura

Se o Servidor A decide censurar seu conteúdo:

-   O conteúdo ainda existe no Servidor B
-   O contrato do Servidor A ainda existe, comprovando que ele um dia hospedou o conteúdo
-   A censura fica **visível**: qualquer um pode ver que o Servidor A deletou algo que tinha assinado
-   A reputação do Servidor A cai na rede

### Endpoints relacionados

-   `POST /content/register` — registrar conteúdo com assinatura
-   `POST /content/replicate` — replicar conteúdo para outro servidor
-   `GET /content/{hash}/registration` — verificar registros de um conteúdo

---

## Verificação de integridade

Periodicamente, o servidor **verifica** se os arquivos armazenados ainda estão íntegros.

### O que é verificado

-   O hash do arquivo corresponde ao hash registrado?
-   O arquivo não foi corrompido?
-   O arquivo tem um contrato válido associado?

### O que acontece se a verificação falhar

1.  O servidor detecta que o hash não confere
2.  Registra uma **violação de contrato**
3.  Tenta reparar: busca o conteúdo em servidores conhecidos
4.  Se não conseguir reparar, marca como corrompido

---

## Censura: como o HPS protege contra

O HPS tem múltiplas camadas de proteção contra censura:

### Camada 1: Múltiplos servidores

Você não depende de um único servidor. Se um te censura, você migra.

### Camada 2: Assinatura dupla

Seu conteúdo pode estar registrado em mais de um servidor.

### Camada 3: Contratos visíveis

Qualquer censura deixa rastro — o contrato de publicação original ainda existe.

### Camada 4: Reputação

Servidores que censuram perdem reputação na rede.

### Camada 5: Verificação pública

Qualquer pessoa pode verificar se um conteúdo foi adulterado comparando hashes.

---

## Redirecionamento de conteúdo

O HPS suporta **redirecionamento** de conteúdo — quando um arquivo é atualizado, o hash antigo pode redirecionar para o novo.

### Como funciona

1.  Você publica a versão 1 do seu site (hash: `aaa...`)
2.  Depois publica a versão 2 (hash: `bbb...`)
3.  Você registra que `aaa...` agora redireciona para `bbb...`
4.  Quem acessar `aaa...` recebe um aviso: "Conteúdo atualizado. Novo hash: bbb..."

### Headers de redirecionamento

Quando o Browser acessa um conteúdo desatualizado, o servidor retorna headers:

```
X-HPS-Newer-Hash: bbb...
X-HPS-Redirect: true
```

### Comportamento dos clientes

-   O HPS Browser **segue** o redirecionamento automaticamente
-   Outros clientes podem escolher entre o conteúdo antigo e o novo

---

## Contratos de violação

Quando algo está errado com um conteúdo ou domínio (ex: hash não confere), o servidor registra um **contrato de violação**.

### O que dispara uma violação

-   Hash não corresponde ao conteúdo armazenado
-   Conteúdo referenciado não existe
-   Assinatura do conteúdo não é válida
-   Domínio aponta para conteúdo removido
-   Servidor de origem não é mais confiável

### Consequências

-   O conteúdo/domínio fica bloqueado até resolução
-   Contrato de violação é registrado publicamente
-   Pode afetar a reputação do publicador

---

## Proxy: navegando hps:// de qualquer browser

O **HPS Proxy** é um componente que permite acessar conteúdo HPS de **navegadores comuns** (Chrome, Firefox, Edge).

### Como funciona

1.  Você acessa `http://proxy-hps:8080/hps://meusite`
2.  O Proxy recebe a requisição, entende que é um domínio HPS
3.  Consulta um servidor HPS para resolver o domínio
4.  Busca o conteúdo pelo hash
5.  Renderiza e serve como HTML/HTTP comum

### Para que serve

-   Pessoas que não têm o HPS Browser podem acessar conteúdo HPS
-   Facilita a transição da web tradicional para a HPS
-   Permite compartilhar links HPS com quem não usa o ecossistema

---

## Termos importantes

| Termo | Definição simples |
|---|---|
| **hps://** | Protocolo de domínio do HPS (como `http://`) |
| **Hash** | Impressão digital única do conteúdo |
| **SHA-256** | Algoritmo que calcula o hash |
| **DNS** | Sistema que traduz nomes em hashes |
| **DDNS** | DNS Dinâmico — para conteúdo que muda |
| **Registrar** | Associar um nome a um hash |
| **Resolver** | Descobrir o hash de um nome |
| **Proxy** | Ponte entre web tradicional e HPS |
| **Replicação** | Copiar conteúdo entre servidores |
| **Dual Signature** | Assinatura dupla (anti-censura) |
| **Redirecionamento** | Encaminhar de um hash antigo para um novo |
| **Violação** | Quando a integridade do conteúdo é quebrada |
| **Quota de disco** | Limite de armazenamento por usuário |

---

**Leia agora:** [userguide5.md](userguide5.md) — Rede Federada, Segurança e Auditoria
