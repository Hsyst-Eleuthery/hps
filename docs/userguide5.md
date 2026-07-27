# Rede Federada, Segurança e Auditoria

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** [userguide.md](userguide.md), [userguide2.md](userguide2.md), [userguide3.md](userguide3.md), [userguide4.md](userguide4.md)
**Próximo:** [userguide6.md](userguide6.md) (Aplicativos)

---

## Sumário

- [O que é uma rede federada?](#o-que-é-uma-rede-federada)
- [Servidores vs Clientes](#servidores-vs-clientes)
- [Handshake: o aperto de mão entre servidores](#handshake-o-aperto-de-mão-entre-servidores)
- [Protocolo 2S+1U+1M: o mínimo para a rede funcionar](#protocolo-2s1u1m-o-mínimo-para-a-rede-funcionar)
- [Monitoramento de estabilidade de nós](#monitoramento-de-estabilidade-de-nós)
- [Autenticação inter-servidores](#autenticação-inter-servidores)
- [Rate Limiting e anti-spam](#rate-limiting-e-anti-spam)
- [Sistema de Auditoria](#sistema-de-auditoria)
- [Cadeia de Auditoria (Audit Chain)](#cadeia-de-auditoria-audit-chain)
- [Score de Saúde do Servidor](#score-de-saúde-do-servidor)
- [Desafios de Comportamento (Behavior Challenges)](#desafios-de-comportamento-behavior-challenges)
- [Verificação de Integridade do Código](#verificação-de-integridade-do-código)
- [Supply Chain de Vouchers](#supply-chain-de-vouchers)
- [Como migrar de servidor](#como-migrar-de-servidor)
- [Segurança em camadas](#segurança-em-camadas)
- [Termos importantes](#termos-importantes)

---

## O que é uma rede federada?

Diferente de uma rede **centralizada** (um servidor manda em tudo) ou de uma rede **puramente P2P** (todo mundo é igual), o HPS usa um modelo **federado**.

### Analogia: países e embaixadas

Pense em cada servidor HPS como um **país**:

-   Cada país tem suas próprias leis (regras de moderação, taxas, etc.)
-   Países se reconhecem mutuamente (através do handshake)
-   Você pode "migrar" de um país para outro
-   Se um país se tornar hostil, você se muda
-   Países comerciam entre si (exchange)
-   Embora cada país seja independente, eles seguem regras básicas comuns (o protocolo HPS)

### Características da federação HPS

-   **Sem servidor mestre:** não existe um "servidor principal"
-   **Multi-servidor:** qualquer pessoa pode rodar um servidor
-   **Portabilidade:** sua identidade funciona em qualquer servidor
-   **Confiança variável:** servidores confiam mais ou menos uns nos outros
-   **Sincronização seletiva:** servidores escolhem o que compartilhar

---

## Servidores vs Clientes

### Servidor (Server)

-   Escrito em **Go** (linguagem de programação)
-   Roda em um servidor dedicado ou VPS
-   Armazena conteúdo, gerencia contratos, valida assinaturas
-   Mantém o banco de dados (SQLite)
-   Se comunica com outros servidores
-   Expõe APIs HTTP e WebSocket

### Clientes

-   **Browser:** aplicativo desktop (Windows/Linux) com interface gráfica
-   **CLI:** programa de linha de comando para automação
-   **Mobile:** aplicativo Android
-   **Wallet:** carteira Android standalone
-   **Miner:** minerador dedicado (GUI ou CLI)

A diferença principal: **clientes são seus, servidores são da rede**.

---

## Handshake: o aperto de mão entre servidores

Quando dois servidores querem se comunicar, eles fazem um **handshake** (aperto de mão digital).

### Por que handshake é necessário?

-   Para estabelecer confiança entre servidores
-   Para garantir que ninguém está se passando por outro servidor
-   Para criar um canal seguro de comunicação

### Como funciona

```
Servidor A                     Servidor B
    |                              |
    |--- POST /handshake/init ---->|  A envia: ID, nonce, chave pública
    |                              |  B verifica a identidade de A
    |<-- POST /handshake/response -|  B responde: nonce assinado
    |                              |  A verifica assinatura de B
    |--- POST /handshake/complete->|  A envia: nonce de B assinado
    |                              |  B verifica assinatura de A
    |<--------- Sucesso -----------|  Pronto! Confiança estabelecida
```

### Características do handshake

-   **Efêmero:** dura apenas 5 minutos (TTL = 300 segundos)
-   **Nonces aleatórios:** cada handshake usa números únicos
-   **Assinaturas RSA-PSS:** provam a identidade dos servidores
-   **Reautenticação periódica:** precisa renovar a cada 5 minutos

---

## Protocolo 2S+1U+1M: o mínimo para a rede funcionar

O **Protocolo 2S+1U+1M** define os requisitos mínimos para a operação completa da rede HPS:

**2 Servidores + 1 Usuário + 1 Minerador**

### Por que esse mínimo?

-   **2 Servidores:** para ter federação (um servidor só é um sistema centralizado)
-   **1 Usuário:** para validar que a rede atende usuários reais
-   **1 Minerador:** para sustentar a economia (criar vouchers)

### As 10 fases de segurança distribuída

1.  **Handshake efêmero:** servidores se autenticam com RSA-PSS e nonces
2.  **Confirmação cruzada de vouchers:** um segundo servidor valida vouchers
3.  **Travas anti-double-spend:** impede gasto duplo durante exchange
4.  **Assinatura dupla de conteúdo:** conteúdo registrado em dois servidores
5.  **Validação cruzada de transferências:** dois servidores verificam transferências
6.  **Monitoramento de estabilidade:** servidores são classificados como Estável, Degradado ou Instável
7.  **Geração de contratos de auditoria:** cada login gera contrato de auditoria
8.  **Verificação de integridade do código:** detecção de adulteração no servidor
9.  **Desafios de comportamento:** verificação de conformidade entre servidores
10. **Sistema completo de auditoria:** score de saúde de 0 a 100

---

## Monitoramento de estabilidade de nós

Cada servidor na rede monitora a **estabilidade** de outros servidores.

### Níveis de estabilidade

| Nível | Significado |
|---|---|
| **Estável** | Servidor responde normalmente, sem violações |
| **Degradado** | Servidor com problemas intermitentes ou violações recentes |
| **Instável** | Servidor com falhas graves ou múltiplas violações |

### Como a estabilidade é calculada

O servidor avalia:

-   Percentual de downtime
-   Quantidade de violações de contrato
-   Consistência das respostas
-   Histórico de handshakes
-   Participação em validações cruzadas

---

## Autenticação inter-servidores

Quando servidores trocam dados entre si, a comunicação é protegida.

### Headers de autenticação

Cada requisição entre servidores inclui:

| Header | O que contém |
|---|---|
| `X-HPS-Server-Address` | Endereço do servidor remetente |
| `X-HPS-Timestamp` | Carimbo de data/hora (validade de ±30 segundos) |
| `X-HPS-Nonce` | Número aleatório único (16-128 caracteres) |
| `X-HPS-Signature` | Assinatura dos dados da requisição |
| `X-HPS-Body-SHA256` | Hash do corpo da requisição |
| `X-HPS-Server-Public-Key` | Chave pública do servidor remetente |

### Proteção contra replay

Nonces são registrados e não podem ser reutilizados. Mesmo que alguém intercepte uma requisição, não pode repeti-la (replay attack) porque o nonce já foi "queimado".

### Verificação de timestamps

O timestamp é verificado contra o relógio do servidor. Diferenças maiores que 30 segundos são rejeitadas. Isso impede ataques com mensagens antigas.

---

## Rate Limiting e anti-spam

O HPS tem múltiplos mecanismos para evitar abuso.

### Token Bucket

Cada cliente tem um "balde de fichas". Cada ação consome uma ficha. Fichas se recuperam com o tempo. Se o balde esvazia, o cliente precisa esperar.

### Limites por ação

-   Upload: limite de taxa por IP
-   Exchange: limite de 10 requisições por 20 fichas (burst)
-   Login: limite de tentativas por minuto

### Bloqueio por excesso

Se um cliente excede os limites:

1.  Recebe resposta HTTP 429 (Too Many Requests)
2.  Fica bloqueado por um período
3.  O bloqueio aumenta com reincidência

### Bloqueio de minerador

Mineradores que têm **transferências pendentes não resolvidas** são bloqueados de minerar até resolverem as pendências. Isso incentiva boa conduta.

---

## Sistema de Auditoria

O HPS possui um sistema completo de auditoria que **registra tudo o que acontece** na rede.

### Contratos de auditoria

Cada evento importante gera um **contrato de auditoria** — um documento assinado que descreve o evento. Exemplos:

-   `audit_login`: gerado em cada login de usuário
-   `audit_check`: verificação periódica de estado
-   `exchange_*`: operações econômicas
-   `mint:*` e `burn:*`: criação e destruição de valor

### O que é auditado

-   Operações econômicas (mint, burn, exchange, distribuição)
-   Logins de usuários
-   Conexões entre servidores
-   Violações de contrato
-   Alterações de configuração
-   Integridade de conteúdo

---

## Cadeia de Auditoria (Audit Chain)

A **cadeia de auditoria** é um encadeamento de hashes — cada contrato de auditoria contém o hash do contrato anterior.

### Como funciona

```
Contrato 1: "Login de thais" → hash: aaa
Contrato 2: "Upload feito" → hash: bbb (contém hash aaa)
Contrato 3: "Transferência" → hash: ccc (contém hash bbb)
...
```

### Por que isso importa

-   **Imutabilidade:** se alguém tentar alterar um contrato antigo, todos os hashes subsequentes quebram
-   **Rastreabilidade:** você pode seguir a cadeia do início ao fim
-   **Detecção de adulteração:** qualquer alteração é detectada imediatamente

---

## Score de Saúde do Servidor

Cada servidor tem um **score de saúde** de 0 a 100.

### Como é calculado

O score considera:

-   **Estabilidade do nó:** peso maior
-   **Histórico de violações:** violações reduzem o score
-   **Tempo de atividade:** servidores com mais uptime têm score maior
-   **Participação na rede:** servidores que participam de validações cruzadas ganham pontos
-   **Consistência de dados:** divergências com outros servidores reduzem o score

### O que o score afeta

-   Servidores com score baixo são menos priorizados em sincronizações
-   Outros servidores podem desconfiar de dados vindos de servidores com score baixo
-   O score é público e auditável

---

## Desafios de Comportamento (Behavior Challenges)

O HPS tem um mecanismo onde servidores **desafiam** outros servidores a provar que estão se comportando corretamente.

### Como funciona

1.  Servidor A envia um **desafio** para Servidor B
2.  O desafio pode ser:
    -   "Me mostre o contrato X"
    -   "Verifique se o voucher Y é válido"
    -   "Confirme que o conteúdo Z existe"
3.  Servidor B responde com a prova
4.  Servidor A verifica a resposta

### Por que existe

-   Para detectar servidores maliciosos que escondem dados
-   Para garantir que servidores estão mantendo a integridade dos dados
-   Para aumentar a confiança na rede

---

## Verificação de Integridade do Código

O servidor HPS pode verificar se seu próprio código foi adulterado.

### Como funciona

1.  Na compilação, um **hash de código** é gerado
2.  Em runtime, o servidor verifica se o hash atual corresponde ao esperado
3.  Se o hash mudou (código alterado), uma violação é registrada

### Endpoints

-   `GET /server/integrity` — retorna o hash de integridade do servidor
-   `POST /server/challenge` — envia um desafio de comportamento
-   `GET /server/verify` — verifica o comportamento de um servidor

---

## Supply Chain de Vouchers

A **cadeia de suprimentos** (supply chain) de vouchers é um registro de todos os vouchers que já existiram.

### Como funciona

-   Cada voucher criado é registrado na supply chain
-   Cada voucher gasto é registrado como consumido
-   O "topo" (tip) da supply chain contém o hash do último evento
-   Qualquer pessoa pode verificar a supply chain completa

### Para que serve

-   **Auditar a economia:** ver quantos vouchers existem, quantos foram queimados
-   **Verificar autenticidade:** confirmar que um voucher realmente foi emitido por um servidor
-   **Anti-fraude:** detectar vouchers falsos

### Endpoints

-   `POST /voucher/supply-chain` — consultar a supply chain de um voucher
-   `GET /voucher/supply-chain-tip` — ver o topo atual da supply chain
-   `GET /supply/audit` — auditoria completa da supply chain

---

## Como migrar de servidor

Um dos benefícios da federação é que você pode mudar de servidor.

### O que você leva

-   Sua identidade (chave pública)
-   Seus vouchers (através de exchange)
-   Seus domínios (se o novo servidor os reconhecer)
-   Sua reputação (se o novo servidor sincronizar)

### Passo a passo

1.  Escolha um novo servidor (ex: `server2.hps.hsyst.org`)
2.  No Browser, vá em configurações > servidores
3.  Adicione o novo servidor
4.  Faça login no novo servidor (usando a mesma chave privada)
5.  Seus vouchers do servidor antigo podem ser transferidos via exchange
6.  Seus domínios precisam ser recadastrados (ou o novo servidor pode sincronizar)

### Limitações

-   Vouchers emitidos por um servidor **não são automaticamente aceitos** por outro
-   É necessário fazer exchange para converter vouchers
-   Domínios registrados em um servidor não aparecem automaticamente em outro
-   A reputação pode ou não ser transferida (depende da sincronização entre servidores)

---

## Segurança em camadas

O HPS adota uma abordagem de **segurança em camadas** (defense in depth):

### Camada 1: Criptografia

-   Dados em repouso: AES-256-GCM com chave derivada de senha
-   Dados em trânsito: TLS/HTTPS para cliente-servidor, handshake RSA-PSS para servidor-servidor
-   Assinaturas: ECDSA P-256

### Camada 2: Autenticação

-   Challenge-response para login
-   Handshake efêmero entre servidores
-   Headers de autenticação em toda comunicação inter-servidor

### Camada 3: Autorização

-   Verificação de assinatura em cada ação
-   Verificação de propriedade (só o dono pode transferir)
-   Rate limiting por IP e por usuário

### Camada 4: Auditoria

-   Tudo vira contrato
-   Cadeia de auditoria encadeada por hash
-   Supply chain de vouchers

### Camada 5: Detecção

-   Monitoramento de estabilidade
-   Desafios de comportamento
-   Verificação de integridade de código

### Camada 6: Resposta

-   Violações registradas como contrato
-   Reputação diminuída
-   Bloqueio de operações
-   Comunicação para a rede

---

## Termos importantes

| Termo | Definição simples |
|---|---|
| **Federação** | Rede de servidores independentes que cooperam |
| **Handshake** | Aperto de mão digital entre servidores |
| **Nonce** | Número aleatório usado uma única vez |
| **TTL** | Tempo de validade de algo (ex: handshake de 5 min) |
| **2S+1U+1M** | Mínimo para rede funcionar: 2 servidores, 1 usuário, 1 minerador |
| **Estabilidade** | Classificação de quão confiável é um servidor |
| **Supply Chain** | Cadeia de suprimentos de vouchers |
| **Score de Saúde** | Nota de 0 a 100 do servidor |
| **Replay Attack** | Ataque repetindo uma mensagem capturada |
| **Rate Limit** | Limite de requisições por período |
| **Token Bucket** | Algoritmo de controle de taxa |
| **Audit Trail** | Rastro de auditoria |
| **Audit Chain** | Cadeia de contratos de auditoria |
| **Behavior Challenge** | Desafio para verificar comportamento de servidor |
| **Migração** | Trocar de servidor mantendo identidade |

---

**Leia agora:** [userguide6.md](userguide6.md) — Aplicativos
