# Identidade e Contratos Digitais

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** [userguide.md](userguide.md) (visão geral)
**Próximo:** [userguide3.md](userguide3.md) (Economia e Mineração)

---

## Sumário

- [Identidade: quem é você no HPS?](#identidade-quem-e-você-no-hps)
- [Por que não usar email e senha?](#por-que-não-usar-email-e-senha)
- [Chave pública e chave privada (entendendo de verdade)](#chave-pública-e-chave-privada-entendendo-de-verdade)
- [Criptografia: o cadeado e a chave](#criptografia-o-cadeado-e-a-chave)
- [O perigo de perder sua chave privada](#o-perigo-de-perder-sua-chave-privada)
- [Como o HPS protege suas chaves](#como-o-hps-protege-suas-chaves)
- [Contratos Digitais: o que são e por que existem](#contratos-digitais-o-que-são-e-por-que-existem)
- [Anatômia de um contrato HPS](#anatômia-de-um-contrato-hps)
- [Tipos de contratos](#tipos-de-contratos)
- [Assinatura dupla de conteúdo (anti-censura)](#assinatura-dupla-de-conteúdo-anti-censura)
- [Verificação de contratos](#verificação-de-contratos)
- [Desafio-response (Challenge-Response)](#desafio-response-challenge-response)
- [O que acontece no servidor quando você assina algo](#o-que-acontece-no-servidor-quando-você-assina-algo)
- [Reputação: seu histórico como prova](#reputação-seu-histórico-como-prova)
- [Termos importantes](#termos-importantes)
- [Perguntas frequentes](#perguntas-frequentes)

---

## Identidade: quem é você no HPS?

No mundo real, sua identidade é definida por documentos (RG, CPF, passaporte), por características físicas (sua cara, sua voz) e por instituições que confirmam quem você é (governo, cartório).

No HPS, sua identidade é definida por **uma conta matemática**.

Brincadeira. Mas é quase isso. Sua identidade no HPS é definida por um **par de chaves criptográficas** — basicamente, dois números enormes que têm uma relação especial entre si. Um deles é público (todo mundo pode ver), o outro é privado (só você tem).

**Analogia:** Pense na sua chave privada como a **chave do seu apartamento**. A chave pública é como o **número do seu apartamento** no sistema de correspondência. Qualquer pessoa pode saber o número do seu apartamento e te mandar carta, mas só quem tem a chave física consegue entrar.

Diferente de um site normal onde você cria "usuário: fulano, senha: 123456", no HPS não existe um banco de dados central com sua senha. A prova de que você é você é **matemática**: você demonstra que possui a chave privada sem precisar mostrá-la.

### Como funciona na prática

1.  Você abre o HPS Browser pela primeira vez
2.  O programa **gera** automaticamente um par de chaves pra você
3.  A chave pública é enviada ao servidor quando você se registra
4.  A chave privada **nunca sai do seu computador** (ou celular)
5.  Quando você faz algo (publicar, transferir), o programa **assina** digitalmente a ação com sua chave privada
6.  O servidor **verifica** a assinatura usando sua chave pública

---

## Por que não usar email e senha?

Sistemas tradicionais de email+senha têm problemas fundamentais:

| Problema | Como acontece | No HPS |
|---|---|---|
| **Vazamento de dados** | A empresa que guarda sua senha pode ser hackeada | Sua chave privada nunca sai do seu dispositivo |
| **Banimento** | A plataforma pode te excluir sem explicação | Nenhum servidor pode te banir da rede inteira |
| **Censura** | A plataforma pode remover seu conteúdo | Seu conteúdo é assinado e pode ser verificado |
| **Espionagem** | A empresa lê suas mensagens/dados | Seus dados são criptografados |
| **Dependência** | Você precisa da plataforma pra acessar seu conteúdo | Você pode mudar de servidor |

**Mas tem um preço:** Não tem "esqueci minha senha". Se perder sua chave privada, sua identidade no HPS **acabou**. Não tem suporte técnico, não tem recuperação. É como perder a chave do cofre.

---

## Chave pública e chave privada (entendendo de verdade)

Vamos simplificar ainda mais.

### Chave Privada (PRIVATE KEY)

-   É um arquivo no seu computador/celular
-   **Nunca** deve ser compartilhado com ninguém
-   Quem tem a chave privada **é** o dono da identidade
-   Se alguém roubar sua chave privada, roubou sua identidade
-   O HPS guarda ela criptografada (protegida por senha)

### Chave Pública (PUBLIC KEY)

-   É como seu "número de conta"
-   Pode ser compartilhada à vontade
-   Serve para outros verificarem que uma assinatura veio de você
-   Fica registrada no servidor

### Assinatura Digital

Quando você "assina" algo no HPS:

1.  O sistema pega o conteúdo (um texto, um arquivo, uma transação)
2.  Aplica uma função matemática (hash) que gera uma "impressão digital" única
3.  Essa impressão é criptografada com sua chave privada
4.  O resultado é uma **assinatura digital** — um código único

Qualquer um com sua chave pública pode verificar que a assinatura é genuína.

---

## Criptografia: o cadeado e a chave

O HPS usa **dois tipos** de proteção criptográfica:

### Para guardar dados (em repouso)

Usa **AES-256-GCM** — imagina um cofre com segredo de 256 bits. É o mesmo padrão usado por governos e bancos. Protege:

-   O banco de dados do servidor
-   Suas chaves no disco
-   Arquivos armazenados

A senha que você escolhe no HPS passa por um processo chamado **PBKDF2-SHA256 com 210.000 iterações** — basicamente, mesmo que alguém descubra o arquivo criptografado, levaria uma eternidade para quebrar a senha.

### Para assinar (prova de autoria)

Usa **ECDSA P-256** — uma curva elíptica que gera assinaturas compactas e seguras. É tipo um carimbo digital que não pode ser falsificado.

### Para comunicação entre servidores

Usa **RSA-PSS** com **nonces** (números aleatórios usados uma única vez) e **TTL de 5 minutos** — as conversas entre servidores têm validade curta e são autenticadas a cada nova conversa.

---

## O perigo de perder sua chave privada

Isso é **tão importante** que merece uma seção só pra si.

Se você perder sua chave privada no HPS:

-   ❌ Perde acesso à sua conta
-   ❌ Perde seus vouchers (saldo)
-   ❌ Perde seus domínios registrados
-   ❌ Perde seu histórico de contratos
-   ❌ **Não há recuperação possível**

Compare com sistemas tradicionais:

| Situação | Facebook | HPS |
|---|---|---|
| Esqueceu a senha | "Esqueci minha senha" → email de recuperação | **Não existe** |
| Hackearam sua conta | Suporte restaura | Se roubaram a chave, acabou |
| Você perdeu o acesso | Verificação de identidade | **Não existe** |

### Como se proteger

1.  **Faça backup** da pasta de configuração do HPS Browser
2.  **Anote a senha** que você escolheu na primeira vez que abriu o Browser
3.  **Não compartilhe** arquivos de chave com ninguém
4.  Considere usar um **gerenciador de senhas** para guardar sua senha do HPS

> **Dica:** O HPS Browser armazena suas chaves na pasta de dados do aplicativo. Descubra onde ela fica e faça backup periódico.

---

## Como o HPS protege suas chaves

O HPS não te deixa totalmente desprotegido. Ele usa várias camadas de segurança:

### Separação de chaves

O servidor HPS tem **quatro chaves diferentes**:

| Chave | Função | O que acontece se vazar |
|---|---|---|
| **server_key** | Identidade do servidor na rede | Servidores param de confiar |
| **custody_key** | Operações econômicas (custódia) | Podem forjar transferências |
| **issuer_key** | Emissão de vouchers | Podem criar vouchers falsos |
| **storage_key** | Criptografia dos arquivos | Podem descriptografar dados |

Isso é tipo ter **quatro fechaduras diferentes** em quatro portas diferentes. Se uma for comprometida, as outras ainda estão seguras.

### Criptografia em repouso

Todos os dados sensíveis são criptografados antes de serem salvos no disco:

-   Arquivos de chave viram arquivos `.enc` com cabeçalho `HPSENC1`
-   Banco de dados pode ser inteiramente criptografado (modo `HPSDBENC1`)
-   No modo mais seguro, o banco de dados fica **na memória RAM** e é salvo criptografado no disco periodicamente

### Criptografia em trânsito

-   Conexões entre Browser e Server usam HTTPS/TLS
-   Conexões entre servidores usam handshake efêmero com assinaturas
-   Toda comunicação relevante é assinada

---

## Contratos Digitais: o que são e por que existem

Agora que você entende identidade, vamos ao que você **faz** com ela: **contratos digitais**.

Na internet tradicional, quando você posta uma foto no Instagram, o que acontece é:

> O banco de dados do Instagram registra: "Usuário 123 postou foto X às 14:30"

Isso é **invisível** pra você. Você não pode ver esse registro, não pode verificar se ele foi alterado, não pode provar que postou. O Instagram pode deletar, alterar ou esconder esse registro e você nunca vai saber.

No HPS, quando você publica algo, o que acontece é:

> É gerado um **documento de texto** estruturado que diz: "O usuário com chave pública Y publicou o conteúdo de hash Z às 14:30". Esse documento é **assinado digitalmente** por você, registrado no servidor, e pode ser **lido e verificado** por qualquer pessoa.

Isso é um **contrato digital**. Não é uma metáfora — é um arquivo de texto real com formato definido.

### Por que "contrato"?

Porque ele tem os elementos de um contrato real:

-   **Partes envolvidas** (quem está fazendo a ação)
-   **Objeto** (o que está sendo feito)
-   **Data** (quando foi feito)
-   **Assinatura** (prova de que as partes concordam)
-   **Testemunhas** (o servidor que registra)

### O que vira contrato no HPS?

Quase tudo que é relevante:

-   Upload de conteúdo
-   Registro de domínio DNS
-   Transferência de vouchers
-   Transferência de domínio
-   Denúncia de conteúdo
-   Aceite de termos
-   Operações de exchange
-   Eventos econômicos (mint, burn)
-   Auditorias

**Sem contrato = sem confiança.** Essa é a regra.

---

## Anatômia de um contrato HPS

Todo contrato HPS segue um formato padronizado. Veja um exemplo simplificado:

```
# HSYST P2P SERVICE
## CONTRACT:
### DETAILS:
# ACTION: upload
# PUBLIC_KEY: -----BEGIN PUBLIC KEY-----\n...
# CONTENT_HASH: a1b2c3d4e5f6...
# TIMESTAMP: 1712345678.123
### :END DETAILS
### START:
# USER: thais
# SIGNATURE: MEQCIHQ1k2...
### :END START
## :END CONTRACT
```

### O que cada parte significa

| Parte | Significado |
|---|---|
| `# HSYST P2P SERVICE` | Identifica que é um documento do ecossistema HPS |
| `## CONTRACT:` | Marca o início do contrato |
| `### DETAILS:` | Seção com os detalhes da ação |
| `# ACTION: upload` | O tipo de ação sendo contratada |
| `# PUBLIC_KEY: ...` | A chave pública de quem assina |
| `# CONTENT_HASH: ...` | Identificador único do conteúdo |
| `### :END DETAILS` | Fim da seção de detalhes |
| `### START:` | Seção de assinatura |
| `# USER: thais` | Nome de usuário de quem assina |
| `# SIGNATURE: ...` | A assinatura digital em base64 |
| `## :END CONTRACT` | Fim do contrato |

Esse formato é **legível por humanos** (você consegue ler e entender) e **parseável por máquinas** (o servidor consegue extrair os campos automaticamente).

---

## Tipos de contratos

O HPS reconhece diversos tipos de ação contratual:

### Publicação de conteúdo (`upload`)

Registra que um conteúdo foi publicado. Inclui o hash do arquivo (impressão digital), título, descrição, tipo de arquivo.

### Registro de DNS (`dns`)

Registra que um domínio `hps://` foi associado a um conteúdo. Inclui o domínio e o hash do conteúdo.

### Transferência de voucher (`hps_transfer`)

Registra a transferência de valor entre usuários ou para o sistema.

### Transferência de contrato (`contract_transfer`)

Transfere a propriedade de um contrato (por exemplo, um domínio) para outro usuário.

### Certificação (`contract_certify`)

Certifica que um contrato é válido e ativo.

### Denúncia (`report`)

Registra uma denúncia de violação de contrato.

### Uso de recursos (`usage_contract`)

Registra o uso de recursos do sistema.

### Eventos econômicos

-   `exchange_outgoing`: valor saindo do servidor
-   `exchange_incoming`: valor chegando no servidor
-   `distribution`: distribuição de valor para usuários
-   `custody_price_support`: subsídio de preço pela custódia
-   `phps_payout`: pagamento de título PHPS
-   `mint` e `burn`: criação e destruição de valor

### Auditoria

-   `audit_login`: contrato gerado automaticamente no login
-   `audit_check`: verificação periódica de auditoria
-   `hps_transfer_exchange`: operação de exchange entre servidores

---

## Assinatura dupla de conteúdo (anti-censura)

Um mecanismo importante do HPS é a **assinatura dupla de conteúdo**.

### O problema

Se você publica um conteúdo em apenas um servidor, esse servidor pode:

-   Deletar seu conteúdo
-   Impedir o acesso
-   Alterar metadados

### A solução

O HPS permite que você **registre o mesmo conteúdo em dois servidores diferentes**. Cada servidor assina o conteúdo com sua própria chave. Assim:

-   Se um servidor censurar, o conteúdo ainda existe no outro
-   Fica provado que o conteúdo existia em ambos os servidores
-   A censura fica visível e auditável

### Como funciona

1.  Você faz upload para o Servidor A
2.  O Servidor A registra o conteúdo e emite um contrato
3.  Você (ou o servidor) replica o conteúdo para o Servidor B
4.  O Servidor B também registra e assina
5.  Ambos os contratos ficam visíveis na rede

---

## Verificação de contratos

Quando alguém quer verificar se um contrato é válido, o processo é:

### Passo 1: Verificar estrutura

O contrato segue o formato padrão? Tem os cabeçalhos corretos? As seções estão completas?

### Passo 2: Verificar assinatura

A assinatura digital corresponde à chave pública declarada? Foi realmente o dono da chave quem assinou?

### Passo 3: Verificar integridade

O conteúdo referenciado existe? O hash confere? O conteúdo não foi adulterado?

### Passo 4: Verificar histórico

O contrato não conflita com outros contratos? O usuário não está tentando gastar o mesmo voucher duas vezes? O domínio já não foi transferido?

### Passo 5: Verificar reputação

O usuário que assinou tem reputação suficiente? Não está violando termos de uso?

---

## Desafio-Response (Challenge-Response)

Quando seu cliente (Browser, Mobile, CLI) se conecta ao servidor, ele precisa **provar** que possui a chave privada. O processo é:

1.  **Cliente:** "Oi, meu nome é thais, minha chave pública é X"
2.  **Servidor:** "Legal. Resolve esse desafio criptográfico pra provar que é você."
3.  **Cliente:** (usa a chave privada para assinar o desafio)
4.  **Servidor:** (verifica a assinatura com a chave pública) "Pode entrar!"

Isso impede que alguém se passe por você mesmo que descubra seu nome de usuário.

---

## O que acontece no servidor quando você assina algo

Vamos seguir o fluxo de uma publicação de conteúdo:

1.  **Você** seleciona um arquivo no HPS Browser
2.  **Browser** calcula o hash (impressão digital) do arquivo
3.  **Browser** monta o contrato: ação=upload, hash=..., chave=...
4.  **Browser** assina o contrato com sua chave privada
5.  **Servidor** recebe o arquivo e o contrato
6.  **Servidor** verifica sua assinatura
7.  **Servidor** verifica que o hash do arquivo confere
8.  **Servidor** verifica seu limite de disco e reputação
9.  **Servidor** armazena o arquivo e o contrato
10. **Servidor** registra o contrato no banco de dados
11. **Servidor** retorna o hash para você

Pronto. Seu conteúdo está publicado e há um contrato assinado provando isso.

---

## Reputação: seu histórico como prova

Além da identidade criptográfica, o HPS usa um sistema de **reputação**.

### Como funciona

-   Cada ação que você faz afeta sua reputação
-   A reputação é um número que sobe e desce
-   Usuários com reputação mais alta têm mais privilégios
-   Violações de contrato diminuem a reputação

### O que afeta a reputação

**Aumenta:**
-   Publicar conteúdo verificado
-   Manter vouchers válidos
-   Participar da rede de forma consistente
-   Completar transferências com sucesso

**Diminui:**
-   Tentativas de gasto duplo (double-spend)
-   Conteúdo fraudulento ou violador
-   Inatividade prolongada
-   Múltiplas tentativas de login falhas

### Por que reputação importa

-   Operações como upload e registro de DNS custam vouchers (queimam valor) — o custo pode ser menor para quem tem boa reputação
-   Usuários com reputação muito baixa podem ter operações bloqueadas
-   A reputação é **visível** e **auditável**

---

## Termos importantes

| Termo | Definição simples |
|---|---|
| **Chave Privada** | Arquivo secreto que prova sua identidade. Nunca compartilhe. |
| **Chave Pública** | Seu "endereço" na rede. Pode compartilhar. |
| **Assinatura Digital** | Carimbo matemático único que prova que você autorizou algo. |
| **Hash** | Impressão digital de um arquivo. Se mudar 1 letra, o hash muda completamente. |
| **Contrato** | Documento assinado registrando uma ação. |
| **DKVHPS** | Descriptografy Key for Vouchers of HPS — chave usada na proteção de vouchers. |
| **P2P** | Peer-to-Peer — rede onde múltiplos servidores cooperam sem um chefe. |
| **Federado** | Vários servidores independentes que se comunicam. |
| **Nonce** | Número aleatório usado uma única vez (pra evitar replay de mensagens). |
| **TTL** | Time-To-Live — tempo de validade de algo. |
| **ECDSA P-256** | Algoritmo de assinatura digital usado pelo HPS. |
| **AES-256-GCM** | Algoritmo de criptografia usado para proteger dados parados. |

---

## Perguntas frequentes

### "Se eu perder minha chave privada, perco tudo mesmo?"

Sim. Não há recuperação. Por isso o HPS te avisa várias vezes. **Faça backup.**

### "Alguém pode roubar minha chave privada?"

Teoricamente sim, se tiver acesso ao seu computador e à sua senha do HPS. Por isso as chaves ficam criptografadas no disco — mesmo que alguém roube o arquivo, precisa da senha.

### "O servidor sabe minha chave privada?"

**Não.** Sua chave privada nunca sai do seu dispositivo. O servidor só conhece sua chave pública.

### "Um contrato pode ser alterado depois de assinado?"

Não sem invalidar a assinatura. Qualquer alteração no texto do contrato muda o hash, e a assinatura antiga não vai mais ser válida.

### "Quantos contratos existem no HPS?"

Depende do uso, mas cada ação relevante gera um. Um usuário ativo pode gerar dezenas de contratos por dia.

---

**Leia agora:** [userguide3.md](userguide3.md) — Economia, Vouchers, PoW e Mineração
