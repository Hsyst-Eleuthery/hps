# Economia, Vouchers e Mineração

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** [userguide.md](userguide.md) e [userguide2.md](userguide2.md)
**Próximo:** [userguide4.md](userguide4.md) (DNS e Conteúdo)

---

## Sumário

- [O dinheiro do HPS: Vouchers](#o-dinheiro-do-hps-vouchers)
- [Analogia: o vale-refeição digital](#analogia-o-vale-refeição-digital)
- [Supply Cap: o limite de 1 milhão](#supply-cap-o-limite-de-1-milhão)
- [Lineage: o histórico de cada voucher](#lineage-o-histórico-de-cada-voucher)
- [DKVHPS: a chave secreta do voucher](#dkvhps-a-chave-secreta-do-voucher)
- [Proof of Work (PoW): o custo computacional](#proof-of-work-pow-o-custo-computacional)
- [Mineração: como criar vouchers](#mineração-como-criar-vouchers)
- [Custódia (Custody): o guardião da economia](#custódia-custody-o-guardião-da-economia)
- [Exchange: trocar valor entre servidores](#exchange-trocar-valor-entre-servidores)
- [PHPS: Títulos e investimentos](#phps-títulos-e-investimentos)
- [Taxas e custos das operações](#taxas-e-custos-das-operações)
- [Fluxo monetário completo](#fluxo-monetário-completo)
- [Anti-Double-Spend: o maior inimigo](#anti-double-spend-o-maior-inimigo)
- [Termos econômicos importantes](#termos-econômicos-importantes)

---

## O dinheiro do HPS: Vouchers

O HPS tem sua própria economia digital, baseada em **vouchers HPS**.

Pense num voucher como uma **nota de dinheiro digital**, mas diferente do dinheiro comum (que só tem um valor), cada voucher HPS carrega:

-   **Valor:** quantas unidades de HPS ele vale
-   **Dono:** quem é o proprietário atual
-   **Emissor:** qual servidor criou ele
-   **Motivo:** por que ele foi criado
-   **Data:** quando foi emitido
-   **Histórico completo (lineage):** de onde ele veio, quem eram os donos anteriores
-   **Assinaturas:** tanto do emissor quanto do dono atual
-   **Integridade:** um hash que garante que ninguém adulterou

### Para que servem os vouchers?

Tudo no HPS custa vouchers:

| Operação | Custo (em PoW) |
|---|---|
| Publicar conteúdo | 4 unidades |
| Registrar um domínio `hps://` | 4 unidades |
| Fazer denúncia | 4 unidades |
| Transferir contrato | 4 unidades |
| Resetar contrato | 4 unidades |
| Certificar contrato | 4 unidades |
| Transferir HPS | 4 unidades |
| Verificação de emissor | 2 unidades |
| Minerar (criar) vouchers | 12 unidades (PoW) |

### Por que existe um custo?

Para evitar **abuso**. Sem custo, pessoas mal-intencionadas poderiam:

-   Publicar milhões de arquivos inúteis (spam)
-   Registrar milhares de domínios
-   Sobrecarregar a rede

O custo em PoW (Proof of Work) exige que você **gaste poder computacional** para realizar operações. É como um pedágio: pequeno o suficiente para não atrapalhar usuários legítimos, mas grande o suficiente para impedir abusos.

---

## Analogia: o vale-refeição digital

Pense nos vouchers HPS como **vales-refeição**:

-   Cada vale tem um valor (R$ 20, R$ 50)
-   Cada vale tem um dono (seu nome está nele)
-   Cada vale tem um histórico (você sabe de que empresa veio)
-   Você pode gastar o vale em operações (como "comprar" um upload)
-   O vale não pode ser falsificado (tem assinatura digital)
-   O vale não pode ser gasto duas vezes (anti-double-spend)

**Diferença importante:** diferente de criptomoedas como Bitcoin, onde você tem UMA carteira com um saldo, no HPS cada voucher é um **objeto individual**. É como ter várias notas no bolso em vez de um cartão com saldo.

---

## Supply Cap: o limite de 1 milhão

O HPS tem um **limite máximo** de 1.000.000 (um milhão) de unidades HPS que podem ser mineradas. Esse é o **Supply Cap**.

### Por que um limite?

-   **Controle de inflação:** impede que valor infinito seja criado
-   **Escassez:** dá valor aos vouchers existentes
-   **Previsibilidade:** todo mundo sabe que no máximo 1 milhão de HPS existirão

### E quando atingir o limite?

Quando atingir 1 milhão de HPS minerados, **não será possível minerar novos vouchers**. A economia se torna puramente transacional — você só pode ganhar HPS através de transferências de outros usuários.

---

## Lineage: o histórico de cada voucher

Uma das características mais interessantes (e únicas) do HPS é a **lineage** (linhagem) dos vouchers.

### O que é lineage?

É a **árvore genealógica** de cada voucher. Assim como você pode rastrear sua ascendência (pais, avós, bisavós), cada voucher HPS pode ser rastreado até sua origem.

### O que a lineage registra

| Campo | Significado |
|---|---|
| `lineage_root_voucher_id` | ID do voucher raiz (o primeiro da linhagem) |
| `lineage_parent_voucher_id` | ID do voucher "pai" (de onde este veio) |
| `lineage_parent_hash` | Hash de integridade do voucher pai |
| `lineage_depth` | Quantas gerações desde a origem |
| `lineage_origin` | Origem: `pow_root` (minerado) ou `exchange_in` (exchange) |

### Por que lineage importa?

-   **Auditabilidade:** qualquer voucher pode ser rastreado até sua origem
-   **Anti-fraude:** fica impossível criar vouchers do nada
-   **Transparência:** a economia inteira pode ser auditada

---

## DKVHPS: a chave secreta do voucher

DKVHPS significa **Descriptografy Key for Vouchers of HPS**. O nome é estranho (é uma brincadeira interna do projeto), mas o conceito é importante.

### O que é o DKVHPS?

É uma **camada adicional de criptografia** que protege certos campos internos dos vouchers. Funciona assim:

-   Alguns campos do voucher são criptografados com o DKVHPS
-   Apenas quem tem a chave correta pode descriptografar
-   Diferentes partes têm diferentes níveis de acesso

### Por que existe?

-   **Privacidade:** nem todo campo do voucher precisa ser público
-   **Segurança:** impede que adulterem campos críticos
-   **Encadeamento:** a lineage usa DKVHPS para garantir integridade entre gerações

---

## Proof of Work (PoW): o custo computacional

**Proof of Work** (Prova de Trabalho) é um mecanismo que exige que o computador **resolva um problema matemático** antes de realizar uma ação.

### Como funciona

1.  O servidor gera um **desafio**: um número aleatório
2.  Seu computador precisa encontrar outro número que, combinado com o desafio, produza um hash com uma certa quantidade de zeros no início
3.  Quanto mais zeros são exigidos, mais difícil é o problema
4.  Quando você encontra a solução, envia para o servidor
5.  O servidor verifica em milissegundos

### Analogia

É como um **quebra-cabeça**: você gasta tempo (e energia) montando, mas quem confere se está certo gasta segundos.

### Dificuldade variável

A dificuldade do PoV se ajusta automaticamente:

-   **Baseado na ação:** upload é mais fácil (8 bits), mineração é mais difícil (12 bits)
-   **Baseado no histórico:** se você errou muitos desafios, a dificuldade aumenta
-   **Baseado no tempo:** o sistema tenta fazer cada desafio levar cerca de 20-30 segundos
-   **Baseado no hash rate:** seu computador reporta a velocidade, e o sistema ajusta

### Hash rate máximo

O servidor **não confia cegamente** no hash rate reportado pelo cliente. Existe um teto de **10 MH/s (10 milhões de hashes por segundo)** — mesmo que seu computador seja mais rápido, o sistema considera no máximo isso. Isso impede manipulação.

---

## Mineração: como criar vouchers

A mineração é o processo de **criar novos vouchers** resolvendo desafios de PoW.

### Quem pode minerar?

Qualquer usuário do HPS pode minerar, usando:

-   **HPS Miner** (aplicativo de desktop com interface gráfica)
-   **HPS CLI** (modo texto, para servidores)
-   **HPS Mobile** (mineração no celular Android, mais lenta)
-   **HPS Browser** (mineração integrada)

### Como funciona a mineração

1.  Você inicia o minerador
2.  Ele recebe um desafio PoW do servidor
3.  Começa a testar números (nonces) até encontrar a solução
4.  Quando encontra, envia a solução
5.  O servidor verifica e cria um voucher para você
6.  O voucher aparece na sua carteira

### Modos de mineração

**Modo Contínuo:** o minerador resolve desafios um atrás do outro sem parar. Você pode configurar quantas "threads" (linhas de processamento) usar — quanto mais threads, mais rápido, mas mais CPU/energia consome.

**Modo Agendado:** você configura horários para minerar (ex: só à noite quando o computador está ocioso).

### Configuração de threads

O minerador permite ajustar quantas threads de CPU usar:

-   **1-2 threads:** mineração leve, quase não impacta o computador
-   **4-8 threads:** equilíbrio entre velocidade e uso de recursos
-   **16+ threads:** máxima velocidade, computador fica mais lento para outras tarefas

No HPS Mobile (celular), há um **slider** (controle deslizante) para ajustar as threads.

---

## Custódia (Custody): o guardião da economia

O sistema de **custódia** (custody) é um mecanismo econômico que ajuda a estabilizar a economia.

### O que é Custody?

É uma **conta especial do sistema** que acumula vouchers e os usa para:

-   **Subsidiar preços:** quando a inflação aumenta os custos, a custódia cobre parte do aumento
-   **Garantir trocas:** em operações de exchange entre servidores, a custódia garante o valor
-   **Distribuir valor:** quando a custódia tem saldo, pode distribuir para usuários

### Como a custódia ganha dinheiro

-   Taxas de exchange
-   Compras de títulos PHPS
-   Multas de mineradores
-   Excedente de operações econômicas

### Subsídio de preço

Quando a inflação faria o custo de uma operação (ex: upload) subir, a custódia pode cobrir parte do aumento. É como um **seguro-preço**: o usuário não sente tanto a inflação.

---

## Exchange: trocar valor entre servidores

Exchange é o processo de **transferir valor de um servidor para outro**.

### Por que existe?

Se você tem vouchers emitidos pelo Servidor A e quer usar no Servidor B, precisa de exchange. Servidores diferentes são como "países" diferentes — cada um emite seus próprios vouchers.

### Como funciona

1.  **Validação:** o servidor de origem verifica seus vouchers, reserva eles e gera um **token** de exchange
2.  **Confirmação:** você confirma que quer prosseguir com a troca
3.  **Envio:** o servidor de origem consome (queima) seus vouchers e envia uma mensagem para o servidor de destino
4.  **Recebimento:** o servidor de destino recebe a mensagem, verifica, e emite novos vouchers para você
5.  **Completude:** a operação é registrada em contrato em ambos os servidores

### Taxa de exchange

O servidor cobra uma taxa sobre o valor trocado:

-   Taxa padrão: 2% do valor
-   Taxa mínima: 1 unidade HPS
-   A taxa vai para a custódia

### O que acontece se der erro?

Se o servidor de destino rejeitar a operação, os vouchers do servidor de origem **não são devolvidos** (anti-double-spend). Isso é proposital — evita que você tente gastar o mesmo voucher em dois lugares.

---

## PHPS: Títulos e investimentos

PHPS é um sistema de **títulos** que permite aos usuários investir na economia do servidor.

### O que são títulos PHPS?

São como **ações** de um servidor. Quando você compra um título PHPS:

-   Você paga um valor em vouchers HPS
-   Recebe um título que dá direito a uma **porcentagem** das taxas de exchange
-   Periodicamente, você recebe pagamentos (dividendos) proporcionais à sua participação

### Como comprar um título

1.  Acesse o **mercado PHPS** no HPS Browser
2.  Veja os títulos disponíveis
3.  Compre usando vouchers HPS
4.  O título aparece na sua carteira

### Como resgatar

Após comprar, você pode resgatar o valor do título após um período (7 dias). O resgate paga o valor original mais uma participação nos lucros.

### Dívidas PHPS

Quando um servidor não tem saldo suficiente para pagar um resgate, ele emite uma **dívida PHPS** — uma promessa de pagamento futuro. Essas dívidas são pagas quando o servidor receber novas receitas.

---

## Taxas e custos das operações

Cada operação no HPS tem um custo associado. Esses custos são dinâmicos e podem mudar com base na inflação e no saldo da custódia.

### Custos base (em unidades PoW)

| Operação | Custo Base |
|---|---|
| Upload | 4 |
| Registro de DNS | 4 |
| Denúncia (report) | 4 |
| Transferência de contrato | 4 |
| Reset de contrato | 4 |
| Certificação de contrato | 4 |
| Transferência de HPS | 4 |
| Verificação de emissor | 2 |
| Mineração (mint) | 12 |

### Como o custo é calculado

O custo final não é fixo. Ele é calculado assim:

```
custo_base × multiplicador_inflação - subsídio_custódia
```

O **multiplicador de inflação** reflete quanto já foi minerado. Quanto mais HPS existem, mais caro fica realizar operações — isso desestimula o acúmulo e incentiva a circulação.

---

## Fluxo monetário completo

Vamos seguir o ciclo de vida de um voucher desde a criação até o gasto:

### 1. Mineração (nascimento)

```
Minerador → Desafio PoW → Solução → Servidor valida → Voucher criado (origem: pow_root)
```

### 2. Posse

O voucher fica associado ao usuário que minerou. A chave pública dele é registrada como owner.

### 3. Transferência

Quando o usuário envia HPS para outro:
```
Remetente assina → Servidor verifica → Destinationário recebe novo voucher → voucher original marcado como "spent"
```

### 4. Exchange (troca de servidor)

```
Voucher A (Servidor X) → Validação → Token → Confirmação → Servidor Y emite novo voucher
```

### 5. Gasto (operações)

```
Usuário → Operação (upload, DNS, etc) → Voucher é "queimado" (burn) → Serviço é liberado
```

### 6. Queima (burn)

Quando um voucher é gasto em uma operação, ele é **queimado** — marcado como "spent" e não pode ser reutilizado. O total de HPS queimados é registrado nas estatísticas econômicas.

---

## Anti-Double-Spend: o maior inimigo

**Double-spend** (gasto duplo) é o maior problema de qualquer sistema de dinheiro digital: como garantir que a mesma nota não seja gasta duas vezes?

### Como o HPS resolve

1.  **Status de voucher:** cada voucher tem um status (`valid`, `reserved`, `spent`, `invalidated`). Um voucher "spent" não pode ser usado de novo.
2.  **Reserva:** durante operações (ex: exchange), os vouchers são marcados como "reserved" primeiro.
3.  **Transações atômicas:** operações críticas usam transações SQL que ou completam totalmente ou não acontecem.
4.  **Supply chain:** cada voucher tem entrada na cadeia de suprimentos, permitindo rastrear se ele já foi gasto.
5.  **Confirmação entre servidores:** exchange exige confirmação do servidor de destino antes de marcar como concluído.
6.  **Travas (locks):** mecanismos de lock de voucher impedem que dois processos gastem o mesmo voucher simultaneamente.

### O que acontece se alguém tentar gasto duplo?

-   A segunda tentativa falha
-   O usuário perde reputação
-   O contrato de violação é registrado
-   O usuário pode ser bloqueado de mineração

---

## Termos econômicos importantes

| Termo | Definição simples |
|---|---|
| **Voucher** | Unidade de valor digital no HPS |
| **PoW (Proof of Work)** | Prova de trabalho — custo computacional para realizar ações |
| **Minerar** | Resolver PoW para criar novos vouchers |
| **Mint** | Criar novo voucher (sinônimo de minerar) |
| **Burn** | Queimar voucher (gastar em operação) |
| **Supply Cap** | Limite máximo de 1 milhão de HPS |
| **Custódia** | Conta do sistema que estabiliza a economia |
| **Exchange** | Troca de valor entre servidores |
| **Lineage** | Árvore genealógica do voucher |
| **DKVHPS** | Chave de criptografia interna do voucher |
| **PHPS** | Títulos de investimento no servidor |
| **Subsídio** | Quando a custódia paga parte do custo de uma operação |
| **Thread** | Linha de processamento — mais threads = mineração mais rápida |
| **Nonce** | Número aleatório usado no PoW |
| **Double-spend** | Tentativa de gastar o mesmo voucher duas vezes |

---

**Leia agora:** [userguide4.md](userguide4.md) — DNS, Conteúdo e Publicação
