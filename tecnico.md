# AVISO
- Este projeto não é open-source, verifique a [licença](https://github.com/Hsyst-Eleuthery/hps/blob/main/LICENSE.md) antes de executar ou replicar


# 0. Introdução
O HPS, como está escrito hoje no código, é mais do que “um programa que roda em Python”: ele é um esqueleto completo de infraestrutura, com regras próprias de identidade, contratos, economia, DNS e validação distribuída. O manual abaixo tenta explicar isso de forma técnica, mas fluida, usando o próprio código como referência, e deixando clara a filosofia por trás das escolhas — inclusive a da licença.

---

## 1. Visão técnica geral do HPS

Do ponto de vista de engenharia, o HPS é um **protocolo P2P com implementação de referência em Python**, estruturado em dois grandes componentes: o servidor (`hps_server.py`) e o navegador/cliente (`hps_browser.py`). O servidor expõe uma API HTTP + Socket.IO, mantém o estado persistente em um banco SQLite, gerencia contratos, DNS, economia e reputação, e sincroniza com outros servidores de rede. O navegador implementa uma interface gráfica em Tkinter, cuida das chaves locais do usuário, assina contratos, apresenta diálogos de segurança e guia a interação com a rede.

Não há um “nó central”; a própria estrutura de tabelas como `server_nodes`, `known_servers` e o mecanismo de `periodic_ping` mostram que cada instância de servidor observa e mede os outros, marcando nós inativos, ajustando reputação e mantendo uma visão emergente da rede, não um grafo hierárquico com raiz única. 

Isso já estabelece o espírito do sistema: cada servidor decide com quem fala, que conteúdo aceita e como interage; cada usuário escolhe em qual servidor confia. Não existe uma autoridade global que possa “apertar um botão” e redefinir tudo.

---

## 2. Identidade, chaves e modelo de confiança

No HPS, a identidade de um usuário não é um e-mail, um telefone ou um CPF; é, essencialmente, o par de chaves criptográficas mantido no lado do cliente (`public_key_pem` e a chave privada correspondente). O navegador salva esses artefatos em um diretório próprio (`~/.hps_browser`), junto com o banco local que registra vouchers, relatórios e estado de carteira.

Cada ação importante que o usuário realiza no sistema — publicar conteúdo, aceitar contratos de uso, fazer transferências de HPS, certificar ou reportar conteúdo — passa por algum tipo de assinatura no cliente, que depois é verificada no servidor. Quando o cliente constrói, por exemplo, um “contrato de uso” a partir de um texto de termos enviado pelo servidor, ele insere a identidade do usuário e deixa um campo para assinatura; em seguida, o `ContractDialog` aplica a assinatura digital antes de enviar o contrato de volta, garantindo que aquela aceitação é inequívoca e vinculada à chave daquele usuário.

Esse modelo elimina a necessidade de confiar em cadastros externos: o servidor não precisa “acreditar” em quem você diz ser, ele apenas confere se a chave privada que você controla corresponde à chave pública que você apresentou e às assinaturas que está emitindo. A confiança passa a ser um produto de criptografia e de histórico, não de documentos.

---

## 3. Conteúdo, contratos e o ciclo de vida de uma publicação

Quando o usuário faz upload de um arquivo no navegador, a interface guia um fluxo relativamente sofisticado, mas que, visto de perto, segue uma lógica simples. O cliente calcula um hash SHA-256 do conteúdo, coleta metadados (nome, MIME, descrição, eventualmente também informações de APP/API ou pedidos de transferência), e em seguida organiza esses dados em um “pacote” que será publicado.

Do lado do servidor, a função de publicação trata esse conteúdo considerando uma série de regras:
– valida tamanho, quota de disco e limite máximo de itens por usuário;
– detecta se aquele upload é uma operação especial (como uma mudança de DNS ou atualização de API App, guiada por títulos como `'(HPS!dns_change){...}'`);
– avalia se existem contratos associados à ação (por exemplo, contratos de transferência ou de alteração de domínio);
– grava o arquivo em disco, registra a entrada na tabela `content` e possivelmente propaga o conteúdo para outros servidores da rede.

Além disso, há um sistema de contratos persistentes, armazenados na tabela `contracts` com campos como `action_type`, `content_hash`, `domain`, `username`, assinatura e o próprio conteúdo do contrato em Base64. O servidor expõe handlers de busca de contratos por hash, domínio, usuário ou tipo de ação, permitindo auditar o histórico que levou um conteúdo ou domínio ao estado atual. 

O resultado é que nenhuma operação relevante existe como “mágica do sistema”. Se um domínio mudou de dono, há um contrato para isso. Se um conteúdo foi certificado, denunciado ou reemitido, existe um objeto textual assinado descrevendo o que aconteceu. Essa rastreabilidade é o oposto da caixa-preta centralizada: qualquer nó ou usuário pode verificar, com base em dados que não dependem de confiança cega.

---

## 4. DNS descentralizado e fluxo de transferência de domínios

O subsistema de DNS do HPS é um dos exemplos mais claros de como o protocolo substitui estruturas tradicionais por regras contratuais explícitas. Registros são mantidos em `dns_records`, ligando `domain` a `content_hash`, usuário, dono original e assinatura. Quando um cliente solicita `/dns/<domain>`, o servidor responde com o hash apontado, o dono, a verificação e o dono original, desde que não haja violação contratual detectada. 

A alteração de dono de um domínio não é um simples “UPDATE” arbitrário. O fluxo usa um arquivo especial com cabeçalho padronizado (`# HSYST P2P SERVICE` e seções `### DNS:`...), onde constam campos como `NEW_DNAME` e `NEW_DOWNER`. O servidor valida esse formato, confere se o domínio existe, se o usuário atual tem legitimidade para trocá-lo (se é o dono, o custodiante ou o sistema) e cruza esses dados com um contrato correspondente, que deve citar o mesmo domínio.

Dependendo de quem envia a alteração, o domínio pode ser movido para um usuário-alvo, ou colocado em “custódia” (`CUSTODY_USERNAME`) enquanto aguarda que o novo dono aceite a transferência. Essa lógica é reforçada pela criação de registros de mudança (`dns_owner_changes`) e de “pending transfers”, garantindo que transições de posse sempre deixem trilha. Em paralelo, há um mecanismo de sincronização de DNS entre servidores (`sync_dns_with_server`), que busca registros remotos, baixa arquivos `.ddns`, verifica e insere apenas o que ainda não existe localmente. 

Na prática, isso equivale a um DNS “sem cartório central”, onde as disputas não são resolvidas por decreto de uma entidade única, mas por contratos verificáveis e pela escolha de cada servidor sobre o que aceita ou não replicar.

---

## 5. Prova de Trabalho, custo de operações e economia HPS

Um aspecto central do HPS é a maneira como ele trata recursos escassos: armazenamento, atenção da rede e capacidade de validação dos nós. Quase toda operação sensível — upload, registro de DNS, reporte de conteúdo, certificação ou invalidação de contrato, aceitação de contrato de uso, transferência de HPS — pode ser feita de duas formas:

1. O cliente realiza uma **prova de trabalho (PoW)** específica para aquela ação.
2. O cliente utiliza saldo de **HPS vouchers** para “comprar” a dispensa do PoW.

O navegador mantém um mapa `hps_pow_skip_costs` e rótulos (`hps_pow_skip_labels`) que definem, por exemplo, que pular o PoW de upload, DNS, reporte ou transferência de HPS custa um valor fixo (como 4 unidades HPS por operação).

Quando o usuário inicia um upload, por exemplo, o código prepara o conteúdo, calcula o hash, assina, e então chama `run_pow_or_hps("upload", start_pow, start_hps)`. Essa função oferece um caminho duplo: ou a máquina gasta CPU, resolvendo um desafio de PoW gerado pelo servidor, ou o usuário usa HPS que já possui para pagar pelo atalho. O mesmo padrão aparece no fluxo de reporte de conteúdo, aceitação de contrato de uso, transferência de HPS e outras ações críticas.

Do lado do servidor, existe um subsistema completo de vouchers HPS: a função `build_hps_voucher_payload` monta o payload com `value`, `issuer`, `owner`, informações de PoW, condições e timestamps; `create_voucher_offer` cria ofertas temporárias (`hps_voucher_offers`) que podem ser entregues ao cliente após mineração bem-sucedida, com expiração e status controlados.

O navegador mantém uma carteira local de vouchers (`browser_hps_vouchers`), atualizada via eventos como `hps_wallet_sync`. Quando essa carteira é recebida, o cliente atualiza o saldo, recalcula o poder de compra, registra relatórios de economia por servidor (incluindo `total_minted`, `multiplier` e taxas de troca) e até faz auditoria contra fraude, verificando consistência entre vouchers e relatórios.

A mineração também não é cega: o cliente gerencia status de mineração, bits de dificuldade, hashrate observado, total de tentativas, contagem de blocos minerados, e até mecanismos de **multas** para mineradores que falham em honrar responsabilidades — por exemplo, quando assumem uma transação e não a concluem corretamente. O servidor pode emitir “multas” que o cliente precisa pagar em HPS ou prometer pagar, sob pena de suspensão de mineração automática ou de outras proteções.

No conjunto, surge um sistema de incentivos em que:
– ações que consomem recursos precisam ser “pagas” com esforço computacional ou com valor econômico;
– mineradores são recompensados por prestar serviço, mas responsabilizados por abuso ou negligência;
– cada servidor pode reportar métricas próprias, possibilitando algo próximo a “mercados de câmbio” entre HPS emitidos por diferentes nós.

É um desenho que substitui coerção central por incentivos e penalidades distribuídos. Quem quer participar intensamente, paga com CPU ou com vouchers; quem abusa ou tenta explorar o sistema encontra limites econômicos, não apenas morais.

---

## 6. Reputação, reporte de conteúdo e auditoria da rede

A reputação do usuário é tratada como um recurso tão importante quanto o saldo HPS. Durante o login, o servidor envia, junto com o sucesso da autenticação, o valor da reputação atual do usuário, que o cliente exibe e usa como critério em operações como reporte de conteúdo. 

No fluxo de reporte, o navegador abre um `ContractDialog` para que o usuário revise e assine um contrato de denúncia, deixando claro o conteúdo reportado, o usuário alvo e a reputação de quem denuncia. Antes de enviar, o cliente verifica se a reputação é alta o bastante (por exemplo, impede denúncias se a reputação ficar abaixo de um limiar, como 20). Também confere se aquele usuário já reportou o mesmo conteúdo anteriormente, evitando spam de denúncias. Só então ele inicia o processo de PoW ou oferece a opção de pagar com HPS para priorizar o reporte. 

Do lado do servidor, contratos são avaliados contra possíveis violações: tanto arquivos quanto domínios passam por `evaluate_contract_violation_for_content` e `evaluate_contract_violation_for_domain`. Se um conteúdo for considerado incompatível com contratos ativos (por exemplo, por quebrar algum termo aceito), o servidor pode recusar o download via HTTP, explicitando o motivo (“contract_violation”) em vez de simplesmente sumir com o arquivo. 

Além disso, há toda uma camada de auditoria de servidores e carteira HPS: o navegador pode solicitar relatórios de economia, verificar multiplicadores de emissão, acompanhar a quantidade de HPS emitidos e cruzar isso com vouchers na carteira, detectando inconsistências e sinalizando possíveis fraudes. Isso reforça a ideia de que, numa rede sem centro, a vigilância não é privilégio de um órgão: ela é uma ferramenta de qualquer participante bem equipado.

---

## 7. Contratos de uso e responsabilidade mútua

Um ponto particularmente importante é a maneira como o HPS lida com **contratos de uso** entre usuário e servidor. Antes mesmo de concluir o login, o servidor pode exigir que o cliente aceite um contrato de uso específico, cujo texto é enviado em tempo real ao navegador. Este texto é então encapsulado em um template padronizado com seções `DETAILS`, `TERMS` e `START`, incluindo a identidade do usuário. Em seguida, o cliente assina o contrato e retorna ao servidor, novamente podendo escolher entre PoW e pagamento em HPS para validar essa aceitação.

Esse fluxo é uma forma bastante explícita de dizer: “a relação entre servidor e usuário é voluntária, bilateral e registrada”. O servidor não estabelece termos secretos; o usuário não finge que não leu. Ambos assumem um compromisso que pode ser auditado por terceiros.

Do ponto de vista filosófico, isso desloca o foco da obediência silenciosa para o consentimento informado. Se um servidor mudar as regras de forma abusiva, o contrato que o usuário aceitou pode ser comparado com o texto original, e a comunidade da rede pode escolher se continua se conectando àquele nó, se considera seus vouchers válidos ou se passa a evitá-lo. A sanção, aqui, vem de decisões de rota e de confiança, não de sanções centralizadas.

---

## 8. Navegador, experiência de uso e ergonomia de segurança

O `hps_browser.py` é um cliente pesado, mas feito com uma preocupação curiosamente rara: fazer o usuário **ver** o que está assinando. A classe `ContractDialog`, por exemplo, mostra o contrato inteiro, extrai um resumo interpretável (“ação”, “alvo”, “transferir para”, “app”, “título”), exibe um diff entre o template e o texto final e ainda controla um fluxo em duas etapas: primeiro aplica a assinatura, depois pede uma confirmação final com o documento já assinado, convidando o usuário a rejeitar se algo não parecer certo. 

Da mesma forma, há diálogos dedicados à segurança de conteúdo e de domínio: janelas que mostram o hash, o dono original, o autor atual, reputação, chave pública e assinatura, e deixam claro se existem violações contratuais registradas, se o conteúdo foi certificado, se passou por reemissões ou se é alvo de contratos inter-servidor.

O navegador também gerencia abas específicas para upload de conteúdo, ações HPS (transferência de arquivo, de HPS, de domínio, criação/atualização de API), mineração, economia, troca entre servidores e auditoria. Tudo isso a partir de um estado local persistente, que permite que o usuário mude de servidor sem perder completamente o histórico da sua carteira nem a visão da rede.

Em resumo, o cliente não trata o usuário como um “idiota clicador de botão”, mas como um agente que pode — e deve — entender o que está assinando, pagando e transferindo.

---

## 9. Sincronização entre servidores, limpeza e saúde da rede

No lado servidor, além dos handlers imediatos de publicação, DNS e contratos, existe um conjunto de tarefas periódicas que mantêm a rede saudável. A função `periodic_sync` lida com sincronização de conteúdo, contratos e DNS com outros servidores conhecidos; `periodic_cleanup` remove lixo: transações velhas, logs antigos, metadados órfãos, client files não sincronizados há mais de trinta dias. Já `periodic_ping` verifica regularmente se outros servidores estão ativos, ajustando reputação e estado (`is_online`, `is_active`) conforme as respostas.

Esses mecanismos evitam que a rede fique congestionada com nós zumbis ou registros obsoletos. Ao mesmo tempo, o modelo é suave: um servidor não “é expulso” por um centro; ele simplesmente perde reputação em outros nós, que passam a tratá-lo como desconectado ou pouco confiável até que volte a se comportar bem. De novo, é a lógica de incentivos distribuídos, não a de banimento monolítico.

---

## 10. A licença: por que tão restritiva para um projeto que quer ser livre?

A licença que acompanha o HPS pode parecer, à primeira vista, “dura demais” para um software que nasce com intenção de ser aberto e acessível. Ela estabelece que o uso gratuito é **por tempo limitado**, com possibilidade de cobrança futura; exige créditos explícitos e repetidos à autora e ao projeto original; proíbe o uso do nome e marca em forks sem autorização; obriga forks a distribuírem, lado a lado, a versão original; e prevê até perda do direito de manter forks infratores, com possibilidade de remoção forçada.

Isso não é um capricho nem uma contradição com a ideia de circulação livre. É, na prática, um instrumento de **auto-defesa jurídica e de preservação de autoria**, num cenário em que a própria arquitetura do HPS — descentralizada, auditável, resistente a censura — torna difícil controlar como terceiros vão usar o código.

Dois riscos aparecem claramente:

1. **Risco legal e reputacional**: alguém pode pegar o HPS, montar um serviço hostil à lei, ou claramente abusivo, e dizer que “isso é HPS”, tentando associar o nome da autora a usos que ela não aprova, ou arrastando o projeto para disputas jurídicas que nada têm a ver com a intenção original. A cláusula que proíbe o uso do nome, marca e identidade visual em forks sem autorização direta funciona como uma parede entre “o que a Thaís escreveu” e “o que terceiros fizeram usando o código”.

2. **Risco de apropriação indevida**: outro vetor clássico é um terceiro tentar capturar o projeto, limpar créditos, reempacotar como produto próprio, ou vender como se fosse obra original. Por isso, a licença exige créditos fortes, em destaque, com links para o repositório e para o site da Hsyst, e obriga que qualquer fork mantenha a versão original visível, acessível e claramente identificada. Assim, mesmo em cenários hostis, quem chegar a um fork tem caminho direto para o código fonte legítimo.

A possibilidade de cobrança futura, com prazo mínimo e sem retroatividade, serve menos como plano de negócios e mais como válvula de segurança: se o projeto crescer a ponto de gerar risco jurídico ou custo operacional significativo, a autora mantém um instrumento formal para ajustar o modelo sem precisar fingir que tudo é “para sempre gratuito”. Ao mesmo tempo, a estrutura da licença deixa claro que o **espírito** do projeto é aberto e comunitário; o texto fala de gratuidade, de desejo de acesso livre, e só admite mudanças sob responsabilidade explícita da autora, inclusive com espaço para a comunidade reagir publicamente.

Em outras palavras, a licença é restritiva para proteger a liberdade de desenvolvimento do projeto, e não para trancá-lo. Ela desincentiva apropriações predatórias e uso irresponsável da marca, ao mesmo tempo em que garante que o código em si possa ser estudado, copiado, modificado e replicado, desde que os créditos sejam preservados e o vínculo com o original não seja apagado.

---

## 11. Filosofia: incentivos, responsabilidade e soberania informacional

O HPS opera em cima de uma ideia recorrente: **ninguém é obrigado a confiar em ninguém, mas todos podem construir relações voluntárias baseadas em prova, histórico e benefício mútuo**.

Os elementos principais que você colocou no código caminham todos na mesma direção:

* Identidade baseada em chaves, não em cadastros comprados em bancos de dados.
* Contratos textuais, assinados, legíveis, com diff, resumo e trilha de auditoria.
* Economia local, onde quem consome recursos paga com esforço ou com valor, e quem presta serviço é recompensado — mas pode ser multado se abusar.
* DNS sem autoridade única, onde domínios mudam de dono por contrato, não por decisão de um registrador central.
* Reputação que cresce ou cai conforme ações observáveis, e não por critérios opacos.
* Licença que protege autoria e marca sem tentar controlar o que cada pessoa faz em sua própria máquina.

Tudo isso compõe um sistema em que a coerência não é garantida por um topo hierárquico, mas por incentivos desenhados no próprio protocolo: se um servidor emite HPS demais, a economia dele perde credibilidade e as taxas de câmbio ficam ruins; se um minerador não honra transações, acumula multas; se um usuário denuncia tudo por abuso, sua reputação cai e ele perde voz; se um fork tenta esconder a origem, a licença corta o direito de uso.

No limite, o HPS é um estudo de como combinar código, contratos, economia e reputação para permitir que pessoas e servidores cooperem **sem precisar de uma instância que mande em todo mundo**. A rede funciona enquanto houver gente disposta a conectar-se a alguém, aceitar contratos, pagar por recursos, validar provas e, principalmente, continuar fazendo as coisas de forma voluntária, explícita e auditável.
