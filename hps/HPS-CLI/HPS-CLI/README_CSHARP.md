# HPS-Cli Refatorado (C#)

Esta pasta agora possui uma entrada principal em C# (`hps-cli`) com arquitetura modular.

## Objetivo de paridade

- Comandos legados/duplicados foram removidos (ex.: `keys generate`, `dns-res`, `exchange refresh`, `sync push-content`).
- Comandos faltantes foram adicionados (`cancel`, `fraud-report`).
- O modo padrao agora e nativo C#.
- O modo Python legado foi removido.

## Arquitetura

- `Program.cs`: ponto de entrada.
- `Core/CliApplication.cs`: bootstrap da aplicacao.
- `Core/CliArguments.cs`: parser de modos (`--native`, `--native-pow-selftest`).
- `Native/Core/*`: shell e servicos de negocio do cliente nativo.
- `Native/Crypto/KeyPairManager.cs`: gerenciamento de chaves RSA no padrao do Browser C#:
  - `<user>.masterkey.hps`
  - `<user>.login.hps.key`
  - `<user>.local.hps.key`
  - chave de armazenamento local derivada da chave local (SHA-256 do PEM privado local).
- `Native/Storage/*`: estado local (servers, sessao, cache de conteudo/DDNS/contratos/vouchers).
- `Native/Pow/*`: solver PoW nativo em C#.
- `Native/Socket/*`: cliente Socket.IO (WebSocket/Engine.IO v4) para fluxos realtime.

## Modos de execucao

- `hps-cli ...`: modo nativo C# (padrao).
- `hps-cli --native --native-pow-selftest`: executa self-test do PoW nativo em C#.

## Comandos nativos atuais

- `whoami [username]`
- `login <server> <username> [passphrase]`
- `logout`
- `keys status [username]`
- `keys init <username>`
- `keys unlock <username>`
- `keys lock`
- `keys show`
- `keys export-public`
- `keys export <file_path>` (PEM da chave privada de login)
- `keys import <file_path>` (importa PEM da chave privada de login)
- `keys export-bundle <username> <output_path>`
- `keys import-bundle <username> <input_path>`
- `servers [list|add|remove|connect]`
- `use <indice|host:porta|url>`
- `history [limit]`
- `stats`
- `health`
- `server-info`
- `economy`
- `pow [bits] [target_seconds] [challenge_b64]`
- `pow threads [n]`
- `cancel content <hash>`
- `cancel dns <domain>`
- `cancel flow <kind> <target>`
- `resolve <dominio>`
- `get <dominio|hash>`
- `download <hash_or_url> [--output PATH]`
- `search <termo> [--type TYPE] [--sort ORDER]`
- `upload <file_path> [mime]`
- `dns-reg <domain> <hash>`
- `contract get <contract_id>`
- `contract search --type <all|hash|domain|user|type> --value <value> [--limit 50]`
- `contract analyze <contract_id>`
- `contract sign <action> <k=v,...> [out_file]`
- `contract verify <file_or_id> [pubkey]`
- `contract pending`
- `contract accept <transfer_id>`
- `contract reject <transfer_id>`
- `contract renounce <transfer_id>`
- `contract fix`
- `contract certify <contract_id>`
- `contract certify-missing <target> [--type domain|content]`
- `contract invalidate <contract_id>`
- `contract sync`
- `voucher get <voucher_id>`
- `voucher audit <id1,id2,...>`
- `voucher contract [voucher_id]`
- `voucher spend <contract_id>`
- `voucher verify <file_json>`
- `voucher list [limit]`
- `exchange validate <target_server> <id1,id2,...>`
- `exchange confirm [token_json_file]`
- `network`
- `security <content_hash>`
- `report <content_hash> <reported_user>`
- `fraud-report <server_address> <reason>`
- `actions transfer-file <content_hash> <target_user>`
- `actions transfer-domain <domain> <new_owner>`
- `actions transfer-api <app_name> <target_user> <file_path>`
- `actions api-app <app_name> <file_path>`
- `wallet refresh|list|show <voucher_id>`
- `wallet mint [--reason TEXT]`
- `wallet auto-mint on|off`
- `wallet transfer <target_user> <amount>`
- `wallet signature-monitor on|off`
- `wallet signature-auto on|off`
- `wallet auto-select on|off`
- `wallet fine-auto on|off`
- `wallet fine-promise on|off`
- `wallet sign-transfer <transfer_id>`
- `sync [limit]`
- `state`
- `clear`

## Criptografia local (paridade Browser C#)

- Chave mestra protegida por senha (`PBKDF2-SHA256 + AES-GCM`).
- Chave de login (RSA) protegida pela chave mestra.
- Chave local (RSA) protegida pela chave mestra.
- Conteudo/DDNS local cifrado com `AES-GCM` usando chave de armazenamento derivada da chave local.
- Payload local usa cabecalho magico `HPS2ENC1` para detectar dados cifrados.

## Observacoes

- Alguns fluxos realtime podem depender de regras do servidor (ex.: contrato de uso pendente), tal como no cliente original.
- Neste ambiente de sandbox, `dotnet build` pode falhar por bloqueio de rede ao NuGet (NU1301), entao a validacao final deve ser executada localmente fora do sandbox.
