# v5.0.1_server — Changelog

Data: 2026-08-02

## Correções

### Saldo da custódia drenando + `economy_update` parando de fluir

**Sintoma relatado:** após um tempo de funcionamento o servidor deixava de emitir `hps_economy_update`, e o saldo da custódia caía em vez de subir com as multas/PoW de mineração.

**Causa raiz:** `GetHpsPowCost()` era usado nos caminhos de **leitura** (`getHpsEconomyStatusPayload()` e `BuildEconomyReport()`), mas internamente chamava `ApplyCustodyDiscount(..., apply=true)`, que **debitava `custody_balance`** a cada invocação. Como `hps_economy_update` é emitido a cada mineração confirmada, cada emissão drenava a custódia para cada ação PoW com inflação — mais rápido do que as multas repunham. Além disso, o mesmo caminho disparava escritas pesadas (contratos, eventos econômicos e ofertas de subsídio a title holders) a cada emissão, sobrecarregando o handler.

**Arquivos alterados:**

- `internal/core/economy.go`
  - `GetHpsPowCost()` agora calcula o preço subsidiado **sem mutar estado**.
  - Nova função pura `ComputeCustodyDiscount(baseCost, inflatedCost)` — calcula o desconto da custódia sem efeitos colaterais.
  - O débito real da custódia continua **somente** no caminho de pagamento: `SpendHPSForAction` → `GetHpsPowCostWithDiscount(action, true)` → `ApplyCustodyDiscount`.

**Comportamento corrigido:**

- `custody_balance` agora só **aumenta** com multas/PoW (`AddCustodyFunds`) e só é debitada em gastos reais.
- `getHpsEconomyStatusPayload()` / `BuildEconomyReport()` voltaram a ser puros (leitura), aliviando o handler que emite após mineração.
- A recompensa de PoW (`GetHpsPowCostWithDiscount(action, false)`) e os demais gastos legítimos de custódia ficaram intactos.

### Seal/persistência quebrado no build `CGO_ENABLED=0`

**Sintoma relatado:** no encerramento do servidor:
```
server.go:353: WARN: final seal failed: create table sqlite_sequence: SQL logic error: object name reserved for internal use: sqlite_sequence (1)
```

**Causa raiz:** o caminho de persistência sem cgo (`sqlite_serialize_disabled.go`) reconstruía o schema copiando todos os objetos de `sqlite_master`, incluindo a tabela interna `sqlite_sequence` (criada por causa de `tx_id INTEGER PRIMARY KEY AUTOINCREMENT` em `internal/core/schema.sql:618`). O SQLite rejeita `CREATE TABLE sqlite_sequence(...)` por ser um nome reservado. Com o build anterior (cgo + `Serialize()` nativo) o problema não existia.

**Arquivo alterado:**

- `internal/core/sqlite_serialize_disabled.go`
  - No loop de criação do schema, objetos internos com prefixo `sqlite_` agora são ignorados (o estado do `sqlite_sequence` continua sendo copiado separadamente, preservando o AUTOINCREMENT).

## Build

- Recompilado o servidor para as 3 plataformas em `builds/`:
  - `hps-server-win64.exe`
  - `hps-server-linux64`
- Build com `CGO_ENABLED=0` (driver `modernc.org/sqlite`, puro em Go) e `-trimpath`.
- `internal/core/codegen.go` regenerado via `go run scripts/generate_code_hash.go`:
  - `ServerCodeHash = a27cc9266ba13ff725c7c79bc00df8d7d2b377eb4bb38ea9050c2318ae91f244`
  - `ServerBuildTimestamp = 2026-08-02T23:16:59Z`

## Verificação

- `go build ./...` — OK
- `go vet ./internal/core/` — OK
- `go test ./...` — falhas pré-existentes de infraestrutura de teste (`sql: unknown driver "sqlite"`: os pacotes de teste não importam `modernc.org/sqlite`, registrado apenas em `main.go`), não relacionadas a esta mudança.
