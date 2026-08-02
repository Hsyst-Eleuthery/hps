# v5.0.1-server — Changelog

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

## Build

- Recompilado o servidor para as 3 plataformas em `builds/`:
  - `hps-server-win64.exe`
  - `hps-server-linux64`
- Build com `CGO_ENABLED=0` (driver `modernc.org/sqlite`, puro em Go) e `-trimpath`.
- `internal/core/codegen.go` regenerado via `go run scripts/generate_code_hash.go`:
  - `ServerCodeHash = 012924ed80aaf7661d13294a546d8a4fe08edff432b9c427afb983565993a1c5`
  - `ServerBuildTimestamp = 2026-08-02T22:59:37Z`

## Verificação

- `go build ./...` — OK
- `go vet ./internal/core/` — OK
- `go test ./...` — falhas pré-existentes de infraestrutura de teste (`sql: unknown driver "sqlite"`: os pacotes de teste não importam `modernc.org/sqlite`, registrado apenas em `main.go`), não relacionadas a esta mudança.
