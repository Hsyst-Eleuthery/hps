package core

// ===========================================================================
// CODEGEN - Hash embutido no compile-time
// ===========================================================================
// Este arquivo é GERADO automaticamente pelo script generate_code_hash.go
// NÃO EDITE manualmente - execute: go run scripts/generate_code_hash.go
//
// O hash é calculado ANTES da compilação e embutido como constante.
// Um servidor malicioso NÃO pode falsificar este hash porque:
// 1. O hash está hardcoded no binário compilado
// 2. Se o código for modificado, o hash mudará
// 3. O binário terá um hash diferente do source code
// ===========================================================================

// ServerCodeHash é o hash SHA256 do código fonte calculado no compile-time.
// Este valor é atualizado sempre que o código fonte é modificado.
const ServerCodeHash = "80f9322b0a246d60f3ecc5f45e02d82e69713a94a6d31ec0b2e38d89142981f4"

// ServerCodeVersion é a versão do código para rastreamento.
const ServerCodeVersion = "v14.0.0"

// ServerBuildTimestamp é o timestamp da compilação (UTC).
const ServerBuildTimestamp = "2026-07-16T23:02:41Z"
