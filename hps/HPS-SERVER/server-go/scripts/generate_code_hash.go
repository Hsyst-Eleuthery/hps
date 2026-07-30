// +build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Este script calcula o hash SHA256 de todos os arquivos .go e .sql
// e gera o arquivo codegen.go com o hash embutido.
//
// Uso: go run scripts/generate_code_hash.go
//
// O script deve ser executado ANTES de cada build para garantir
// que o hash corresponda ao código fonte atual.

const codegenTemplate = `package core

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
const ServerCodeHash = "%s"

// ServerCodeVersion é a versão do código para rastreamento.
const ServerCodeVersion = "v14.0.0"

// ServerBuildTimestamp é o timestamp da compilação (UTC).
const ServerBuildTimestamp = "%s"
`

func main() {
	// Coletar todos os arquivos .go e .sql relevantes
	var files []string
	
	// Encontrar todos os arquivos .go exceto codegen.go e scripts
	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		// Pular diretórios de vendor, scripts, e arquivos gerados
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == "scripts" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		
		// Incluir apenas arquivos .go e .sql (exceto codegen.go)
		if strings.HasSuffix(path, ".go") && !strings.Contains(path, "codegen.go") && !strings.Contains(path, "scripts/") {
			files = append(files, path)
		}
		if strings.HasSuffix(path, ".sql") {
			files = append(files, path)
		}
		
		return nil
	})
	
	// Ordenar para hash determinístico
	sort.Strings(files)
	
	// Calcular hash
	hasher := sha256.New()
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Erro lendo %s: %v\n", file, err)
			continue
		}
		hasher.Write(data)
		// Incluir path no hash para detectar renomeações
		hasher.Write([]byte(file))
	}
	
	hash := hex.EncodeToString(hasher.Sum(nil))
	timestamp := time.Now().UTC().Format(time.RFC3339)
	
	// Gerar codegen.go
	output := fmt.Sprintf(codegenTemplate, hash, timestamp)
	
	err := os.WriteFile("internal/core/codegen.go", []byte(output), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erro escrevendo codegen.go: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("✓ Code hash gerado: %s\n", hash)
	fmt.Printf("✓ Timestamp: %s\n", timestamp)
	fmt.Printf("✓ Arquivos hash: %d\n", len(files))
	fmt.Printf("✓ Arquivo gerado: internal/core/codegen.go\n")
	
	// Listar arquivos incluídos
	fmt.Println("\nArquivos incluídos no hash:")
	for _, f := range files {
		fmt.Printf("  - %s\n", f)
	}
}
