package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sync"
)

// ===========================================================================
// SISTEMA COMPLETO DE AUDITORIA DE COMPORTAMENTO DO SERVIDOR
// ===========================================================================
// Este sistema verifica se o servidor está agindo de forma honesta e correta.
// Cada operação é auditada e registrada para detecção de anomalias.
// ===========================================================================

// AuditEntry representa uma entrada no log de auditoria.
type AuditEntry struct {
	ID          string         `json:"id"`
	Timestamp   float64        `json:"timestamp"`
	Category    string         `json:"category"`
	Action      string         `json:"action"`
	Actor       string         `json:"actor"`
	Target      string         `json:"target"`
	Details     map[string]any `json:"details"`
	Hash        string         `json:"hash"`        // Hash desta entrada
	PrevHash    string         `json:"prev_hash"`   // Hash da entrada anterior (cadeia)
	Signature   string         `json:"signature"`   // Assinatura do servidor
}

// AuditAnomaly representa uma anomalia detectada.
type AuditAnomaly struct {
	ID          string  `json:"id"`
	Timestamp   float64 `json:"timestamp"`
	Severity    string  `json:"severity"` // "low", "medium", "high", "critical"
	Category    string  `json:"category"`
	Description string  `json:"description"`
	Evidence    any     `json:"evidence"`
	Resolved    bool    `json:"resolved"`
}

// MinerAssignmentAudit rastreia atribuições de mineradores.
type MinerAssignmentAudit struct {
	Miner           string  `json:"miner"`
	TransferCount   int     `json:"transfer_count"`
	TotalAmount     int     `json:"total_amount"`
	FirstAssignment float64 `json:"first_assignment"`
	LastAssignment  float64 `json:"last_assignment"`
	AvgTimeBetween  float64 `json:"avg_time_between"`
	IsSuspicious    bool    `json:"is_suspicious"`
	Reason          string  `json:"reason,omitempty"`
}

// FeeAuditEntry auditoria de cálculo de taxas.
type FeeAuditEntry struct {
	TransferID    string  `json:"transfer_id"`
	Amount        int     `json:"amount"`
	DeclaredFee   int     `json:"declared_fee"`
	ExpectedFee   int     `json:"expected_fee"`
	Matches       bool    `json:"matches"`
	FeeRate       float64 `json:"fee_rate"`
	MinFee        int     `json:"min_fee"`
	Timestamp     float64 `json:"timestamp"`
}

// VoucherAuditEntry auditoria de vouchers.
type VoucherAuditEntry struct {
	VoucherID       string  `json:"voucher_id"`
	Issuer          string  `json:"issuer"`
	Owner           string  `json:"owner"`
	Value           int     `json:"value"`
	IssuedAt        float64 `json:"issued_at"`
	HasSupplyChain  bool    `json:"has_supply_chain"`
	HasIssuerSig    bool    `json:"has_issuer_signature"`
	HasOwnerSig     bool    `json:"has_owner_signature"`
	IsValid         bool    `json:"is_valid"`
	ValidationErrors []string `json:"validation_errors,omitempty"`
}

var (
	auditMu          sync.Mutex
	auditChain       []AuditEntry
	auditAnomalies   []AuditAnomaly
	auditChainHash   string = "GENESIS"
)

// InitAuditChain inicializa a cadeia de auditoria.
func (s *Server) InitAuditChain() {
	auditMu.Lock()
	defer auditMu.Unlock()
	
	// Verificar se já existe cadeia no banco
	var count int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM audit_log`).Scan(&count)
	
	if count == 0 {
		// Criar entrada genesis
		genesis := AuditEntry{
			ID:        "genesis",
			Timestamp: now(),
			Category:  "system",
			Action:    "chain_initialized",
			Actor:     "system",
			Target:    "audit_chain",
			Details:   map[string]any{"server_id": s.ServerID},
			PrevHash:  "0000000000000000000000000000000000000000000000000000000000000000",
		}
		genesis.Hash = s.computeAuditHash(genesis)
		genesis.Signature = s.SignRawText(genesis.Hash)
		
		s.saveAuditEntry(genesis)
		auditChainHash = genesis.Hash
		log.Printf("audit chain initialized: hash=%s", auditChainHash[:16])
	}
}

// RecordAuditEvent registra um evento de auditoria.
func (s *Server) RecordAuditEvent(category, action, actor, target string, details map[string]any) string {
	auditMu.Lock()
	defer auditMu.Unlock()
	
	entry := AuditEntry{
		ID:        NewUUID(),
		Timestamp: now(),
		Category:  category,
		Action:    action,
		Actor:     actor,
		Target:    target,
		Details:   details,
		PrevHash:  auditChainHash,
	}
	
	entry.Hash = s.computeAuditHash(entry)
	entry.Signature = s.SignRawText(entry.Hash)
	
	s.saveAuditEntry(entry)
	auditChainHash = entry.Hash
	
	return entry.ID
}

// computeAuditHash calcula o hash de uma entrada de auditoria.
func (s *Server) computeAuditHash(entry AuditEntry) string {
	data := fmt.Sprintf("%s:%.0f:%s:%s:%s:%s:%s",
		entry.ID, entry.Timestamp, entry.Category, entry.Action,
		entry.Actor, entry.Target, entry.PrevHash)
	
	if entry.Details != nil {
		detailBytes, _ := json.Marshal(entry.Details)
		data += ":" + string(detailBytes)
	}
	
	h := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(h[:])
}

// saveAuditEntry salva uma entrada de auditoria no banco.
func (s *Server) saveAuditEntry(entry AuditEntry) {
	detailsJSON, _ := json.Marshal(entry.Details)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO audit_log
		(id, timestamp, category, action, actor, target, details, hash, prev_hash, signature)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.Timestamp, entry.Category, entry.Action,
		entry.Actor, entry.Target, string(detailsJSON), entry.Hash,
		entry.PrevHash, entry.Signature)
}

// ===========================================================================
// VERIFICAÇÕES ESPECÍFICAS DE COMPORTAMENTO
// ===========================================================================

// AuditMinerAssignment verifica se mineradores estão sendo atribuídos de forma justa.
func (s *Server) AuditMinerAssignment() []MinerAssignmentAudit {
	var results []MinerAssignmentAudit
	
	rows, err := s.DB.Query(`SELECT assigned_miner, COUNT(*) as cnt, SUM(amount), MIN(created_at), MAX(created_at)
		FROM monetary_transfers 
		WHERE assigned_miner IS NOT NULL AND assigned_miner != ''
		AND status IN ('signed', 'completed')
		GROUP BY assigned_miner
		ORDER BY cnt DESC`)
	if err != nil {
		return results
	}
	defer rows.Close()
	
	for rows.Next() {
		var miner string
		var count, totalAmount int
		var firstTs, lastTs float64
		if rows.Scan(&miner, &count, &totalAmount, &firstTs, &lastTs) != nil {
			continue
		}
		
		audit := MinerAssignmentAudit{
			Miner:           miner,
			TransferCount:   count,
			TotalAmount:     totalAmount,
			FirstAssignment: firstTs,
			LastAssignment:  lastTs,
		}
		
		// Calcular tempo médio entre atribuições
		if count > 1 {
			audit.AvgTimeBetween = (lastTs - firstTs) / float64(count-1)
		}
		
		// Detectar suspeitas
		totalTransfers := 0
		_ = s.DB.QueryRow(`SELECT COUNT(1) FROM monetary_transfers WHERE status IN ('signed', 'completed')`).Scan(&totalTransfers)
		
		if totalTransfers > 10 {
			// Se um minerador tem mais de 70% das transações = suspeito
			percentage := float64(count) / float64(totalTransfers) * 100
			if percentage > 70 {
				audit.IsSuspicious = true
				audit.Reason = fmt.Sprintf("Miner has %.1f%% of all assignments (threshold: 70%%)", percentage)
				s.recordAnomaly("high", "miner_concentration", 
					fmt.Sprintf("Miner %s has %.1f%% of assignments", miner, percentage), audit)
			}
			
			// Se tempo médio entre atribuições é muito curto (< 10 segundos)
			if audit.AvgTimeBetween < 10 && count > 5 {
				audit.IsSuspicious = true
				audit.Reason = fmt.Sprintf("Avg time between assignments: %.1fs (suspiciously fast)", audit.AvgTimeBetween)
				s.recordAnomaly("medium", "rapid_assignments",
					fmt.Sprintf("Miner %s getting assignments too fast", miner), audit)
			}
		}
		
		results = append(results, audit)
	}
	
	return results
}

// AuditFeeCalculation verifica se taxas estão sendo calculadas corretamente.
func (s *Server) AuditFeeCalculation() []FeeAuditEntry {
	var results []FeeAuditEntry
	
	rows, err := s.DB.Query(`SELECT transfer_id, amount, fee_amount, created_at
		FROM monetary_transfers 
		WHERE fee_amount > 0 AND status IN ('signed', 'completed')
		ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		return results
	}
	defer rows.Close()
	
	for rows.Next() {
		var transferID string
		var amount, feeAmount int
		var createdAt float64
		if rows.Scan(&transferID, &amount, &feeAmount, &createdAt) != nil {
			continue
		}
		
		// Calcular taxa esperada
		expectedFee := int(math.Ceil(float64(amount) * s.cfg.ExchangeFeeRate))
		if expectedFee < s.cfg.ExchangeFeeMin {
			expectedFee = s.cfg.ExchangeFeeMin
		}
		
		audit := FeeAuditEntry{
			TransferID:  transferID,
			Amount:      amount,
			DeclaredFee: feeAmount,
			ExpectedFee: expectedFee,
			Matches:     feeAmount == expectedFee,
			FeeRate:     s.cfg.ExchangeFeeRate,
			MinFee:      s.cfg.ExchangeFeeMin,
			Timestamp:   createdAt,
		}
		
		if !audit.Matches {
			s.recordAnomaly("high", "fee_mismatch",
				fmt.Sprintf("Transfer %s: declared=%d expected=%d", transferID, feeAmount, expectedFee), audit)
		}
		
		results = append(results, audit)
	}
	
	return results
}

// AuditVoucherIntegrity verifica integridade de vouchers.
func (s *Server) AuditVoucherIntegrity() []VoucherAuditEntry {
	var results []VoucherAuditEntry
	
	rows, err := s.DB.Query(`SELECT voucher_id, issuer, owner, value, issued_at, status
		FROM hps_vouchers 
		WHERE status = 'valid'
		ORDER BY issued_at DESC LIMIT 50`)
	if err != nil {
		return results
	}
	defer rows.Close()
	
	for rows.Next() {
		var voucherID, issuer, owner, status string
		var value int
		var issuedAt float64
		if rows.Scan(&voucherID, &issuer, &owner, &value, &issuedAt, &status) != nil {
			continue
		}
		
		audit := VoucherAuditEntry{
			VoucherID: voucherID,
			Issuer:    issuer,
			Owner:     owner,
			Value:     value,
			IssuedAt:  issuedAt,
		}
		
		// Verificar supply chain
		var chainCount int
		_ = s.DB.QueryRow(`SELECT COUNT(1) FROM voucher_supply_chain WHERE voucher_id = ?`, voucherID).Scan(&chainCount)
		audit.HasSupplyChain = chainCount > 0
		
		// Verificar assinaturas
		var issuerSig, ownerSig string
		err := s.DB.QueryRow(`SELECT issuer_signature, owner_signature FROM hps_vouchers WHERE voucher_id = ?`, voucherID).
			Scan(&issuerSig, &ownerSig)
		if err == nil {
			audit.HasIssuerSig = issuerSig != ""
			audit.HasOwnerSig = ownerSig != ""
		}
		
		// Validar
		audit.IsValid = audit.HasSupplyChain && audit.HasIssuerSig && audit.HasOwnerSig
		if !audit.IsValid {
			if !audit.HasSupplyChain {
				audit.ValidationErrors = append(audit.ValidationErrors, "missing_supply_chain")
			}
			if !audit.HasIssuerSig {
				audit.ValidationErrors = append(audit.ValidationErrors, "missing_issuer_signature")
			}
			if !audit.HasOwnerSig {
				audit.ValidationErrors = append(audit.ValidationErrors, "missing_owner_signature")
			}
			s.recordAnomaly("medium", "voucher_integrity",
				fmt.Sprintf("Voucher %s has integrity issues", voucherID), audit)
		}
		
		results = append(results, audit)
	}
	
	return results
}

// AuditStatisticsAccuracy verifica se estatísticas são precisas.
func (s *Server) AuditStatisticsAccuracy() map[string]any {
	nowTs := now()
	
	// Verificar consistência entre tabelas
	var userStats, minerStats, contentStats struct {
		declared int
		actual   int
	}
	
	// Usuários
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username != 'custody' AND username != 'owner'`).Scan(&userStats.actual)
	
	// Mineradores
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM miner_stats`).Scan(&minerStats.actual)
	
	// Conteúdo
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM content`).Scan(&contentStats.actual)
	
	// Verificar se há usuários fantasma (reputação mas sem registro)
	var ghostUsers int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM user_reputations ur
		WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.username = ur.username)`).Scan(&ghostUsers)
	
	// Verificar se há contratos órfãos
	var orphanContracts int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM contracts c
		WHERE c.content_hash != '' AND NOT EXISTS (SELECT 1 FROM content co WHERE co.content_hash = c.content_hash)`).Scan(&orphanContracts)
	
	inconsistencies := []string{}
	if ghostUsers > 0 {
		inconsistencies = append(inconsistencies, fmt.Sprintf("ghost_users:%d", ghostUsers))
	}
	if orphanContracts > 0 {
		inconsistencies = append(inconsistencies, fmt.Sprintf("orphan_contracts:%d", orphanContracts))
	}
	
	return map[string]any{
		"users":              userStats.actual,
		"miners":             minerStats.actual,
		"content":            contentStats.actual,
		"ghost_users":        ghostUsers,
		"orphan_contracts":   orphanContracts,
		"inconsistencies":    inconsistencies,
		"consistent":         len(inconsistencies) == 0,
		"timestamp":          nowTs,
	}
}

// recordAnomaly registra uma anomalia detectada.
func (s *Server) recordAnomaly(severity, category, description string, evidence any) {
	anomaly := AuditAnomaly{
		ID:          NewUUID(),
		Timestamp:   now(),
		Severity:    severity,
		Category:    category,
		Description: description,
		Evidence:    evidence,
	}
	
	auditMu.Lock()
	auditAnomalies = append(auditAnomalies, anomaly)
	auditMu.Unlock()
	
	// Salvar no banco
	evidenceJSON, _ := json.Marshal(evidence)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO audit_anomalies
		(id, timestamp, severity, category, description, evidence, resolved)
		VALUES (?, ?, ?, ?, ?, ?, 0)`,
		anomaly.ID, anomaly.Timestamp, anomaly.Severity, anomaly.Category,
		anomaly.Description, string(evidenceJSON))
	
	log.Printf("ANOMALY DETECTED [%s]: %s - %s", severity, category, description)
}

// GetAuditAnomalies retorna anomalias não resolvidas.
func (s *Server) GetAuditAnomalies(severity string) []AuditAnomaly {
	var anomalies []AuditAnomaly
	
	query := `SELECT id, timestamp, severity, category, description, evidence, resolved
		FROM audit_anomalies WHERE resolved = 0`
	args := []any{}
	
	if severity != "" {
		query += ` AND severity = ?`
		args = append(args, severity)
	}
	
	query += ` ORDER BY timestamp DESC LIMIT 100`
	
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return anomalies
	}
	defer rows.Close()
	
	for rows.Next() {
		var a AuditAnomaly
		var evidenceJSON string
		var resolved int
		if rows.Scan(&a.ID, &a.Timestamp, &a.Severity, &a.Category, 
			&a.Description, &evidenceJSON, &resolved) == nil {
			a.Resolved = resolved != 0
			json.Unmarshal([]byte(evidenceJSON), &a.Evidence)
			anomalies = append(anomalies, a)
		}
	}
	
	return anomalies
}

// GetAuditChain retorna as últimas entradas da cadeia de auditoria.
func (s *Server) GetAuditChain(limit int) []AuditEntry {
	var entries []AuditEntry
	
	rows, err := s.DB.Query(`SELECT id, timestamp, category, action, actor, target, 
		details, hash, prev_hash, signature
		FROM audit_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return entries
	}
	defer rows.Close()
	
	for rows.Next() {
		var e AuditEntry
		var detailsJSON string
		if rows.Scan(&e.ID, &e.Timestamp, &e.Category, &e.Action, &e.Actor,
			&e.Target, &detailsJSON, &e.Hash, &e.PrevHash, &e.Signature) == nil {
			json.Unmarshal([]byte(detailsJSON), &e.Details)
			entries = append(entries, e)
		}
	}
	
	return entries
}

// VerifyAuditChainIntegrity verifica se a cadeia de auditoria está íntegra.
func (s *Server) VerifyAuditChainIntegrity() map[string]any {
	rows, err := s.DB.Query(`SELECT id, timestamp, category, action, actor, target, 
		details, hash, prev_hash, signature
		FROM audit_log ORDER BY timestamp ASC`)
	if err != nil {
		return map[string]any{"valid": false, "error": err.Error()}
	}
	defer rows.Close()
	
	var prevHash string = "0000000000000000000000000000000000000000000000000000000000000000"
	entries := 0
	broken := 0
	
	for rows.Next() {
		var e AuditEntry
		var detailsJSON string
		if rows.Scan(&e.ID, &e.Timestamp, &e.Category, &e.Action, &e.Actor,
			&e.Target, &detailsJSON, &e.Hash, &e.PrevHash, &e.Signature) != nil {
			continue
		}
		
		entries++
		
		// Verificar encadeamento
		if e.PrevHash != prevHash {
			broken++
		}
		
		// Verificar hash
		json.Unmarshal([]byte(detailsJSON), &e.Details)
		expectedHash := s.computeAuditHash(e)
		if e.Hash != expectedHash {
			broken++
		}
		
		// Verificar assinatura
		if !VerifyRawTextSignature(e.Hash, e.Signature, base64.StdEncoding.EncodeToString(s.PublicKeyPEM)) {
			broken++
		}
		
		prevHash = e.Hash
	}
	
	return map[string]any{
		"valid":           broken == 0,
		"total_entries":   entries,
		"broken_entries":  broken,
		"chain_hash":      auditChainHash,
	}
}

// RunFullAudit executa uma auditoria completa e retorna resultados.
func (s *Server) RunFullAudit() map[string]any {
	startTime := now()
	
	// 1. Auditoria de atribuição de mineradores
	minerAudit := s.AuditMinerAssignment()
	suspiciousMiners := 0
	for _, m := range minerAudit {
		if m.IsSuspicious {
			suspiciousMiners++
		}
	}
	
	// 2. Auditoria de cálculo de taxas
	feeAudit := s.AuditFeeCalculation()
	feeMismatches := 0
	for _, f := range feeAudit {
		if !f.Matches {
			feeMismatches++
		}
	}
	
	// 3. Auditoria de vouchers
	voucherAudit := s.AuditVoucherIntegrity()
	invalidVouchers := 0
	for _, v := range voucherAudit {
		if !v.IsValid {
			invalidVouchers++
		}
	}
	
	// 4. Auditoria de estatísticas
	statsAudit := s.AuditStatisticsAccuracy()
	
	// 5. Verificar cadeia de auditoria
	chainAudit := s.VerifyAuditChainIntegrity()
	
	// 6. Buscar anomalias
	anomalies := s.GetAuditAnomalies("")
	criticalAnomalies := 0
	for _, a := range anomalies {
		if a.Severity == "critical" || a.Severity == "high" {
			criticalAnomalies++
		}
	}
	
	// Calcular score de saúde (0-100)
	healthScore := 100.0
	healthScore -= float64(suspiciousMiners) * 10
	healthScore -= float64(feeMismatches) * 5
	healthScore -= float64(invalidVouchers) * 3
	healthScore -= float64(criticalAnomalies) * 15
	if !statsAudit["consistent"].(bool) {
		healthScore -= 20
	}
	if !chainAudit["valid"].(bool) {
		healthScore -= 25
	}
	if healthScore < 0 {
		healthScore = 0
	}
	
	elapsed := now() - startTime
	
	result := map[string]any{
		"health_score":        healthScore,
		"elapsed_seconds":     elapsed,
		"timestamp":           now(),
		
		"miner_assignment": map[string]any{
			"total_miners":      len(minerAudit),
			"suspicious_miners": suspiciousMiners,
			"details":           minerAudit,
		},
		
		"fee_calculation": map[string]any{
			"total_checked":   len(feeAudit),
			"mismatches":      feeMismatches,
			"details":         feeAudit,
		},
		
		"voucher_integrity": map[string]any{
			"total_checked":   len(voucherAudit),
			"invalid":         invalidVouchers,
			"details":         voucherAudit,
		},
		
		"statistics": statsAudit,
		"audit_chain": chainAudit,
		
		"anomalies": map[string]any{
			"total":              len(anomalies),
			"critical":           criticalAnomalies,
			"recent":             anomalies[:min(10, len(anomalies))],
		},
	}
	
	// Registrar auditoria completa
	s.RecordAuditEvent("system", "full_audit", "system", "server", map[string]any{
		"health_score": healthScore,
		"suspicious_miners": suspiciousMiners,
		"fee_mismatches": feeMismatches,
		"invalid_vouchers": invalidVouchers,
	})
	
	return result
}
