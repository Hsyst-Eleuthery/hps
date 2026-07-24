package core

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"time"
)

// ===========================================================================
// CHALLENGE-RESPONSE VERIFICATION
// ===========================================================================
// O servidor deve provar que está executando o código correto respondendo
// a desafios que requerem comportamento específico do código.
//
// Diferente do hash estático, isso verifica o COMPORTAMENTO real do servidor.
// Um servidor malicioso precisaria replicar toda a lógica para passar.
// ===========================================================================

// ChallengeType define o tipo de desafio.
type ChallengeType string

const (
	ChallengeCrypto      ChallengeType = "crypto"       // Teste de operações criptográficas
	ChallengeConsistency ChallengeType = "consistency"   // Verificação de consistência estatística
	ChallengeProtocol    ChallengeType = "protocol"     // Conformidade de protocolo
	ChallengeComputation ChallengeType = "computation"  // Cálculos específicos
)

// ChallengeRequest é um desafio enviado pelo cliente ao servidor.
type ChallengeRequest struct {
	Type      ChallengeType `json:"type"`
	Challenge string        `json:"challenge"`
	Data      map[string]any `json:"data,omitempty"`
	Timestamp float64       `json:"timestamp"`
}

// ChallengeResponse é a resposta do servidor ao desafio.
type ChallengeResponse struct {
	Success   bool    `json:"success"`
	Answer    string  `json:"answer"`
	Proof     string  `json:"proof,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	Timestamp float64 `json:"timestamp"`
}

// HandleChallengeResponse processa um desafio e retorna a resposta provando comportamento correto.
func (s *Server) HandleChallengeResponse(req ChallengeRequest) ChallengeResponse {
	nowTs := now()
	
	// Verificar timestamp (desafios expiram em 30 segundos)
	if math.Abs(nowTs-req.Timestamp) > 30 {
		return ChallengeResponse{
			Success:   false,
			Answer:    "challenge_expired",
			Timestamp: nowTs,
		}
	}
	
	switch req.Type {
	case ChallengeCrypto:
		return s.handleCryptoChallenge(req)
	case ChallengeConsistency:
		return s.handleConsistencyChallenge(req)
	case ChallengeProtocol:
		return s.handleProtocolChallenge(req)
	case ChallengeComputation:
		return s.handleComputationChallenge(req)
	default:
		return ChallengeResponse{
			Success:   false,
			Answer:    "unknown_challenge_type",
			Timestamp: nowTs,
		}
	}
}

// handleCryptoChallenge testa operações criptográficas do servidor.
func (s *Server) handleCryptoChallenge(req ChallengeRequest) ChallengeResponse {
	nowTs := now()
	challenge := req.Challenge
	
	if challenge == "" {
		return ChallengeResponse{Success: false, Answer: "missing_challenge", Timestamp: nowTs}
	}
	
	// O cliente envia um nonce, o servidor deve assinar e retornar
	// Isso prova que o servidor tem chaves criptográficas funcionais
	
	// 1. Assinar o desafio com a chave do servidor
	signature := s.SignRawText(challenge)
	if signature == "" {
		return ChallengeResponse{Success: false, Answer: "signing_failed", Timestamp: nowTs}
	}
	
	// 2. Calcular hash do challenge para prova
	h := sha256.Sum256([]byte(challenge + signature))
	proof := base64.StdEncoding.EncodeToString(h[:])
	
	// 3. Verificar que a assinatura é válida (auto-verificação)
	if !VerifyRawTextSignature(challenge, signature, base64.StdEncoding.EncodeToString(s.PublicKeyPEM)) {
		return ChallengeResponse{Success: false, Answer: "signature_invalid", Timestamp: nowTs}
	}
	
	return ChallengeResponse{
		Success:   true,
		Answer:    signature,
		Proof:     proof,
		Timestamp: nowTs,
		Details: map[string]any{
			"algorithm":    "RSA-PSS-SHA256",
			"key_verified": true,
		},
	}
}

// handleConsistencyChallenge verifica consistência estatística.
// O servidor deve retornar dados que fazem sentido juntos.
func (s *Server) handleConsistencyChallenge(req ChallengeRequest) ChallengeResponse {
	nowTs := now()
	
	// Coletar estatísticas
	var totalUsers, onlineUsers, totalContent, totalMiners, activeMiners, knownServers int
	
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username != 'custody' AND username != 'owner'`).Scan(&totalUsers)
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE last_activity > ? AND username != 'custody' AND username != 'owner'`, nowTs-300).Scan(&onlineUsers)
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM content`).Scan(&totalContent)
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM miner_stats`).Scan(&totalMiners)
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM miner_stats WHERE (banned_until IS NULL OR banned_until < ?) AND last_updated > ?`, nowTs, nowTs-300).Scan(&activeMiners)
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM known_servers WHERE is_active = 1 AND last_connected > ?`, nowTs-86400).Scan(&knownServers)
	
	// Verificar consistência lógica
	inconsistencies := []string{}
	
	// 1. Online users não pode ser maior que total users
	if onlineUsers > totalUsers {
		inconsistencies = append(inconsistencies, "online_exceeds_total")
	}
	
	// 2. Active miners não pode ser maior que total miners
	if activeMiners > totalMiners {
		inconsistencies = append(inconsistencies, "active_miners_exceeds_total")
	}
	
	// 3. Uptime deve ser positivo
	uptime := time.Since(s.StartTime).Seconds()
	if uptime <= 0 {
		inconsistencies = append(inconsistencies, "invalid_uptime")
	}
	
	// 4. Server ID deve ser UUID válido
	if len(s.ServerID) < 36 {
		inconsistencies = append(inconsistencies, "invalid_server_id")
	}
	
	// 5. Address deve ser não-vazio
	if s.Address == "" {
		inconsistencies = append(inconsistencies, "empty_address")
	}
	
	// Calcular "assinatura de consistência" - hash dos dados
	data := fmt.Sprintf("%d:%d:%d:%d:%d:%d:%.0f:%s", 
		totalUsers, onlineUsers, totalContent, totalMiners, activeMiners, knownServers, uptime, s.ServerID)
	h := sha256.Sum256([]byte(data))
	consistencyHash := base64.StdEncoding.EncodeToString(h[:])
	
	isConsistent := len(inconsistencies) == 0
	
	return ChallengeResponse{
		Success:   true,
		Answer:    consistencyHash,
		Proof:     fmt.Sprintf("%t", isConsistent),
		Timestamp: nowTs,
		Details: map[string]any{
			"total_users":     totalUsers,
			"online_users":    onlineUsers,
			"total_content":   totalContent,
			"total_miners":    totalMiners,
			"active_miners":   activeMiners,
			"known_servers":   knownServers,
			"uptime_seconds":  uptime,
			"consistent":      isConsistent,
			"inconsistencies": inconsistencies,
		},
	}
}

// handleProtocolChallenge testa conformidade do protocolo.
func (s *Server) handleProtocolChallenge(req ChallengeRequest) ChallengeResponse {
	nowTs := now()
	
	// Verificar que o servidor suporta os endpoints esperados
	protocolVersion := "2S+1U+1M"
	
	// Verificar que as tabelas necessárias existem
	tables := []string{
		"server_handshakes",
		"voucher_confirmations",
		"voucher_locks",
		"content_dual_registrations",
	}
	
	existingTables := []string{}
	for _, table := range tables {
		var count int
		// M-01 FIX: Use parameterized query to prevent SQL injection
		_ = s.DB.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count)
		if count > 0 {
			existingTables = append(existingTables, table)
		}
	}
	
	// Verificar estabilidade
	stability := s.CheckNodeStability()
	
	// Hash de protocolo
	data := fmt.Sprintf("%s:%d:%d:%d:%d",
		protocolVersion,
		len(existingTables),
		stability.KnownServers,
		stability.RegisteredUsers,
		stability.ActiveMiners)
	h := sha256.Sum256([]byte(data))
	protocolHash := base64.StdEncoding.EncodeToString(h[:])
	
	return ChallengeResponse{
		Success:   true,
		Answer:    protocolHash,
		Proof:     protocolVersion,
		Timestamp: nowTs,
		Details: map[string]any{
			"protocol_version": protocolVersion,
			"tables_present":   existingTables,
			"tables_expected":  tables,
			"stability_level":  int(stability.Level),
			"requirements_met": stability.Level >= NodeStable,
		},
	}
}

// handleComputationChallenge testa cálculos específicos que provam lógica correta.
func (s *Server) handleComputationChallenge(req ChallengeRequest) ChallengeResponse {
	nowTs := now()
	
	data, _ := req.Data["input"].(float64)
	
	// O servidor deve calcular algo que prova que a lógica está correta
	// Por exemplo: calcular taxa de exchange com a fórmula correta
	
	// Fórmula: fee = max(min_fee, ceil(amount * fee_rate))
	feeRate := s.cfg.ExchangeFeeRate
	feeMin := s.cfg.ExchangeFeeMin
	amount := int(data)
	
	expectedFee := int(math.Ceil(float64(amount) * feeRate))
	if expectedFee < feeMin {
		expectedFee = feeMin
	}
	
	// Hash do resultado
	resultData := fmt.Sprintf("%d:%.4f:%d:%d", amount, feeRate, feeMin, expectedFee)
	h := sha256.Sum256([]byte(resultData))
	resultHash := base64.StdEncoding.EncodeToString(h[:])
	
	return ChallengeResponse{
		Success:   true,
		Answer:    fmt.Sprintf("%d", expectedFee),
		Proof:     resultHash,
		Timestamp: nowTs,
		Details: map[string]any{
			"input":        amount,
			"fee_rate":     feeRate,
			"fee_min":      feeMin,
			"calculated":   expectedFee,
			"formula":      "max(min_fee, ceil(amount * fee_rate))",
		},
	}
}

// VerifyServerBehavior é chamado pelo cliente para verificar o comportamento do servidor.
func (s *Server) VerifyServerBehavior() map[string]any {
	results := map[string]any{}
	
	// 1. Challenge criptográfico
	cryptoChallenge := ChallengeRequest{
		Type:      ChallengeCrypto,
		Challenge: newUUID(),
		Timestamp: now(),
	}
	cryptoResult := s.HandleChallengeResponse(cryptoChallenge)
	results["crypto"] = map[string]any{
		"success": cryptoResult.Success,
		"proof":   cryptoResult.Proof,
	}
	
	// 2. Challenge de consistência
	consistencyChallenge := ChallengeRequest{
		Type:      ChallengeConsistency,
		Challenge: newUUID(),
		Timestamp: now(),
	}
	consistencyResult := s.HandleChallengeResponse(consistencyChallenge)
	results["consistency"] = map[string]any{
		"success":   consistencyResult.Success,
		"consistent": consistencyResult.Details["consistent"],
		"inconsistencies": consistencyResult.Details["inconsistencies"],
	}
	
	// 3. Challenge de protocolo
	protocolChallenge := ChallengeRequest{
		Type:      ChallengeProtocol,
		Challenge: newUUID(),
		Timestamp: now(),
	}
	protocolResult := s.HandleChallengeResponse(protocolChallenge)
	results["protocol"] = map[string]any{
		"success":    protocolResult.Success,
		"version":    protocolResult.Proof,
		"tables":     protocolResult.Details["tables_present"],
	}
	
	// 4. Challenge de computação
	computationChallenge := ChallengeRequest{
		Type:      ChallengeComputation,
		Challenge: newUUID(),
		Data:      map[string]any{"input": 100.0},
		Timestamp: now(),
	}
	computationResult := s.HandleChallengeResponse(computationChallenge)
	results["computation"] = map[string]any{
		"success":   computationResult.Success,
		"calculated": computationResult.Answer,
	}
	
	// Verificar se todos passaram
	allPassed := true
	for _, result := range results {
		if r, ok := result.(map[string]any); ok {
			if !r["success"].(bool) {
				allPassed = false
				break
			}
		}
	}
	
	results["all_passed"] = allPassed
	results["code_hash"] = ServerCodeHash
	results["code_version"] = ServerCodeVersion
	results["timestamp"] = now()
	
	return results
}
