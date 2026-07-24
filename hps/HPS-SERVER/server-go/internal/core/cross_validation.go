package core

import (
	"log"
	"strings"
	"time"
)

// CrossValidationResult represents the result of a cross-server validation.
type CrossValidationResult struct {
	Valid       bool    `json:"valid"`
	Server      string  `json:"server"`
	Timestamp   float64 `json:"timestamp"`
	Reason      string  `json:"reason,omitempty"`
	Signature   string  `json:"signature"`
}

// HandleTransferValidate handles the /transfer/validate endpoint.
// Validates a transfer cross-server before processing.
func (s *Server) HandleTransferValidate(data map[string]any) map[string]any {
	transferID := asString(data["transfer_id"])
	sender := asString(data["sender"])
	receiver := asString(data["receiver"])
	amount := asInt(data["amount"])
	senderSignature := asString(data["sender_signature"])

	if transferID == "" || sender == "" || receiver == "" || amount <= 0 {
		return map[string]any{"success": false, "error": "missing fields"}
	}

	// Local validation
	if !s.ValidateTransferLocally(sender, receiver, amount, senderSignature) {
		return map[string]any{
			"success": false,
			"valid":   false,
			"reason":  "local_validation_failed",
		}
	}

	// Sign validation result
	validationPayload := map[string]any{
		"transfer_id": transferID,
		"sender":      sender,
		"receiver":    receiver,
		"amount":      amount,
		"valid":       true,
		"server":      s.Address,
		"timestamp":   now(),
	}
	signature := s.SignPayload(validationPayload)

	return map[string]any{
		"success":   true,
		"valid":     true,
		"server":    s.Address,
		"timestamp": now(),
		"signature": signature,
	}
}

// HandleTransferNotify handles the /transfer/notify endpoint.
// Notifies that a transfer has been processed.
func (s *Server) HandleTransferNotify(data map[string]any) map[string]any {
	transferID := asString(data["transfer_id"])
	if transferID == "" {
		return map[string]any{"success": false, "error": "missing transfer_id"}
	}

	// Record notification for audit trail
	nowTs := now()
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO server_sync_history
		(server_address, last_sync, sync_type, items_count, success)
		VALUES (?, ?, ?, ?, 1)`,
		"transfer_notify:"+transferID, nowTs, "transfer_notify", 1)

	return map[string]any{
		"success":    true,
		"transfer_id": transferID,
		"notified_at": nowTs,
	}
}

// ValidateTransferLocally performs local validation of a transfer.
func (s *Server) ValidateTransferLocally(sender, receiver string, amount int, senderSignature string) bool {
	if strings.TrimSpace(sender) == "" || strings.TrimSpace(receiver) == "" {
		return false
	}
	if amount <= 0 {
		return false
	}

	// Check if sender exists
	var senderExists int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username = ?`, sender).Scan(&senderExists)
	if senderExists == 0 {
		return false
	}

	// Check if receiver exists
	var receiverExists int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username = ?`, receiver).Scan(&receiverExists)
	if receiverExists == 0 {
		return false
	}

	return true
}

// RequestCrossServerValidation requests validation from another server.
func (s *Server) RequestCrossServerValidation(remoteAddr string, transferID, sender, receiver string, amount int, senderSignature string) *CrossValidationResult {
	remoteAddr = s.ensureAddressProtocol(remoteAddr)

	validatePayload := map[string]any{
		"transfer_id":      transferID,
		"sender":           sender,
		"receiver":         receiver,
		"amount":           amount,
		"sender_signature": senderSignature,
	}

	ok, resp, errMsg := s.MakeRemoteRequestJSON(remoteAddr, "/transfer/validate", "POST", validatePayload)
	if !ok {
		log.Printf("cross-server validation failed for %s from %s: %s", transferID, remoteAddr, errMsg)
		return nil
	}

	valid, _ := resp["valid"].(bool)
	signature := asString(resp["signature"])
	timestamp := asFloat(resp["timestamp"])

	// C3 FIX: Verify the response signature from the remote server
	if signature != "" {
		// A1 FIX: Use GetServerNodePublicKey for server addresses (queries server_nodes table)
		serverKey := s.GetServerNodePublicKey(remoteAddr)
		if serverKey != "" {
			verifyPayload := map[string]any{
				"transfer_id": transferID,
				"valid":       valid,
				"timestamp":   timestamp,
			}
			if !VerifyPayloadSignature(verifyPayload, signature, serverKey) {
				log.Printf("C3 FIX: Cross-validation response signature invalid from %s", remoteAddr)
				return nil
			}
		}
	}

	return &CrossValidationResult{
		Valid:     valid,
		Server:    remoteAddr,
		Timestamp: timestamp,
		Signature: signature,
	}
}

// NotifyTransferProcessed notifies all known servers about a processed transfer.
func (s *Server) NotifyTransferProcessed(transferID string) {
	servers := s.listRemoteServersByPriority()
	for _, serverAddr := range servers {
		go func(addr string) {
			s.MakeRemoteRequestJSON(addr, "/transfer/notify", "POST", map[string]any{
				"transfer_id": transferID,
			})
		}(serverAddr)
	}
}

// ValidateTransferCrossServer performs cross-server validation with fallback.
func (s *Server) ValidateTransferCrossServer(transferID, sender, receiver string, amount int, senderSignature string) bool {
	servers := s.listRemoteServersByPriority()
	if len(servers) == 0 {
		// No other servers available, proceed with local validation only
		return true
	}

	validations := 0
	for _, serverAddr := range servers {
		result := s.RequestCrossServerValidation(serverAddr, transferID, sender, receiver, amount, senderSignature)
		if result != nil && result.Valid {
			validations++
			break // Got at least one confirmation
		}
	}

	// At least 1 confirmation needed (minConfirmations = 1)
	return validations >= 1
}

func init() {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		for range ticker.C {
			// Cleanup old transfer notifications
		}
	}()
}
