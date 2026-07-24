package core

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"time"
)

// ContentRegistration represents a dual-signed content registration.
type ContentRegistration struct {
	ContentHash      string  `json:"content_hash"`
	UserSignature    string  `json:"user_signature"`
	ServerASignature string  `json:"server_a_signature"`
	ServerBSignature string  `json:"server_b_signature"`
	Timestamp        float64 `json:"timestamp"`
	ReplicatedAt     float64 `json:"replicated_at"`
}

// HandleContentRegister handles the /content/register endpoint.
// Registers content with dual signature (user + server).
func (s *Server) HandleContentRegister(data map[string]any) map[string]any {
	contentHash := asString(data["content_hash"])
	userSignature := asString(data["user_signature"])
	userPublicKey := asString(data["user_public_key"])

	if contentHash == "" || userSignature == "" {
		return map[string]any{"success": false, "error": "missing fields"}
	}

	// Verify user signature
	if userPublicKey != "" {
		if !VerifyRawTextSignature(contentHash, userSignature, userPublicKey) {
			return map[string]any{"success": false, "error": "invalid user signature"}
		}
	}

	// Server signs the content hash
	serverSignature := s.SignRawText(contentHash)

	// Store registration
	nowTs := now()
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO content_dual_registrations
		(content_hash, server, user_signature, server_signature, registered_at)
		VALUES (?, ?, ?, ?, ?)`,
		contentHash, s.Address, userSignature, serverSignature, nowTs)

	// Attempt replication to other servers
	go s.ReplicateContentDualSig(contentHash, userSignature, serverSignature)

	return map[string]any{
		"success":            true,
		"content_hash":       contentHash,
		"server":             s.Address,
		"server_signature":   serverSignature,
		"registered_at":      nowTs,
	}
}

// HandleContentReplicate handles the /content/replicate endpoint.
// Receives content from another server and adds local signature.
func (s *Server) HandleContentReplicate(data map[string]any) map[string]any {
	contentHash := asString(data["content_hash"])
	userSignature := asString(data["user_signature"])
	serverASignature := asString(data["server_a_signature"])
	serverAAddress := asString(data["server_a_address"])

	if contentHash == "" || userSignature == "" || serverASignature == "" || serverAAddress == "" {
		return map[string]any{"success": false, "error": "missing fields (content_hash, user_signature, server_a_signature, server_a_address required)"}
	}

	// PROTOCOLO-14: Verificação obrigatória da assinatura do servidor remetente
	// Se não temos a chave pública, rejeitar em vez de confiar
	serverAKey := s.GetRegisteredPublicKey(serverAAddress)
	if serverAKey == "" {
		return map[string]any{"success": false, "error": "server A public key not registered - cannot verify signature"}
	}
	if !VerifyRawTextSignature(contentHash, serverASignature, serverAKey) {
		return map[string]any{"success": false, "error": "invalid server A signature"}
	}

	// Server B signs the content hash
	serverBSignature := s.SignRawText(contentHash)

	// Store registration
	nowTs := now()
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO content_dual_registrations
		(content_hash, server, user_signature, server_signature, registered_at)
		VALUES (?, ?, ?, ?, ?)`,
		contentHash, s.Address, userSignature, serverBSignature, nowTs)

	return map[string]any{
		"success":            true,
		"content_hash":       contentHash,
		"server":             s.Address,
		"server_signature":   serverBSignature,
		"registered_at":      nowTs,
	}
}

// HandleContentRegistration handles the /content/:hash/registration endpoint.
// Returns all registrations for a content hash.
func (s *Server) HandleContentRegistration(contentHash string) map[string]any {
	if contentHash == "" {
		return map[string]any{"success": false, "error": "missing content_hash"}
	}

	rows, err := s.DB.Query(`SELECT server, user_signature, server_signature, registered_at
		FROM content_dual_registrations WHERE content_hash = ?
		ORDER BY registered_at ASC`, contentHash)
	if err != nil {
		return map[string]any{"success": false, "error": "database error"}
	}
	defer rows.Close()

	var registrations []map[string]any
	for rows.Next() {
		var server, userSig, serverSig string
		var registeredAt float64
		if rows.Scan(&server, &userSig, &serverSig, &registeredAt) == nil {
			registrations = append(registrations, map[string]any{
				"server":           server,
				"user_signature":   userSig,
				"server_signature": serverSig,
				"registered_at":    registeredAt,
			})
		}
	}

	hasDualSignature := len(registrations) >= 2

	return map[string]any{
		"success":             true,
		"content_hash":        contentHash,
		"registrations":       registrations,
		"registration_count":  len(registrations),
		"has_dual_signature":  hasDualSignature,
	}
}

// ReplicateContentDualSig replicates content registration to other servers.
func (s *Server) ReplicateContentDualSig(contentHash, userSignature, serverSignature string) {
	servers := s.listRemoteServersByPriority()
	if len(servers) == 0 {
		return
	}

	for _, serverAddr := range servers {
		go func(addr string) {
		 replicatePayload := map[string]any{
				"content_hash":      contentHash,
				"user_signature":    userSignature,
				"server_a_signature": serverSignature,
				"server_a_address":  s.Address,
			}
			ok, resp, errMsg := s.MakeRemoteRequestJSON(addr, "/content/replicate", "POST", replicatePayload)
			if !ok {
				log.Printf("content replication failed for %s to %s: %s", contentHash, addr, errMsg)
				return
			}
			success, _ := resp["success"].(bool)
			if success {
				log.Printf("content replicated successfully for %s to %s", contentHash, addr)
			}
		}(serverAddr)
	}
}

// VerifyContentDualSignature checks if content has dual signatures.
func (s *Server) VerifyContentDualSignature(contentHash string) bool {
	var count int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM content_dual_registrations WHERE content_hash = ?`,
		contentHash).Scan(&count)
	return count >= 2
}

// CalculateContentHash computes SHA256 hash of content bytes.
func CalculateContentHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// CleanupOldContentRegistrations removes registrations older than 1 year.
func (s *Server) CleanupOldContentRegistrations() {
	_, _ = s.DB.Exec(`DELETE FROM content_dual_registrations WHERE registered_at < ?`,
		now()-float64(365*24*3600))
}

func init() {
	go func() {
		ticker := time.NewTicker(7 * 24 * time.Hour)
		for range ticker.C {
			// Will run when a server instance is created
		}
	}()
}
