package core

import (
	"log"
	"strings"
	"time"
)

// ConfirmationSignature represents a cross-server confirmation of a voucher.
type ConfirmationSignature struct {
	Server          string  `json:"server"`
	Signature       string  `json:"signature"`
	Timestamp       float64 `json:"timestamp"`
	BalanceVerified bool    `json:"balance_verified"`
}

// VoucherReceipt is the complete receipt with cross-server confirmations.
type VoucherReceipt struct {
	VoucherID               string                 `json:"voucher_id"`
	IssuerServer            string                 `json:"issuer_server"`
	IssuerSignature         string                 `json:"issuer_signature"`
	ConfirmationSignatures  []ConfirmationSignature `json:"confirmation_signatures"`
}

const (
	minConfirmations      = 1
	confirmationTimeoutSec = 30
	maxConfirmationRetries = 3
)

// RequestCrossServerConfirmation sends a voucher to another server for confirmation.
func (s *Server) RequestCrossServerConfirmation(remoteAddr, voucherID string, voucher map[string]any) (bool, string) {
	remoteAddr = s.ensureAddressProtocol(remoteAddr)

	payload := mapValue(voucher["payload"])
	signatures := mapValue(voucher["signatures"])

	confirmPayload := map[string]any{
		"voucher_id":      voucherID,
		"value":           asInt(payload["value"]),
		"issuer":          asString(payload["issuer"]),
		"owner":           asString(payload["owner"]),
		"issuer_signature": asString(signatures["issuer"]),
	}

	ok, resp, errMsg := s.MakeRemoteRequestJSON(remoteAddr, "/voucher/confirm", "POST", confirmPayload)
	if !ok {
		return false, errMsg
	}

	success, _ := resp["success"].(bool)
	if !success {
		errMsg, _ := resp["error"].(string)
		return false, errMsg
	}

	// Save confirmation in DB
	signature := asString(resp["signature"])
	balanceVerified := asBool(resp["balance_verified"])
	timestamp := asFloat(resp["timestamp"])
	if timestamp <= 0 {
		timestamp = now()
	}

	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO voucher_confirmations
		(voucher_id, confirming_server, signature, balance_verified, confirmed_at)
		VALUES (?, ?, ?, ?, ?)`,
		voucherID, remoteAddr, signature, boolToInt(balanceVerified), timestamp)

	return true, ""
}

// HandleVoucherConfirm handles the /voucher/confirm endpoint from another server.
func (s *Server) HandleVoucherConfirm(data map[string]any) map[string]any {
	voucherID := asString(data["voucher_id"])
	value := asInt(data["value"])
	issuer := asString(data["issuer"])
	owner := asString(data["owner"])
	issuerSignature := asString(data["issuer_signature"])

	if voucherID == "" || value <= 0 || issuer == "" || owner == "" {
		return map[string]any{"success": false, "error": "missing fields"}
	}

	// Verify issuer signature on the voucher
	issuerKey := s.GetRegisteredPublicKey(issuer)
	if issuerKey == "" {
		return map[string]any{"success": false, "error": "issuer key not found"}
	}

	// Build the expected payload to verify signature
	expectedPayload := map[string]any{
		"voucher_id": voucherID,
		"value":      value,
		"issuer":     issuer,
		"owner":      owner,
	}
	if !VerifyPayloadSignature(expectedPayload, issuerSignature, issuerKey) {
		return map[string]any{"success": false, "error": "invalid issuer signature"}
	}

	// Verify balance/permission for the issuer
	balanceVerified := s.VerifyIssuerBalance(issuer, value)

	// Sign confirmation
	confirmPayload := map[string]any{
		"voucher_id":       voucherID,
		"confirming_server": s.Address,
		"timestamp":        now(),
	}
	signature := s.SignPayload(confirmPayload)

	return map[string]any{
		"success":           true,
		"signature":         signature,
		"balance_verified":  balanceVerified,
		"timestamp":         now(),
	}
}

// HandleVoucherReceipt handles the /voucher/:id/receipt endpoint.
func (s *Server) HandleVoucherReceipt(voucherID string) map[string]any {
	if voucherID == "" {
		return map[string]any{"success": false, "error": "missing voucher_id"}
	}

	// Get voucher info
	info := s.GetVoucherAuditInfo(voucherID)
	if info == nil {
		return map[string]any{"success": false, "error": "voucher not found"}
	}

	payload := mapValue(info["payload"])
	signatures := mapValue(info["signatures"])

	// Get confirmations from DB
	confirmations := s.GetVoucherConfirmations(voucherID)

	return map[string]any{
		"success":                 true,
		"voucher_id":              voucherID,
		"issuer_server":           asString(payload["issuer"]),
		"issuer_signature":        asString(signatures["issuer"]),
		"confirmation_signatures": confirmations,
		"confirmation_count":      len(confirmations),
	}
}

// GetVoucherConfirmations returns all cross-server confirmations for a voucher.
func (s *Server) GetVoucherConfirmations(voucherID string) []ConfirmationSignature {
	rows, err := s.DB.Query(`SELECT confirming_server, signature, balance_verified, confirmed_at
		FROM voucher_confirmations WHERE voucher_id = ? ORDER BY confirmed_at DESC`, voucherID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var confirmations []ConfirmationSignature
	for rows.Next() {
		var conf ConfirmationSignature
		var balanceVerified int
		if rows.Scan(&conf.Server, &conf.Signature, &balanceVerified, &conf.Timestamp) == nil {
			conf.BalanceVerified = balanceVerified != 0
			confirmations = append(confirmations, conf)
		}
	}
	return confirmations
}

// HasValidConfirmation checks if a voucher has at least minConfirmations valid confirmations.
func (s *Server) HasValidConfirmation(voucherID string) bool {
	var count int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM voucher_confirmations WHERE voucher_id = ?`, voucherID).Scan(&count)
	return count >= minConfirmations
}

// RequestConfirmationsFromKnownServers requests confirmation from all known servers.
func (s *Server) RequestConfirmationsFromKnownServers(voucherID string, voucher map[string]any) {
	servers := s.listRemoteServersByPriority()
	if len(servers) == 0 {
		return
	}
	for _, serverAddr := range servers {
		go func(addr string) {
			ok, errMsg := s.RequestCrossServerConfirmation(addr, voucherID, voucher)
			if !ok {
				log.Printf("voucher confirmation failed for %s from %s: %s", voucherID, addr, errMsg)
			}
		}(serverAddr)
	}
}

// VerifyIssuerBalance checks if an issuer has sufficient balance/permission.
func (s *Server) VerifyIssuerBalance(issuer string, value int) bool {
	// For now, basic check - issuer must be a known server
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return false
	}
	// Check if issuer is a known server
	var exists int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM server_nodes WHERE address = ?`, issuer).Scan(&exists)
	return exists > 0
}

// CleanupExpiredConfirmations removes old confirmations.
func (s *Server) CleanupExpiredConfirmations() {
	_, _ = s.DB.Exec(`DELETE FROM voucher_confirmations WHERE confirmed_at < ?`,
		now()-float64(30*24*3600)) // 30 days
}

func init() {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		for range ticker.C {
			// Will run when a server instance is created
		}
	}()
}
