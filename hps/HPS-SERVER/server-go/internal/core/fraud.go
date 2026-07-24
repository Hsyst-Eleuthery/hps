package core

import (
	"encoding/json"
	"log"
)

// SetUserFraudRestriction restricts a user for fraud.
// M-08 FIX: Added caller parameter for audit logging.
func (s *Server) SetUserFraudRestriction(username, issuer, reason string, caller ...string) {
	if username == "" || issuer == "" {
		return
	}
	if reason == "" {
		reason = "fraud_report"
	}
	callerID := "system"
	if len(caller) > 0 && caller[0] != "" {
		callerID = caller[0]
	}
	// M-08 FIX: Log who is making the restriction for audit
	log.Printf("M-08 AUDIT: fraud restriction applied username=%s issuer=%s reason=%s caller=%s", username, issuer, reason, callerID)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO fraud_restrictions
		(username, issuer, reason, restricted_at) VALUES (?, ?, ?, ?)`,
		username, issuer, reason, now())
	s.AdjustReputation(username, -30)
}

func (s *Server) IsUserFraudRestricted(username string) bool {
	if username == "" {
		return false
	}
	var exists int
	_ = s.DB.QueryRow(`SELECT 1 FROM fraud_restrictions WHERE username = ? LIMIT 1`, username).Scan(&exists)
	return exists == 1
}

func (s *Server) RegisterFraudulentIssuer(issuer string, report map[string]any) string {
	if issuer == "" {
		return ""
	}
	
	// C-08 FIX: Rate limiting para fraud reports
	// Máximo 5 reports por issuer por hora
	// C-08 FIX: Use username field instead of content_hash for issuer filtering
	var recentReports int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM contracts 
		WHERE action_type = 'economy_alert' 
		AND username = ? 
		AND timestamp > ?`, issuer, now()-3600).Scan(&recentReports)
	
	if recentReports >= 5 {
		return "" // Rate limit atingido
	}
	
	reportText, _ := json.Marshal(report)
	contractID := s.SaveServerContract("economy_alert", []ContractDetail{
		{Key: "ISSUER", Value: issuer},
		{Key: "REASON", Value: "fraud_report"},
		{Key: "EVIDENCE", Value: string(reportText)},
	}, "")
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO hps_issuer_invalidations
		(issuer, reason, session_id, invalidated_at) VALUES (?, ?, ?, ?)`,
		issuer, "fraud_report", asString(report["contract_id"]), now())
	rows, err := s.DB.Query(`SELECT DISTINCT owner FROM hps_vouchers WHERE reason = ?`, "exchange_from:"+issuer)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var owner string
			if rows.Scan(&owner) == nil && owner != "" {
				s.SetUserFraudRestriction(owner, issuer, "fraud_exchange")
			}
		}
	}
	return contractID
}
