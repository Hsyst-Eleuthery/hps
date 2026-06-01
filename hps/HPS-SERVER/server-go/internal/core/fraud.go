package core

import "encoding/json"

func (s *Server) SetUserFraudRestriction(username, issuer, reason string) {
	if username == "" || issuer == "" {
		return
	}
	if reason == "" {
		reason = "fraud_report"
	}
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
