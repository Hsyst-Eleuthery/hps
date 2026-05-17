package core

import "time"

func (s *Server) IsLocalIssuer(issuer string) bool {
	return issuer == s.Address || issuer == s.BindAddress
}

func (s *Server) ReserveVouchersForSession(owner string, sessionID string, voucherIDs []string) (bool, int, string) {
	if len(voucherIDs) == 0 {
		return false, 0, "No vouchers provided"
	}
	total := 0
	for _, voucherID := range voucherIDs {
		var value int
		var issuer, status string
		var invalidated int
		err := s.DB.QueryRow(`SELECT value, issuer, status, invalidated FROM hps_vouchers
			WHERE voucher_id = ? AND owner = ?`, voucherID, owner).Scan(&value, &issuer, &status, &invalidated)
		if err != nil {
			return false, 0, "Voucher " + voucherID + " not found"
		}
		if !s.IsLocalIssuer(issuer) {
			return false, 0, "Voucher " + voucherID + " has different issuer"
		}
		if status != "valid" && status != "reserved" {
			return false, 0, "Voucher " + voucherID + " is not available"
		}
		if invalidated != 0 {
			return false, 0, "Voucher " + voucherID + " invalidated"
		}
		total += value
	}
	for _, voucherID := range voucherIDs {
		_, _ = s.DB.Exec(`UPDATE hps_vouchers SET status = ?, session_id = ?, last_updated = ?
			WHERE voucher_id = ?`, "reserved", sessionID, float64(time.Now().UnixNano())/1e9, voucherID)
	}
	return true, total, ""
}

func (s *Server) MarkVouchersSpent(sessionID string) {
	_, _ = s.DB.Exec(`UPDATE hps_vouchers SET status = ?, last_updated = ?
		WHERE session_id = ? AND status = ?`, "spent", float64(time.Now().UnixNano())/1e9, sessionID, "reserved")
}

func (s *Server) ReleaseVouchersForSession(sessionID string) {
	_, _ = s.DB.Exec(`UPDATE hps_vouchers SET status = ?, session_id = NULL, last_updated = ?
		WHERE session_id = ? AND status = ?`, "valid", float64(time.Now().UnixNano())/1e9, sessionID, "reserved")
}

func (s *Server) ReleaseExpiredExchangeTokens(nowTs float64) int {
	if nowTs <= 0 {
		nowTs = float64(time.Now().UnixNano()) / 1e9
	}
	type expiredToken struct {
		sessionID string
	}
	expired := []expiredToken{}
	s.stateMu.Lock()
	for tokenID, stored := range s.ExchangeTokens {
		if stored == nil {
			delete(s.ExchangeTokens, tokenID)
			continue
		}
		expiresAt := 0.0
		switch t := stored["expires_at"].(type) {
		case float64:
			expiresAt = t
		case float32:
			expiresAt = float64(t)
		case int:
			expiresAt = float64(t)
		case int64:
			expiresAt = float64(t)
		}
		if expiresAt <= 0 || nowTs <= expiresAt {
			continue
		}
		delete(s.ExchangeTokens, tokenID)
		sessionID, _ := stored["session_id"].(string)
		expired = append(expired, expiredToken{sessionID: sessionID})
	}
	s.stateMu.Unlock()
	for _, item := range expired {
		if item.sessionID != "" {
			s.ReleaseVouchersForSession(item.sessionID)
		}
	}
	return len(expired)
}
