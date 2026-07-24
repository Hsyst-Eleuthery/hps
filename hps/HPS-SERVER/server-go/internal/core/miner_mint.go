package core

func (s *Server) GetMinerStats(username string) map[string]any {
	var mintedCount int
	var mintedTotal float64
	var pendingSignatures, pendingFines int
	var lastUpdated, bannedUntil, finePromiseAmount float64
	var finePromiseActive int
	err := s.DB.QueryRow(`SELECT
		COALESCE(minted_count,0), COALESCE(minted_total,0), COALESCE(pending_signatures,0),
		COALESCE(pending_fines,0), COALESCE(last_updated,0), COALESCE(banned_until,0),
		COALESCE(fine_promise_amount,0), COALESCE(fine_promise_active,0)
		FROM miner_stats WHERE username = ?`, username).
		Scan(&mintedCount, &mintedTotal, &pendingSignatures, &pendingFines, &lastUpdated, &bannedUntil, &finePromiseAmount, &finePromiseActive)
	if err != nil {
		return map[string]any{
			"minted_count":        0,
			"minted_total":        0.0,
			"pending_signatures":  0,
			"pending_fines":       0,
			"last_updated":        0.0,
			"banned_until":        0.0,
			"fine_promise_amount": 0.0,
			"fine_promise_active": false,
		}
	}
	return map[string]any{
		"minted_count":        mintedCount,
		"minted_total":        mintedTotal,
		"pending_signatures":  pendingSignatures,
		"pending_fines":       pendingFines,
		"last_updated":        lastUpdated,
		"banned_until":        bannedUntil,
		"fine_promise_amount": finePromiseAmount,
		"fine_promise_active": finePromiseActive != 0,
	}
}

func (s *Server) IsMinerBanned(username string) bool {
	stats := s.GetMinerStats(username)
	return asFloat(stats["banned_until"]) > now()
}

func (s *Server) IsMinerMintingSuspended(username string) (bool, map[string]any) {
	debt := s.SafeGetMinerDebtStatus(username)
	pendingSignatures := asInt(debt["pending_signatures"])
	pendingFines := asInt(debt["pending_fines"])
	pendingDelayFines := asInt(debt["pending_delay_fines"])
	debtLimit := asInt(debt["debt_limit"])
	fineGrace := asInt(debt["fine_grace"])
	if debtLimit <= 0 {
		debtLimit = 3
	}
	if fineGrace <= 0 {
		fineGrace = 2
	}
	promiseActive := asBool(debt["promise_active"]) || asBool(debt["fine_promise_active"])
	signatureBlocked := pendingSignatures >= debtLimit
	fineBlocked := pendingFines > fineGrace && !promiseActive
	delayBlocked := pendingDelayFines > 0
	return signatureBlocked || fineBlocked || delayBlocked, debt
}

func (s *Server) IncrementMinerMint(username string, mintedValue float64) int {
	stats := s.GetMinerStats(username)
	newCount := asInt(stats["minted_count"]) + 1
	newTotal := asFloat(stats["minted_total"]) + mintedValue
	if newCount%2 == 0 {
		lastPending := s.GetLastPendingSignatureType(username)
		signatureType := "signature_last_resort"
		if lastPending == "signature_last_resort" {
			signatureType = "signature_immediate"
		}
		s.AddMinerDebtEntry(username, signatureType, 0, nil)
	}
	pendingSignatures, pendingFines := s.SyncMinerPendingCounts(username)
	_, _ = s.DB.Exec(`INSERT INTO miner_stats
		(username, minted_count, minted_total, pending_signatures, pending_fines, last_updated, banned_until, fine_promise_amount, fine_promise_active)
		VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT banned_until FROM miner_stats WHERE username = ?), 0),
		        COALESCE((SELECT fine_promise_amount FROM miner_stats WHERE username = ?), 0),
		        COALESCE((SELECT fine_promise_active FROM miner_stats WHERE username = ?), 0))
		ON CONFLICT(username) DO UPDATE SET
			minted_count = excluded.minted_count,
			minted_total = excluded.minted_total,
			pending_signatures = excluded.pending_signatures,
			pending_fines = excluded.pending_fines,
			last_updated = excluded.last_updated`,
		username, newCount, newTotal, pendingSignatures, pendingFines, now(), username, username, username)
	return pendingSignatures
}

func (s *Server) GetMinerPendingCounts(username string) (int, int) {
	var pendingSignatures, pendingFines int
	_ = s.DB.QueryRow(`SELECT COALESCE(pending_signatures, 0), COALESCE(pending_fines, 0)
		FROM miner_stats WHERE username = ?`, username).Scan(&pendingSignatures, &pendingFines)
	return pendingSignatures, pendingFines
}

func (s *Server) SyncMinerPendingCounts(username string) (int, int) {
	if username == "" {
		return 0, 0
	}
	var pendingSignatures, pendingFines int
	_ = s.DB.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN entry_type LIKE 'signature_%' AND status = 'pending' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN entry_type LIKE 'fine_%' AND status = 'pending' THEN 1 ELSE 0 END), 0)
		FROM miner_debt_entries WHERE username = ?`, username).Scan(&pendingSignatures, &pendingFines)
	_, _ = s.DB.Exec(`INSERT INTO miner_stats
		(username, pending_signatures, pending_fines, last_updated)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			pending_signatures = excluded.pending_signatures,
			pending_fines = excluded.pending_fines,
			last_updated = excluded.last_updated`,
		username, pendingSignatures, pendingFines, now())
	return pendingSignatures, pendingFines
}
