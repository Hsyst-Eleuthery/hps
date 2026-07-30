package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

func (s *Server) AddMinerDebtEntry(username, entryType string, amount int, metadata map[string]any) string {
	entryID := NewUUID()
	metaText := "{}"
	if metadata != nil {
		if b, err := json.Marshal(metadata); err == nil {
			metaText = string(b)
		}
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO miner_debt_entries
		(entry_id, username, entry_type, amount, status, created_at, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		entryID, username, entryType, amount, "pending", now(), metaText)
	return entryID
}

func (s *Server) listMinerDebtEntries(username, status string, entryTypes []string) []map[string]any {
	if username == "" {
		return nil
	}
	query := `SELECT entry_id, entry_type, amount, status, created_at, resolved_at, metadata
		FROM miner_debt_entries WHERE username = ?`
	args := []any{username}
	if strings.TrimSpace(status) != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	if len(entryTypes) > 0 {
		query += ` AND entry_type IN (` + placeholders(len(entryTypes)) + `)`
		for _, typ := range entryTypes {
			args = append(args, typ)
		}
	}
	query += ` ORDER BY created_at ASC`
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var entryID, entryType, entryStatus, metadataRaw string
		var amount int
		var createdAt float64
		var resolvedAt sql.NullFloat64
		if rows.Scan(&entryID, &entryType, &amount, &entryStatus, &createdAt, &resolvedAt, &metadataRaw) != nil {
			continue
		}
		metadata := map[string]any{}
		if strings.TrimSpace(metadataRaw) != "" {
			_ = json.Unmarshal([]byte(metadataRaw), &metadata)
		}
		entry := map[string]any{
			"entry_id":    entryID,
			"entry_type":  entryType,
			"amount":      amount,
			"status":      entryStatus,
			"created_at":  createdAt,
			"metadata":    metadata,
			"resolved_at": nil,
		}
		if resolvedAt.Valid {
			entry["resolved_at"] = resolvedAt.Float64
		}
		out = append(out, entry)
	}
	return out
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

func (s *Server) ResolveMinerDebtEntries(username string, entryTypes []string) {
	_ = s.ResolveMinerDebtEntriesLimited(username, entryTypes, 0)
}

func (s *Server) ResolveMinerDebtEntriesLimited(username string, entryTypes []string, limit int) []map[string]any {
	if username == "" || len(entryTypes) == 0 {
		return nil
	}
	entries := s.listMinerDebtEntries(username, "pending", entryTypes)
	if len(entries) == 0 {
		return nil
	}
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	ids := make([]any, 0, len(entries)+2)
	for _, entry := range entries {
		ids = append(ids, asString(entry["entry_id"]))
	}
	if len(ids) == 0 {
		return nil
	}
	query := `UPDATE miner_debt_entries SET status = ?, resolved_at = ? WHERE entry_id IN (` + placeholders(len(ids)) + `)`
	args := []any{"resolved", now()}
	args = append(args, ids...)
	_, _ = s.DB.Exec(query, args...)
	return entries
}

func (s *Server) BootstrapMinerDebtEntries(username string) {
	if username == "" {
		return
	}
	stats := s.GetMinerStats(username)
	pendingSignatures := asInt(stats["pending_signatures"])
	if pendingSignatures <= 0 {
		return
	}
	var exists int
	_ = s.DB.QueryRow(`SELECT 1 FROM miner_debt_entries WHERE username = ? LIMIT 1`, username).Scan(&exists)
	if exists == 1 {
		return
	}
	mintedCount := asInt(stats["minted_count"])
	start := mintedCount - pendingSignatures + 1
	if start < 1 {
		start = 1
	}
	for count := start; count <= mintedCount; count++ {
		signatureType := "signature_last_resort"
		if count%2 == 0 {
			signatureType = "signature_immediate"
		}
		s.AddMinerDebtEntry(username, signatureType, 0, nil)
	}
	s.SyncMinerPendingCounts(username)
}

func (s *Server) GetMinerFineEntries(username string) []map[string]any {
	s.BootstrapMinerDebtEntries(username)
	return s.listMinerDebtEntries(username, "pending", []string{"fine_delay", "fine_report_invalid"})
}

func (s *Server) GetMinerSignatureEntries(username string, allowLastResort bool) []map[string]any {
	s.BootstrapMinerDebtEntries(username)
	entryTypes := []string{"signature_immediate"}
	if allowLastResort {
		entryTypes = append(entryTypes, "signature_last_resort")
	}
	return s.listMinerDebtEntries(username, "pending", entryTypes)
}

func (s *Server) GetLastPendingSignatureType(username string) string {
	entries := s.listMinerDebtEntries(username, "", []string{"signature_immediate", "signature_last_resort"})
	if len(entries) == 0 {
		return ""
	}
	return asString(entries[len(entries)-1]["entry_type"])
}

func (s *Server) ComputeDelayFineAmount(entry map[string]any) int {
	metadata := castMap(entry["metadata"])
	feeAmount := asInt(metadata["fee_amount"])
	deadline := asFloat(metadata["deadline"])
	if feeAmount <= 0 || deadline <= 0 {
		return 0
	}
	delay := math.Max(0.0, now()-deadline)
	periods := int(math.Ceil(delay / 3.0))
	if periods < 1 {
		periods = 1
	}
	if periods > 1000000 {
		periods = 1000000
	}
	result := periods * feeAmount
	if result > math.MaxInt/2 {
		result = math.MaxInt
	} else {
		result *= 2
	}
	return result
}

func (s *Server) computeMinerFineAmount(username string) int {
	entries := s.GetMinerFineEntries(username)
	total := 0
	for _, entry := range entries {
		if asString(entry["entry_type"]) == "fine_delay" {
			total += s.ComputeDelayFineAmount(entry)
		} else {
			total += asInt(entry["amount"])
		}
	}
	if total < 0 {
		return 0
	}
	return total
}

func (s *Server) ComputeMinerFinePerPending(username string) int {
	_ = username
	return 5
}

func (s *Server) GetMinerFineQuote(username string, includeSignatureLastResort bool) map[string]any {
	fineEntries := s.GetMinerFineEntries(username)
	fineAmount := 0
	for _, entry := range fineEntries {
		if asString(entry["entry_type"]) == "fine_delay" {
			fineAmount += s.ComputeDelayFineAmount(entry)
		} else {
			fineAmount += asInt(entry["amount"])
		}
	}
	fineCount := len(fineEntries)
	signatureImmediate := len(s.GetMinerSignatureEntries(username, false))
	signatureLastResort := len(s.listMinerDebtEntries(username, "pending", []string{"signature_last_resort"}))
	signatureCount := signatureImmediate
	if includeSignatureLastResort {
		signatureCount += signatureLastResort
	}
	signatureAmount := signatureCount * s.ComputeMinerFinePerPending(username)
	totalAmount := fineAmount + signatureAmount
	if totalAmount < 0 {
		totalAmount = 0
	}
	return map[string]any{
		"total_amount":          totalAmount,
		"fine_amount":           fineAmount,
		"fine_count":            fineCount,
		"signature_amount":      signatureAmount,
		"signature_count":       signatureCount,
		"signature_immediate":   signatureImmediate,
		"signature_last_resort": signatureLastResort,
	}
}

func (s *Server) roundDebtLimit(value float64) int {
	if value >= 9.5 {
		return 10
	}
	return int(math.Floor(value))
}

func (s *Server) GetUserReputation(username string) int {
	if username == "" {
		return 100
	}
	var rep int
	if err := s.DB.QueryRow(`SELECT reputation FROM users WHERE username = ?`, username).Scan(&rep); err == nil {
		if rep <= 0 {
			return 1
		}
		if rep > 100 {
			return 100
		}
		return rep
	}
	if err := s.DB.QueryRow(`SELECT reputation FROM user_reputations WHERE username = ?`, username).Scan(&rep); err == nil {
		if rep <= 0 {
			return 1
		}
		if rep > 100 {
			return 100
		}
		return rep
	}
	return 100
}

func (s *Server) GetUserMinedBalance(username string) int {
	if username == "" {
		return 0
	}
	rows, err := s.DB.Query(`SELECT value, payload, status, invalidated FROM hps_vouchers WHERE owner = ?`, username)
	if err != nil {
		return 0
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var value int
		var payloadText, status string
		var invalidated int
		if rows.Scan(&value, &payloadText, &status, &invalidated) != nil {
			continue
		}
		if invalidated != 0 {
			continue
		}
		if status != "valid" && status != "locked" {
			continue
		}
		payload := map[string]any{}
		if json.Unmarshal([]byte(payloadText), &payload) != nil {
			continue
		}
		powInfo := castMap(payload["pow"])
		if asString(powInfo["action_type"]) == "hps_mint" {
			total += value
		}
	}
	return total
}

func (s *Server) GetMinerSignaturePunctuality(username string, limit int) map[string]any {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.Query(`SELECT created_at, miner_deadline, signed_at FROM monetary_transfers
		WHERE signed_by = ? ORDER BY signed_at DESC LIMIT ?`, username, limit)
	if err != nil {
		return map[string]any{"count": 0, "avg_ratio": 0.0, "penalty_pct": 0.0}
	}
	defer rows.Close()
	ratios := make([]float64, 0)
	for rows.Next() {
		var createdAt sql.NullFloat64
		var minerDeadline sql.NullFloat64
		var signedAt sql.NullFloat64
		if rows.Scan(&createdAt, &minerDeadline, &signedAt) != nil {
			continue
		}
		if !minerDeadline.Valid || !signedAt.Valid {
			continue
		}
		duration := minerDeadline.Float64 - createdAt.Float64
		if duration <= 0 {
			continue
		}
		ratio := (signedAt.Float64 - createdAt.Float64) / duration
		if ratio < 0 {
			ratio = 0
		}
		if ratio > 1 {
			ratio = 1
		}
		ratios = append(ratios, ratio)
	}
	count := len(ratios)
	if count == 0 {
		return map[string]any{"count": 0, "avg_ratio": 0.0, "penalty_pct": 0.0}
	}
	sum := 0.0
	for _, ratio := range ratios {
		sum += ratio
	}
	avgRatio := sum / float64(count)
	penaltyPct := avgRatio * 25.0
	if penaltyPct < 0 {
		penaltyPct = 0
	}
	if penaltyPct > 25 {
		penaltyPct = 25
	}
	return map[string]any{"count": count, "avg_ratio": avgRatio, "penalty_pct": penaltyPct}
}

func (s *Server) GetMinerRecentSignatureParticipation(username string, windowSeconds float64, targetCount int) map[string]any {
	if windowSeconds <= 0 {
		windowSeconds = 86400.0
	}
	if targetCount <= 0 {
		targetCount = 20
	}
	cutoff := now() - windowSeconds
	var count int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM monetary_transfers
		WHERE signed_by = ? AND signed_at IS NOT NULL AND signed_at >= ?`, username, cutoff).Scan(&count)
	ratio := 0.0
	if targetCount > 0 {
		ratio = math.Min(1.0, math.Max(0.0, float64(count)/float64(targetCount)))
	}
	bonusPct := math.Min(25.0, math.Max(0.0, ratio*25.0))
	return map[string]any{"count": count, "ratio": ratio, "bonus_pct": bonusPct}
}

func (s *Server) GetMinerDebtStatus(username string) map[string]any {
	stats := s.GetMinerStats(username)
	pendingSignatures, pendingFines := s.GetMinerPendingCounts(username)
	promiseActive := asBool(stats["fine_promise_active"])
	promiseAmount := asFloat(stats["fine_promise_amount"])
	mintedCount := asInt(stats["minted_count"])
	reputation := float64(s.GetUserReputation(username))
	minedBalance := float64(s.GetUserMinedBalance(username))
	totalMinted := s.GetEconomyStat("total_minted", 0.0)
	miningShare := 0.0
	if totalMinted > 0 {
		miningShare = math.Min(1.0, math.Max(0.0, minedBalance/totalMinted))
	}
	miningPct := math.Min(50.0, math.Max(0.0, miningShare*50.0))
	punctualityInfo := s.GetMinerSignaturePunctuality(username, 50)
	punctualityPct := asFloat(punctualityInfo["penalty_pct"])
	participationInfo := s.GetMinerRecentSignatureParticipation(username, 86400.0, 20)
	participationBonus := asFloat(participationInfo["bonus_pct"])
	repClamped := math.Min(100.0, math.Max(0.0, reputation))
	reputationPct := math.Max(0.0, math.Min(25.0, (1.0-(repClamped/100.0))*25.0))
	combinedPct := math.Min(100.0, math.Max(0.0, miningPct+punctualityPct+reputationPct-participationBonus))
	// C-09 FIX: Invert formula - active miners get HIGHER debt limits (reward, not punish)
	limitRaw := 2.0 + (combinedPct / 10.0)
	limit := s.roundDebtLimit(limitRaw)
	if limit < 2 {
		limit = 2
	}
	if limit > 10 {
		limit = 10
	}
	signatureBlocked := pendingSignatures >= limit
	signatureImmediate := len(s.GetMinerSignatureEntries(username, false))
	signatureLastResort := len(s.listMinerDebtEntries(username, "pending", []string{"signature_last_resort"}))
	signatureFines := signatureImmediate
	if signatureBlocked {
		signatureFines += signatureLastResort
	}
	signatureFineAmount := signatureFines * s.ComputeMinerFinePerPending(username)
	fineAmount := s.computeMinerFineAmount(username) + signatureFineAmount
	withheldSummary := s.GetWithheldOfferSummary(username)
	nextSignatureIncrement := 0
	if (mintedCount+1)%2 == 0 {
		nextSignatureIncrement = 1
	}
	nextPending := pendingSignatures + nextSignatureIncrement
	nextPendingFines := pendingFines
	fineGrace := 2
	pendingDelayFines := len(s.listMinerDebtEntries(username, "pending", []string{"fine_delay"}))
	return map[string]any{
		"pending_signatures":      pendingSignatures,
		"pending_fines":           pendingFines,
		"signature_fines":         signatureFines,
		"signature_immediate":     signatureImmediate,
		"signature_last_resort":   signatureLastResort,
		"debt_limit":              limit,
		"debt_limit_raw":          limitRaw,
		"combined_pct":            combinedPct,
		"minted_count":            mintedCount,
		"next_pending_increase":   nextSignatureIncrement > 0,
		"next_pending":            nextPending,
		"next_pending_fines":      nextPendingFines,
		"pending_delay_fines":     pendingDelayFines,
		"mined_balance":           minedBalance,
		"total_minted":            totalMinted,
		"mining_share":            miningShare,
		"mining_pct":              miningPct,
		"punctuality_pct":         punctualityPct,
		"punctuality_count":       asInt(punctualityInfo["count"]),
		"punctuality_avg_ratio":   asFloat(punctualityInfo["avg_ratio"]),
		"participation_bonus_pct": participationBonus,
		"participation_count":     asInt(participationInfo["count"]),
		"participation_ratio":     asFloat(participationInfo["ratio"]),
		"reputation":              repClamped,
		"reputation_pct":          reputationPct,
		"fine_amount":             fineAmount,
		"fine_per_pending":        s.ComputeMinerFinePerPending(username),
		"withheld_count":          asInt(withheldSummary["count"]),
		"withheld_total":          asInt(withheldSummary["total"]),
		"promise_active":          promiseActive,
		"promise_amount":          promiseAmount,
		"fine_promise_active":     promiseActive,
		"fine_promise_amount":     promiseAmount,
		"fine_grace":              fineGrace,
		"limit_min":               2,
		"limit_max":               10,
	}
}

func (s *Server) SafeGetMinerDebtStatus(username string) map[string]any {
	if username == "" {
		return map[string]any{
			"pending_signatures":    0,
			"pending_fines":         0,
			"debt_limit":            2,
			"fine_amount":           0,
			"fine_per_pending":      0,
			"withheld_count":        0,
			"withheld_total":        0,
			"signature_fines":       0,
			"signature_immediate":   0,
			"signature_last_resort": 0,
			"promise_active":        false,
			"promise_amount":        0.0,
			"fine_grace":            2,
			"pending_delay_fines":   0,
		}
	}
	return s.GetMinerDebtStatus(username)
}

func (s *Server) HasPendingSignatureTransfers(miner string) bool {
	if miner == "" {
		return false
	}
	var found int
	_ = s.DB.QueryRow(`SELECT 1 FROM monetary_transfers
		WHERE assigned_miner = ? AND status = ?
		LIMIT 1`, miner, "pending_signature").Scan(&found)
	if found == 1 {
		return true
	}
	var negBalance int
	_ = s.DB.QueryRow(`SELECT negative_balance FROM miner_pending_sigs WHERE username = ?`, miner).Scan(&negBalance)
	return negBalance > 0
}

func (s *Server) IsMinerBlockedFromMining(miner string) bool {
	if miner == "" {
		return false
	}
	var blockedUntil float64
	err := s.DB.QueryRow(`SELECT blocked_until FROM miner_pending_sigs WHERE username = ?`, miner).Scan(&blockedUntil)
	if err == nil && blockedUntil > now() {
		return true
	}
	return s.HasPendingSignatureTransfers(miner)
}

func (s *Server) GetMinerPendingSig(username string) map[string]any {
	if username == "" {
		return nil
	}
	var pendingCount, negativeBalance int
	var blockedUntil, lastSignedAt, createdAt, updatedAt float64
	err := s.DB.QueryRow(`SELECT pending_count, negative_balance, blocked_until, last_signed_at, created_at, updated_at
		FROM miner_pending_sigs WHERE username = ?`, username).
		Scan(&pendingCount, &negativeBalance, &blockedUntil, &lastSignedAt, &createdAt, &updatedAt)
	if err != nil {
		return map[string]any{"pending_count": 0, "negative_balance": 0, "blocked_until": 0.0}
	}
	return map[string]any{
		"pending_count":    pendingCount,
		"negative_balance": negativeBalance,
		"blocked_until":    blockedUntil,
		"last_signed_at":   lastSignedAt,
	}
}

func (s *Server) CanMinerRequestNewPow(miner string) bool {
	return !s.IsMinerBlockedFromMining(miner)
}

func (s *Server) GetMinerRateConfig(username string) map[string]any {
	if username == "" {
		return nil
	}
	var minFee, maxFee, volatilityEnabled, rateAdjust, lossThreshold int
	var lossWindow, maxTxTime, createdAt, updatedAt float64
	err := s.DB.QueryRow(`SELECT min_fee_per_tx, max_fee_per_tx, fee_volatility_enabled,
		rate_adjustment_on_loss, loss_threshold, loss_window_seconds, max_tx_time_seconds,
		created_at, updated_at
		FROM miner_rate_config WHERE username = ?`, username).
		Scan(&minFee, &maxFee, &volatilityEnabled, &rateAdjust, &lossThreshold, &lossWindow, &maxTxTime, &createdAt, &updatedAt)
	if err != nil {
		return map[string]any{
			"min_fee_per_tx":         s.ComputeMinerFinePerPending(username),
			"max_fee_per_tx":         100,
			"fee_volatility_enabled": 1,
			"rate_adjustment_on_loss": -1,
			"loss_threshold":         3,
			"max_tx_time_seconds":    60.0,
		}
	}
	return map[string]any{
		"min_fee_per_tx":          minFee,
		"max_fee_per_tx":          maxFee,
		"fee_volatility_enabled":  volatilityEnabled,
		"rate_adjustment_on_loss": rateAdjust,
		"loss_threshold":          lossThreshold,
		"loss_window_seconds":     lossWindow,
		"max_tx_time_seconds":     maxTxTime,
	}
}

func (s *Server) UpsertMinerRateConfig(username string, minFee, maxFee int, volatilityEnabled int, rateAdjust, lossThreshold int, lossWindow, maxTxTime float64) {
	if username == "" {
		return
	}
	if minFee < 1 {
		minFee = 1
	}
	if maxFee < minFee {
		maxFee = minFee
	}
	if maxTxTime <= 0 {
		maxTxTime = 60.0
	}
	nowTs := now()
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO miner_rate_config
		(username, min_fee_per_tx, max_fee_per_tx, fee_volatility_enabled,
		 rate_adjustment_on_loss, loss_threshold, loss_window_seconds, max_tx_time_seconds,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		username, minFee, maxFee, volatilityEnabled, rateAdjust, lossThreshold, lossWindow, maxTxTime, nowTs, nowTs)
}

func (s *Server) GetMinerMaxTxTime(username string) float64 {
	cfg := s.GetMinerRateConfig(username)
	maxTxTime := asFloat(cfg["max_tx_time_seconds"])
	if maxTxTime <= 0 {
		maxTxTime = 60.0
	}
	return maxTxTime
}

func (s *Server) InitMinerPendingSig(username string) {
	if username == "" {
		return
	}
	nowTs := now()
	_, _ = s.DB.Exec(`INSERT OR IGNORE INTO miner_pending_sigs
		(username, pending_count, negative_balance, blocked_until, last_signed_at, created_at, updated_at)
		VALUES (?, 0, 0, 0, 0, ?, ?)`, username, nowTs, nowTs)
}

func (s *Server) SetMinerBlocked(miner string, durationSeconds float64) {
	if miner == "" || durationSeconds <= 0 {
		return
	}
	blockedUntil := now() + durationSeconds
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO miner_pending_sigs
		(username, pending_count, negative_balance, blocked_until, last_signed_at, created_at, updated_at)
		VALUES (?, COALESCE((SELECT pending_count FROM miner_pending_sigs WHERE username = ?), 0),
		        COALESCE((SELECT negative_balance FROM miner_pending_sigs WHERE username = ?), 0),
		        ?, 0, COALESCE((SELECT created_at FROM miner_pending_sigs WHERE username = ?), ?), ?)`,
		miner, miner, miner, blockedUntil, miner, now(), now())
}

func (s *Server) UnblockMiner(miner string) {
	if miner == "" {
		return
	}
	_, _ = s.DB.Exec(`UPDATE miner_pending_sigs SET blocked_until = 0, updated_at = ? WHERE username = ?`, now(), miner)
}

func (s *Server) ApplyMinerVolatileFee(username string, baseFee int) int {
	cfg := s.GetMinerRateConfig(username)
	if asInt(cfg["fee_volatility_enabled"]) == 0 {
		return baseFee
	}
	minFee := asInt(cfg["min_fee_per_tx"])
	maxFee := asInt(cfg["max_fee_per_tx"])
	if baseFee < minFee {
		baseFee = minFee
	}
	if baseFee > maxFee {
		baseFee = maxFee
	}
	lossThreshold := asInt(cfg["loss_threshold"])
	if lossThreshold <= 0 {
		lossThreshold = 3
	}
	lossWindow := asFloat(cfg["loss_window_seconds"])
	if lossWindow <= 0 {
		lossWindow = 86400
	}
	cutoff := now() - lossWindow
	var recentLosses int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM miner_debt_entries
		WHERE username = ? AND entry_type IN ('fine_delay', 'fine_report_invalid')
		AND status = 'resolved' AND resolved_at >= ?`, username, cutoff).Scan(&recentLosses)
	if recentLosses >= lossThreshold {
		rateAdjust := asInt(cfg["rate_adjustment_on_loss"])
		adjusted := baseFee + rateAdjust
		if adjusted < minFee {
			adjusted = minFee
		}
		if adjusted > maxFee {
			adjusted = maxFee
		}
		return adjusted
	}
	return baseFee
}

func (s *Server) ComputeSignatureFee(amount int) int {
	return s.ComputeSignatureFeeForMiner(amount, "")
}

func (s *Server) ComputeSignatureFeeForMiner(amount int, miner string) int {
	if amount <= 0 {
		return 0
	}
	rate := s.GetInflationRate()
	fee := int(math.Ceil(float64(amount) * rate))
	if fee < 0 {
		return 0
	}
	if miner == "" || !s.cfg.VolatileFees {
		return fee
	}
	return s.ApplyMinerVolatileFee(miner, fee)
}

// ComputeVariableFeeForClient: calculates the optimal fee based on market supply/demand data
func (s *Server) ComputeVariableFeeForClient(baseFee int, actionType string) int {
	if baseFee <= 0 {
		baseFee = s.ComputeSignatureFee(1)
		if baseFee <= 0 {
			baseFee = 5
		}
	}
	marketData := s.GetFeeMarketData()
	demandRatio := asFloat(marketData["demand_supply_ratio"])
	baseMultiplier := asFloat(marketData["base_multiplier"])
	adjusted := int(math.Ceil(float64(baseFee) * baseMultiplier))
	if demandRatio > 1.0 {
		premium := int(math.Ceil(float64(baseFee) * (demandRatio - 1.0) * 0.3))
		adjusted += premium
	}
	switch actionType {
	case "hps_mint", "upload":
		adjusted = int(math.Ceil(float64(adjusted) * 1.0))
	case "dns", "register_dns":
		adjusted = int(math.Ceil(float64(adjusted) * 0.8))
	case "contract_transfer", "hps_transfer":
		adjusted = int(math.Ceil(float64(adjusted) * 1.2))
	case "report", "report_content":
		adjusted = int(math.Ceil(float64(adjusted) * 0.5))
	}
	minFee := int(s.GetFeeMarketStat("market_min_fee", 1.0))
	if adjusted < minFee {
		adjusted = minFee
	}
	maxFee := int(s.GetFeeMarketStat("market_max_fee", 1000.0))
	if adjusted > maxFee {
		adjusted = maxFee
	}
	return adjusted
}

// GetVariableFeeQuotes: returns fee quotes from all available miners for client selection
// Uses HPS contract syntax for the fee quote format.
func (s *Server) GetVariableFeeQuotes(amount int) []map[string]any {
	quotes := make([]map[string]any, 0)
	rows, err := s.DB.Query(`SELECT ms.username, COALESCE(mrc.min_fee_per_tx, ?), COALESCE(mrc.max_fee_per_tx, ?), COALESCE(mrc.fee_volatility_enabled, 1), COALESCE(mrc.max_tx_time_seconds, 60)
		FROM miner_stats ms
		LEFT JOIN miner_rate_config mrc ON mrc.username = ms.username
		WHERE (ms.banned_until IS NULL OR ms.banned_until < ?)
		AND NOT EXISTS (
			SELECT 1 FROM miner_pending_sigs mps
			WHERE mps.username = ms.username AND mps.blocked_until > ?
		)
		ORDER BY ms.pending_signatures ASC
		LIMIT 20`, s.ComputeMinerFinePerPending(""), 100, now(), now())
	if err != nil {
		return quotes
	}
	defer rows.Close()
	baseFee := s.ComputeSignatureFee(amount)
	marketData := s.GetFeeMarketData()
	demandRatio := asFloat(marketData["demand_supply_ratio"])
	supplyRatio := asFloat(marketData["supply_demand_ratio"])
	baseMultiplier := asFloat(marketData["base_multiplier"])
	for rows.Next() {
		var username string
		var minFee, maxFee, volatilityEnabled int
		var maxTxTime float64
		if rows.Scan(&username, &minFee, &maxFee, &volatilityEnabled, &maxTxTime) != nil {
			continue
		}
		if minFee <= 0 {
			minFee = baseFee
		}
		if maxFee <= 0 {
			maxFee = baseFee * 3
		}
		if maxFee < minFee {
			maxFee = minFee
		}
		variableFee := baseFee
		if volatilityEnabled == 1 {
			variableFee = s.ApplyMinerVolatileFee(username, baseFee)
		}
		variableFee = int(math.Ceil(float64(variableFee) * baseMultiplier))
		if demandRatio > 1.0 {
			premium := int(math.Ceil(float64(variableFee) * (demandRatio - 1.0) * 0.3))
			variableFee += premium
		}
		if variableFee < minFee {
			variableFee = minFee
		}
		if variableFee > maxFee {
			variableFee = maxFee
		}
		if maxTxTime <= 0 {
			maxTxTime = 60.0
		}
		// Build HPS contract-formatted fee quote
		quoteContract := fmt.Sprintf(`# HSYST P2P SERVICE
## CONTRACT:
### DETAILS:
# ACTION: fee_quote
# MINER: %s
# BASE_FEE: %d
# MIN_FEE: %d
# MAX_FEE: %d
# VARIABLE_FEE: %d
# FIXED_FEE: %d
# VOLATILITY_MODEL: %t
# MAX_TX_TIME_SEC: %.0f
# DEMAND_RATIO: %.2f
# SUPPLY_RATIO: %.2f
# BASE_MULTIPLIER: %.2f
# TIMESTAMP: %.0f
### :END DETAILS
### START:
# USER: %s
# SIGNATURE: 
### :END START
## :END CONTRACT`, username, baseFee, minFee, maxFee, variableFee, baseFee,
			volatilityEnabled == 1, maxTxTime, demandRatio, supplyRatio, baseMultiplier, now(), username)
		quotes = append(quotes, map[string]any{
			"miner":              username,
			"min_fee":            minFee,
			"max_fee":            maxFee,
			"variable_fee":       variableFee,
			"fixed_fee":          baseFee,
			"volatility_model":   volatilityEnabled == 1,
			"max_tx_time_sec":    maxTxTime,
			"recommended":        variableFee <= baseFee*2,
			"demand_ratio":       demandRatio,
			"supply_ratio":       supplyRatio,
			"base_multiplier":    baseMultiplier,
			"fee_quote_contract": quoteContract,
		})
	}
	return quotes
}

func (s *Server) AllocateSignatureFee(amount int) (int, string, int) {
	minerFee, _, feeSource, adjusted := s.AllocateSignatureFees(amount)
	return minerFee, feeSource, adjusted
}

func (s *Server) AllocateSignatureFees(amount int) (int, int, string, int) {
	return s.AllocateSignatureFeesForMiner(amount, "")
}

func (s *Server) AllocateSignatureFeesForMiner(amount int, miner string) (int, int, string, int) {
	minerFee := s.ComputeSignatureFeeForMiner(amount, miner)
	if minerFee <= 0 {
		return 0, 0, "", amount
	}
	selectorFee := minerFee
	totalFee := minerFee + selectorFee
	custodyBalance := s.GetEconomyStat("custody_balance", 0.0)
	if custodyBalance >= float64(totalFee) {
		return minerFee, selectorFee, "custody", amount
	}
	adjusted := amount - totalFee
	if adjusted < 1 {
		adjusted = 1
	}
	totalFee = amount - adjusted
	if totalFee < 0 {
		totalFee = 0
	}
	minerFee = int(math.Ceil(float64(totalFee) / 2.0))
	if minerFee < 0 {
		minerFee = 0
	}
	selectorFee = totalFee - minerFee
	if selectorFee < 0 {
		selectorFee = 0
	}
	return minerFee, selectorFee, "receiver", adjusted
}

func (s *Server) LockMinerMintedVouchers(username string) {
	if username == "" {
		return
	}
	rows, err := s.DB.Query(`SELECT voucher_id, payload, status, invalidated FROM hps_vouchers WHERE owner = ?`, username)
	if err != nil {
		return
	}
	defer rows.Close()
	lockIDs := make([]string, 0)
	for rows.Next() {
		var voucherID, payloadText, status string
		var invalidated int
		if rows.Scan(&voucherID, &payloadText, &status, &invalidated) != nil {
			continue
		}
		if invalidated != 0 || status != "valid" {
			continue
		}
		payload := map[string]any{}
		if json.Unmarshal([]byte(payloadText), &payload) != nil {
			continue
		}
		powInfo := castMap(payload["pow"])
		if asString(powInfo["action_type"]) == "hps_mint" {
			lockIDs = append(lockIDs, voucherID)
		}
	}
	for _, voucherID := range lockIDs {
		_, _ = s.DB.Exec(`UPDATE hps_vouchers SET status = ?, last_updated = ? WHERE voucher_id = ?`, "locked", now(), voucherID)
	}
}

func (s *Server) BanMiner(username, reason, transferID string) {
	if username == "" {
		return
	}
	// CÓDIGO-11 FIX: Reduzir ban de 10 anos para 24 horas
	// Miners podem pedir apelação após o período de ban
	banUntil := now() + (24 * 3600) // 24 horas
	_, _ = s.DB.Exec(`INSERT INTO miner_stats (username, banned_until, ban_reason, last_updated)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			banned_until = excluded.banned_until,
			ban_reason = excluded.ban_reason,
			last_updated = excluded.last_updated`, username, banUntil, reason, now())
	s.LockMinerMintedVouchers(username)
	s.SaveServerContract("miner_ban", []ContractDetail{
		{Key: "MINER", Value: username},
		{Key: "REASON", Value: reason},
		{Key: "TRANSFER_ID", Value: transferID},
		{Key: "BAN_DURATION", Value: "24h"},
		{Key: "APPEAL_AVAILABLE", Value: "after_ban_expires"},
	}, "")
}

// AppealMinerBan permite ao miner pedir revisão do ban
func (s *Server) AppealMinerBan(username, reason string) map[string]any {
	if username == "" {
		return map[string]any{"success": false, "error": "missing username"}
	}
	
	var bannedUntil float64
	var banReason string
	err := s.DB.QueryRow(`SELECT banned_until, ban_reason FROM miner_stats WHERE username = ?`, username).Scan(&bannedUntil, &banReason)
	if err != nil {
		return map[string]any{"success": false, "error": "miner not found"}
	}
	
	nowTs := now()
	if bannedUntil > nowTs {
		return map[string]any{
			"success":       false,
			"error":         "miner still banned",
			"banned_until":  bannedUntil,
			"remaining_sec": bannedUntil - nowTs,
		}
	}
	
	// Ban expirado, permitir appeal
	s.SaveServerContract("miner_ban_appeal", []ContractDetail{
		{Key: "MINER", Value: username},
		{Key: "ORIGINAL_REASON", Value: banReason},
		{Key: "APPEAL_REASON", Value: reason},
		{Key: "STATUS", Value: "pending_review"},
	}, "")
	
	return map[string]any{
		"success": true,
		"message": "Appeal submitted for review",
	}
}

func (s *Server) IssueChangeOffer(username string, changeValue int, reason string, sessionID string, contractAction string, contractDetails []ContractDetail) map[string]any {
	if changeValue <= 0 {
		return nil
	}
	ownerKey := s.GetUserPublicKey(username)
	if ownerKey == "" {
		return nil
	}
	sourceVoucherIDs := []string{}
	for _, detail := range contractDetails {
		switch detail.Key {
		case "VOUCHERS":
			sourceVoucherIDs = append(sourceVoucherIDs, parseJSONStrSlice(asString(detail.Value))...)
		case "ORIGINAL_VOUCHER_ID":
			if sourceID := asString(detail.Value); sourceID != "" {
				sourceVoucherIDs = append(sourceVoucherIDs, sourceID)
			}
		}
	}
	offer := s.CreateVoucherOfferWithStatus(
		username,
		ownerKey,
		changeValue,
		reason,
		nil,
		map[string]any{
			"type":               "change",
			"reason":             reason,
			"session_id":         sessionID,
			"source_voucher_ids": dedupeStrings(sourceVoucherIDs),
		},
		"",
		"pending",
	)
	if contractAction != "" && len(contractDetails) > 0 {
		details := append([]ContractDetail{}, contractDetails...)
		details = append(details,
			ContractDetail{Key: "CHANGE_VALUE", Value: changeValue},
			ContractDetail{Key: "CHANGE_VOUCHER_ID", Value: asString(offer["voucher_id"])},
			ContractDetail{Key: "SESSION_ID", Value: sessionID},
		)
		s.SaveServerContract(contractAction, details, asString(offer["voucher_id"]))
	}
	return offer
}

func (s *Server) GetUserPublicKey(username string) string {
	var key string
	_ = s.DB.QueryRow(`SELECT public_key FROM users WHERE username = ?`, username).Scan(&key)
	return key
}

func sortedStrings(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}
