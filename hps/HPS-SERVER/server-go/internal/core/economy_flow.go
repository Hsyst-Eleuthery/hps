package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func (s *Server) IncrementEconomyStat(key string, delta float64) {
	s.economyMu.Lock()
	defer s.economyMu.Unlock()
	var value any
	err := s.DB.QueryRow("SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?", key).Scan(&value)
	current := parseNumeric(value, 0.0)
	if err != nil {
		current = 0.0
	}
	_, _ = s.DB.Exec("INSERT OR REPLACE INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)", key, current+delta)
}

func (s *Server) RecordEconomyEvent(reason string) {
	lastTs := s.GetEconomyStat("last_economy_event_ts", 0.0)
	if now()-lastTs < 5.0 {
		return
	}
	s.SetEconomyStat("last_economy_event_ts", now())
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)`,
		"last_economy_event_reason", reason)
}

func (s *Server) RecordEconomyContract(reason string) string {
	lastUpdate := s.GetEconomyStat("last_economy_update_ts", 0.0)
	if now()-lastUpdate < 1.0 {
		return ""
	}
	snapshot := map[string]any{
		"total_minted":    s.GetEconomyStat("total_minted", 0.0),
		"custody_balance": s.GetEconomyStat("custody_balance", 0.0),
		"owner_balance":   s.GetEconomyStat("owner_balance", 0.0),
		"multiplier":      s.GetEconomyMultiplier(),
	}
	prevHash := s.GetEconomyStatText("last_economy_hash", "")
	contractText := s.buildEconomyContractText(reason, snapshot, prevHash)
	signature := s.SignContractText(contractText)
	signedText := strings.Replace(contractText, "# SIGNATURE: ", "# SIGNATURE: "+signature, 1)
	contractBytes := []byte(signedText)
	contractID := s.SaveContract("economy_update", "", "", CustodyUsername, signature, contractBytes)
	hash := sha256.Sum256(contractBytes)
	s.SetEconomyStatText("last_economy_hash", hex.EncodeToString(hash[:]))
	s.SetEconomyStat("last_economy_update_ts", now())
	s.SetEconomyStatText("last_economy_contract_id", contractID)
	return contractID
}

func (s *Server) buildEconomyContractText(reason string, snapshot map[string]any, prevHash string) string {
	lines := []string{
		"# HSYST P2P SERVICE",
		"## CONTRACT:",
		"### DETAILS:",
		"# ACTION: economy_update",
		fmt.Sprintf("# REASON: %v", reason),
		fmt.Sprintf("# TOTAL_MINTED: %v", snapshot["total_minted"]),
		fmt.Sprintf("# CUSTODY_BALANCE: %v", snapshot["custody_balance"]),
		fmt.Sprintf("# OWNER_BALANCE: %v", snapshot["owner_balance"]),
		fmt.Sprintf("# MULTIPLIER: %v", snapshot["multiplier"]),
		fmt.Sprintf("# PREV_HASH: %v", prevHash),
		"### :END DETAILS",
		"### START:",
		"# USER: " + CustodyUsername,
		"# SIGNATURE: ",
		"### :END START",
		"## :END CONTRACT",
	}
	return strings.Join(lines, "\n") + "\n"
}

func (s *Server) AllocateExchangeFee(feeAmount int) {
	if feeAmount <= 0 {
		return
	}
	s.AddCustodyFunds(feeAmount, "exchange_fee")
}

// Supply Chain: tracks every voucher_issue in a hash chain to detect forgeries
func (s *Server) RecordVoucherSupplyChain(voucherID string, value int, owner string, issuedAt float64, contractID string) (string, int, error) {
	prevHash := s.GetEconomyStatText("supply_chain_hash", "")
	chainIndex := int(s.GetEconomyStat("supply_chain_index", 0.0)) + 1
	entryStr := fmt.Sprintf("%s|%s|%d|%s|%.0f|%d", prevHash, voucherID, value, owner, issuedAt, chainIndex)
	entryHash := sha256Hex(entryStr)
	entryID := newUUID()
	if _, err := s.TxExec(`INSERT OR REPLACE INTO voucher_supply_chain
		(entry_id, voucher_id, value, owner, issued_at, prev_chain_hash, chain_hash, chain_index, contract_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entryID, voucherID, value, owner, issuedAt, prevHash, entryHash, chainIndex, contractID); err != nil {
		return entryHash, chainIndex, fmt.Errorf("failed to record supply chain entry: %w", err)
	}
	s.SetEconomyStatText("supply_chain_hash", entryHash)
	s.SetEconomyStat("supply_chain_index", float64(chainIndex))
	// Record economy contract for the supply chain update
	_ = s.SaveServerContract("supply_chain_entry", []ContractDetail{
		{Key: "VOUCHER_ID", Value: voucherID},
		{Key: "VALUE", Value: value},
		{Key: "OWNER", Value: owner},
		{Key: "CHAIN_HASH", Value: entryHash},
		{Key: "PREV_HASH", Value: prevHash},
		{Key: "CHAIN_INDEX", Value: chainIndex},
	}, entryID)
	return entryHash, chainIndex, nil
}

func (s *Server) VerifyVoucherSupplyChain(voucherID string) bool {
	var chainHash string
	err := s.DB.QueryRow(`SELECT chain_hash FROM voucher_supply_chain WHERE voucher_id = ?`, voucherID).Scan(&chainHash)
	return err == nil && chainHash != ""
}

// VerifyVoucherSupplyChainIntegrity: recomputes the hash for a given voucher's
// supply chain entry and checks it matches the stored chain_hash and that the
// prev_chain_hash links correctly to the previous entry.
func (s *Server) VerifyVoucherSupplyChainIntegrity(voucherID string) bool {
	var chainHash, storedPrevHash string
	var value int
	var owner string
	var issuedAt float64
	var chainIndex int
	err := s.DB.QueryRow(`SELECT prev_chain_hash, chain_hash, value, owner, issued_at, chain_index
		FROM voucher_supply_chain WHERE voucher_id = ?`, voucherID).
		Scan(&storedPrevHash, &chainHash, &value, &owner, &issuedAt, &chainIndex)
	if err != nil {
		return false
	}
	// Recompute expected hash
	entryStr := fmt.Sprintf("%s|%s|%d|%s|%.0f|%d", storedPrevHash, voucherID, value, owner, issuedAt, chainIndex)
	expectedHash := sha256Hex(entryStr)
	if expectedHash != chainHash {
		return false
	}
	// Verify previous entry link (if not first entry)
	if chainIndex > 1 && storedPrevHash != "" {
		var actualPrevHash string
		_ = s.DB.QueryRow(`SELECT chain_hash FROM voucher_supply_chain WHERE chain_index = ?`, chainIndex-1).Scan(&actualPrevHash)
		if actualPrevHash != "" && actualPrevHash != storedPrevHash {
			return false
		}
	}
	return true
}

func (s *Server) GetSupplyChainTip() string {
	return s.GetEconomyStatText("supply_chain_hash", "")
}

// GetSupplyAudit returns a cryptographic audit of the total HPS supply
// vs total minted. Miners and clients can use this to verify integrity.
func (s *Server) GetSupplyAudit() map[string]any {
	totalMinted := s.GetEconomyStat("total_minted", 0.0)
	var totalSupply int64
	_ = s.DB.QueryRow(`SELECT COALESCE(SUM(value), 0) FROM hps_vouchers WHERE status IN ('valid', 'reserved', 'locked')`).Scan(&totalSupply)
	var totalSpent int64
	_ = s.DB.QueryRow(`SELECT COALESCE(SUM(value), 0) FROM hps_vouchers WHERE status IN ('spent', 'burned')`).Scan(&totalSpent)
	var adminSupply int64
	_ = s.DB.QueryRow(`SELECT COALESCE(SUM(value), 0) FROM voucher_supply_chain vs JOIN contracts c ON c.contract_id = vs.contract_id WHERE c.action_type = 'supply_chain_entry' AND vs.voucher_id IN (SELECT voucher_id FROM hps_voucher_offers WHERE reason = 'admin_test')`).Scan(&adminSupply)
	var supplyChainCount int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM voucher_supply_chain`).Scan(&supplyChainCount)
	chainTip := s.GetEconomyStatText("supply_chain_hash", "")
	supplyChainContractID := s.GetEconomyStatText("last_economy_contract_id", "")
	return map[string]any{
		"total_minted":             totalMinted,
		"total_circulating":        float64(totalSupply),
		"total_spent":              float64(totalSpent),
		"total_balance":            float64(totalSupply - totalSpent),
		"admin_generated_supply":   float64(adminSupply),
		"supply_chain_entries":     supplyChainCount,
		"supply_chain_tip":         chainTip,
		"supply_chain_contract_id": supplyChainContractID,
		"circulating_vs_minted":    float64(totalSupply) - totalMinted,
	}
}

func (s *Server) GetTotalMinted() float64 {
	return s.GetEconomyStat("total_minted", 0.0)
}

// Global Transaction Counter: monotonic counter for all DB write operations
func (s *Server) NextTxCounter() int64 {
	s.economyMu.Lock()
	defer s.economyMu.Unlock()
	current := int64(s.GetEconomyStat("global_tx_counter", 0.0))
	next := current + 1
	s.SetEconomyStat("global_tx_counter", float64(next))
	return next
}

// Content Receipt Chain: append-only log of content uploads
func (s *Server) RecordContentReceipt(contentHash, username, title string, size int, timestamp float64) (string, string) {
	prevHash := s.GetEconomyStatText("content_receipt_hash", "")
	receiptIndex := int(s.GetEconomyStat("content_receipt_index", 0.0)) + 1
	entryStr := fmt.Sprintf("%s|%s|%s|%s|%d|%.0f|%d", prevHash, contentHash, username, title, size, timestamp, receiptIndex)
	receiptHash := sha256Hex(entryStr)
	receiptID := newUUID()
	contractID := s.SaveServerContract("content_receipt", []ContractDetail{
		{Key: "CONTENT_HASH", Value: contentHash},
		{Key: "USERNAME", Value: username},
		{Key: "TITLE", Value: title},
		{Key: "SIZE", Value: size},
		{Key: "RECEIPT_HASH", Value: receiptHash},
		{Key: "PREV_HASH", Value: prevHash},
		{Key: "RECEIPT_INDEX", Value: receiptIndex},
	}, receiptID)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO content_receipts
		(receipt_id, content_hash, username, title, size, timestamp, prev_receipt_hash, receipt_hash, receipt_index, contract_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		receiptID, contentHash, username, title, size, timestamp, prevHash, receiptHash, receiptIndex, contractID)
	s.SetEconomyStatText("content_receipt_hash", receiptHash)
	s.SetEconomyStat("content_receipt_index", float64(receiptIndex))
	return receiptHash, receiptID
}

func (s *Server) VerifyContentReceipt(contentHash string) (bool, string) {
	var receiptHash, contractID string
	err := s.DB.QueryRow(`SELECT receipt_hash, contract_id FROM content_receipts WHERE content_hash = ?`, contentHash).Scan(&receiptHash, &contractID)
	if err != nil {
		return false, ""
	}
	return true, contractID
}

// RecordFeeMarketStat: updates supply/demand data for variable fee computation
func (s *Server) RecordFeeMarketStat(key string, value float64) {
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO fee_market_stats (stat_key, stat_value, updated_at) VALUES (?, ?, ?)`, key, value, now())
}

func (s *Server) GetFeeMarketStat(key string, defaultValue float64) float64 {
	var value float64
	err := s.DB.QueryRow(`SELECT stat_value FROM fee_market_stats WHERE stat_key = ?`, key).Scan(&value)
	if err != nil {
		return defaultValue
	}
	return value
}

// VerifyContentReceiptChainIntegrity: verifies the entire content receipt hash chain
func (s *Server) VerifyContentReceiptChainIntegrity() (bool, string, int) {
	var count int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM content_receipts`).Scan(&count)
	if count == 0 {
		return true, "empty_chain", 0
	}
	rows, err := s.DB.Query(`SELECT receipt_id, content_hash, username, title, size, timestamp, prev_receipt_hash, receipt_hash, receipt_index FROM content_receipts ORDER BY receipt_index ASC`)
	if err != nil {
		return false, "query_failed", 0
	}
	defer rows.Close()
	prevHash := ""
	index := 0
	for rows.Next() {
		var receiptID, contentHash, username, title, prevReceiptHash, receiptHash string
		var size int
		var timestamp float64
		var receiptIndex int
		if rows.Scan(&receiptID, &contentHash, &username, &title, &size, &timestamp, &prevReceiptHash, &receiptHash, &receiptIndex) != nil {
			continue
		}
		expectedPrev := prevHash
		if index == 0 {
			expectedPrev = ""
		}
		if prevReceiptHash != expectedPrev {
			return false, fmt.Sprintf("hash_chain_break_at_index_%d", receiptIndex), index
		}
		entryStr := fmt.Sprintf("%s|%s|%s|%s|%d|%.0f|%d", prevReceiptHash, contentHash, username, title, size, timestamp, receiptIndex)
		expectedHash := sha256Hex(entryStr)
		if receiptHash != expectedHash {
			return false, fmt.Sprintf("hash_mismatch_at_index_%d", receiptIndex), index
		}
		prevHash = receiptHash
		index++
	}
	chainTip := s.GetEconomyStatText("content_receipt_hash", "")
	if prevHash != chainTip {
		return false, "chain_tip_mismatch", index
	}
	return true, "chain_intact", index
}

// CacheVoucherPowStatus: caches whether a voucher has direct PoW
func (s *Server) CacheVoucherPowStatus(voucherID string, hasDirectPow bool, powActionType string) {
	nowTs := now()
	powVal := 0
	if hasDirectPow {
		powVal = 1
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO voucher_pow_cache (voucher_id, has_direct_pow, pow_action_type, verified_at) VALUES (?, ?, ?, ?)`,
		voucherID, powVal, powActionType, nowTs)
}

func (s *Server) GetVoucherPowStatus(voucherID string) (bool, string) {
	var hasDirectPow int
	var powActionType string
	err := s.DB.QueryRow(`SELECT has_direct_pow, pow_action_type FROM voucher_pow_cache WHERE voucher_id = ?`, voucherID).Scan(&hasDirectPow, &powActionType)
	if err != nil {
		return false, ""
	}
	return hasDirectPow == 1, powActionType
}

// RecordAdminAudit: creates an admin audit contract
func (s *Server) RecordAdminAudit(action, arguments, adminUsername, clientHost string) string {
	contractID := s.SaveServerContract("admin_audit", []ContractDetail{
		{Key: "ACTION", Value: action},
		{Key: "ARGUMENTS", Value: arguments},
		{Key: "ADMIN_USERNAME", Value: adminUsername},
		{Key: "CLIENT_HOST", Value: clientHost},
		{Key: "TIMESTAMP", Value: now()},
	}, "")
	auditID := newUUID()
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO admin_audit_log (audit_id, action, arguments, admin_username, client_host, timestamp, contract_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		auditID, action, arguments, adminUsername, clientHost, now(), contractID)
	return contractID
}

// GetFeeMarketData: returns market data for variable fee calculation
func (s *Server) GetFeeMarketData() map[string]any {
	pendingTx := int(s.GetEconomyStat("market_pending_transfers", 0.0))
	availableMiners := int(s.GetEconomyStat("market_available_miners", 0.0))
	avgFee := s.GetFeeMarketStat("market_avg_fee", 5.0)
	demandRatio := 1.0
	if availableMiners > 0 {
		demandRatio = float64(pendingTx) / float64(availableMiners)
	}
	supplyRatio := 1.0
	if pendingTx > 0 {
		supplyRatio = float64(availableMiners) / float64(pendingTx)
	}
	return map[string]any{
		"pending_transfers":  pendingTx,
		"available_miners":   availableMiners,
		"average_fee":        avgFee,
		"demand_supply_ratio": demandRatio,
		"supply_demand_ratio": supplyRatio,
		"base_multiplier":    1.0 + demandRatio*0.5,
	}
}

// UpdateFeeMarketStats: called periodically to update market statistics
func (s *Server) UpdateFeeMarketStats() {
	var pendingCount int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM monetary_transfers WHERE status = ?`, "pending_signature").Scan(&pendingCount)
	var minerCount int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM miner_stats ms WHERE (ms.banned_until IS NULL OR ms.banned_until < ?)`, now()).Scan(&minerCount)
	s.SetEconomyStat("market_pending_transfers", float64(pendingCount))
	s.SetEconomyStat("market_available_miners", float64(minerCount))
	var avgFee float64
	_ = s.DB.QueryRow(`SELECT COALESCE(AVG(fee_amount), 0) FROM monetary_transfers WHERE created_at > ?`, now()-3600).Scan(&avgFee)
	s.RecordFeeMarketStat("market_avg_fee", avgFee)
}
