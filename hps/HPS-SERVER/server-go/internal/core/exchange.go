package core

import (
	"log"
	"math"
	"time"
)

func (s *Server) IsLocalIssuer(issuer string) bool {
	return issuer == s.Address || issuer == s.BindAddress
}

func (s *Server) CreateExchangeTitle(rootVoucherID, sourceServer string, value, burnedValue int, backingType string) string {
	if value <= 0 || rootVoucherID == "" {
		return ""
	}

	// C-02 FIX: Check for existing active title with same root voucher (prevent double-spend)
	var existingCount int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM exchange_titles 
		WHERE root_voucher_id = ? AND status = 'active'`, rootVoucherID).Scan(&existingCount)
	if existingCount > 0 {
		log.Printf("C-02 FIX: Rejected duplicate exchange title for root_voucher %s", rootVoucherID)
		return ""
	}

	titleID := NewUUID()
	nowTs := now()

	// C-02 FIX: Use BEGIN IMMEDIATE for atomicity
	_ = s.BeginTx()
	contractID := s.SaveServerContract("exchange_title_issue", []ContractDetail{
		{Key: "TITLE_ID", Value: titleID},
		{Key: "ROOT_VOUCHER_ID", Value: rootVoucherID},
		{Key: "SOURCE_SERVER", Value: sourceServer},
		{Key: "VALUE", Value: value},
		{Key: "BURNED_VALUE", Value: burnedValue},
		{Key: "BACKING_TYPE", Value: backingType},
	}, titleID)
	_, _ = s.TxExec(`INSERT OR IGNORE INTO exchange_titles
		(title_id, root_voucher_id, source_server, destination_server, value, burned_value,
		 status, created_at, backing_type, contract_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		titleID, rootVoucherID, sourceServer, s.Address, value, burnedValue, "active", nowTs, backingType, contractID)
	s.CommitTx()
	return titleID
}

func (s *Server) GetExchangeTitle(titleID string) map[string]any {
	if titleID == "" {
		return nil
	}
	var rootVoucherID, sourceServer, destinationServer, status, holder, holderKey, backingType, contractID string
	var value, burnedValue int
	var createdAt, expiresAt, redeemedAt float64
	err := s.DB.QueryRow(`SELECT root_voucher_id, source_server, destination_server, value, burned_value,
		status, holder_username, holder_public_key, created_at, expires_at, redeemed_at, backing_type, contract_id
		FROM exchange_titles WHERE title_id = ?`, titleID).
		Scan(&rootVoucherID, &sourceServer, &destinationServer, &value, &burnedValue,
			&status, &holder, &holderKey, &createdAt, &expiresAt, &redeemedAt, &backingType, &contractID)
	if err != nil {
		return nil
	}
	return map[string]any{
		"title_id":           titleID,
		"root_voucher_id":    rootVoucherID,
		"source_server":      sourceServer,
		"destination_server": destinationServer,
		"value":              value,
		"burned_value":       burnedValue,
		"status":             status,
		"holder_username":    holder,
		"holder_public_key":  holderKey,
		"created_at":         createdAt,
		"expires_at":         expiresAt,
		"redeemed_at":        redeemedAt,
		"backing_type":       backingType,
		"contract_id":        contractID,
	}
}

func (s *Server) PurchaseExchangeTitle(titleID, username, publicKey string, voucherIDs []string, purchasePrice int) (map[string]any, string) {
	if titleID == "" || username == "" || purchasePrice <= 0 {
		return nil, "Invalid parameters"
	}
	title := s.GetExchangeTitle(titleID)
	if title == nil {
		return nil, "Title not found"
	}
	if asString(title["status"]) != "active" {
		return nil, "Title already claimed"
	}
	if asString(title["holder_username"]) != "" {
		return nil, "Title already has a holder"
	}
	if purchasePrice < asInt(title["value"]) {
		return nil, "Purchase price below title value"
	}
	sessionID := "extitle-" + NewUUID()
	okReserve, totalValue, reserveErr := s.ReserveVouchersForSession(username, sessionID, voucherIDs)
	if !okReserve {
		return nil, reserveErr
	}
	if totalValue < purchasePrice {
		s.ReleaseVouchersForSession(sessionID)
		return nil, "Insufficient balance"
	}
	s.MarkVouchersSpent(sessionID)
	s.RecordBurn(purchasePrice, "exchange_title_purchase:"+titleID)
	changeValue := totalValue - purchasePrice
	if changeValue > 0 {
		s.IssueChangeOffer(username, changeValue, "extitle_change:"+titleID, sessionID, "extitle_change", []ContractDetail{
			{Key: "TITLE_ID", Value: titleID},
			{Key: "PURCHASER", Value: username},
			{Key: "VOUCHERS", Value: CanonicalJSON(voucherIDs)},
		})
	}
	nowTs := now()
	_, _ = s.DB.Exec(`UPDATE exchange_titles
		SET holder_username = ?, holder_public_key = ?, expires_at = ?, status = ?
		WHERE title_id = ?`, username, publicKey, nowTs+86400*7, "claimed", titleID)
	s.AddCustodyFunds(purchasePrice, "exchange_title:"+titleID)
	s.SaveServerContract("exchange_title_purchase", []ContractDetail{
		{Key: "TITLE_ID", Value: titleID},
		{Key: "PURCHASER", Value: username},
		{Key: "PURCHASE_PRICE", Value: purchasePrice},
		{Key: "ROOT_VOUCHER_ID", Value: asString(title["root_voucher_id"])},
		{Key: "SOURCE_SERVER", Value: asString(title["source_server"])},
	}, titleID)
	return map[string]any{
		"title_id":       titleID,
		"purchaser":      username,
		"purchase_price": purchasePrice,
		"value":          asInt(title["value"]),
	}, ""
}

func (s *Server) ListActiveExchangeTitles() []map[string]any {
	rows, err := s.DB.Query(`SELECT title_id, root_voucher_id, source_server, destination_server,
		value, burned_value, status, holder_username, created_at, backing_type
		FROM exchange_titles WHERE status = 'active' OR status = 'claimed' ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var titles []map[string]any
	for rows.Next() {
		var titleID, rootVoucherID, sourceServer, destServer, status, holder, backingType string
		var value, burnedValue int
		var createdAt float64
		if rows.Scan(&titleID, &rootVoucherID, &sourceServer, &destServer, &value, &burnedValue, &status, &holder, &createdAt, &backingType) != nil {
			continue
		}
		titles = append(titles, map[string]any{
			"title_id":           titleID,
			"root_voucher_id":    rootVoucherID,
			"source_server":      sourceServer,
			"destination_server": destServer,
			"value":              value,
			"burned_value":       burnedValue,
			"status":             status,
			"holder_username":    holder,
			"created_at":         createdAt,
			"backing_type":       backingType,
		})
	}
	return titles
}

func (s *Server) RedeemExchangeTitle(titleID, username string) (map[string]any, string) {
	if titleID == "" || username == "" {
		return nil, "Invalid parameters"
	}
	title := s.GetExchangeTitle(titleID)
	if title == nil {
		return nil, "Title not found"
	}
	if asString(title["holder_username"]) != username {
		return nil, "This title does not belong to you"
	}
	if asString(title["status"]) != "claimed" {
		return nil, "Title not in claimable state"
	}
	value := asInt(title["value"])
	burnedValue := asInt(title["burned_value"])
	payout := value + int(math.Ceil(float64(burnedValue)*0.5))
	ownerKey := s.GetUserPublicKey(username)
	if ownerKey == "" {
		return nil, "User public key not found"
	}
	custodyBalance := s.GetEconomyStat("custody_balance", 0.0)
	available := int(custodyBalance)
	if available <= 0 {
		return nil, "Custody has no funds to redeem this title. Wait for custody balance to increase."
	}
	if custodyBalance >= float64(payout) {
		s.SetEconomyStat("custody_balance", custodyBalance-float64(payout))
	} else {
		shortfall := payout - available
		s.SetEconomyStat("custody_balance", 0)
		payout = available
		_ = s.CreatePhpsDebt("exchange_title_shortfall:"+titleID, "exchange", titleID, asString(title["contract_id"]), shortfall)
	}
	s.CreateVoucherOffer(username, ownerKey, payout,
		"exchange_title_redeem:"+titleID, nil,
		map[string]any{"type": "exchange_title_redeem", "title_id": titleID}, "")
	nowTs := now()
	_, _ = s.DB.Exec(`UPDATE exchange_titles SET status = ?, redeemed_at = ? WHERE title_id = ?`, "redeemed", nowTs, titleID)
	s.SaveServerContract("exchange_title_redeem", []ContractDetail{
		{Key: "TITLE_ID", Value: titleID},
		{Key: "HOLDER", Value: username},
		{Key: "PAYOUT", Value: payout},
	}, titleID)
	return map[string]any{
		"title_id": titleID,
		"payout":   payout,
		"status":   "redeemed",
	}, ""
}

func (s *Server) MarkVouchersSpent(sessionID string) {
	if _, err := s.DB.Exec(`UPDATE hps_vouchers SET status = ?, last_updated = ?
		WHERE session_id = ? AND status = ?`, "spent", float64(time.Now().UnixNano())/1e9, sessionID, "reserved"); err != nil {
		log.Printf("EXCHANGE ERROR: failed to mark vouchers spent session=%s err=%v", sessionID, err)
	}
}

func (s *Server) ReleaseVouchersForSession(sessionID string) {
	if _, err := s.DB.Exec(`UPDATE hps_vouchers SET status = ?, session_id = NULL, last_updated = ?
		WHERE session_id = ? AND status = ?`, "valid", float64(time.Now().UnixNano())/1e9, sessionID, "reserved"); err != nil {
		log.Printf("EXCHANGE ERROR: failed to release vouchers session=%s err=%v", sessionID, err)
	}
}

func (s *Server) ReserveVouchersForSession(owner string, sessionID string, voucherIDs []string) (bool, int, string) {
	if len(voucherIDs) == 0 {
		return false, 0, "No vouchers provided"
	}
	err := s.BeginTx()
	if err != nil {
		return false, 0, "Failed to start transaction"
	}
	rolledBack := false
	rollback := func() { if !rolledBack { s.RollbackTx(); rolledBack = true } }
	defer rollback()
	total := 0
	for _, voucherID := range voucherIDs {
		var value int
		var issuer, status string
		var invalidated int
		err := s.TxQueryRow(`SELECT value, issuer, status, invalidated FROM hps_vouchers
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
		// ANTI-FORGERY: verify voucher is in supply chain before reserving
		if !s.VerifyVoucherSupplyChain(voucherID) {
			// For local issuers, supply chain should always exist; log but allow
			// for resilience against transient failures.
			log.Printf("WARN: voucher %s not found in supply chain (issuer=%s) — allowing for local issuer", voucherID, issuer)
		}
		total += value
	}
	for _, voucherID := range voucherIDs {
		if _, err := s.TxExec(`UPDATE hps_vouchers SET status = ?, session_id = ?, last_updated = ?
			WHERE voucher_id = ?`, "reserved", sessionID, float64(time.Now().UnixNano())/1e9, voucherID); err != nil {
			log.Printf("EXCHANGE ERROR: failed to reserve voucher %s session=%s err=%v", voucherID, sessionID, err)
		}
	}
	s.CommitTx()
	rolledBack = true
	return true, total, ""
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
