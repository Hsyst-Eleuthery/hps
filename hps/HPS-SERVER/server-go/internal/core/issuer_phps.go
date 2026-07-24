package core

import (
	"database/sql"
	"fmt"
	"math"
	"strings"
)

const IssuerRecheckFee = 2

func ComputePhpsPayout(principal int) int {
	if principal <= 0 {
		return 0
	}
	return int(math.Ceil(float64(principal) * 1.2))
}

func (s *Server) UpsertIssuerVerification(targetType, targetID, issuerServer, issuerPublicKey, issuerContractID, originalOwner, status, detail, verificationContractID, exceptionContractID, debtContractID string) {
	if targetType == "" || targetID == "" {
		return
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO issuer_verifications
		(target_type, target_id, issuer_server, issuer_public_key, issuer_contract_id, original_owner, status, detail, last_checked, verification_contract_id, exception_contract_id, debt_contract_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		targetType, targetID, issuerServer, issuerPublicKey, issuerContractID, originalOwner, status, detail, now(),
		verificationContractID, exceptionContractID, debtContractID)
}

func (s *Server) GetIssuerVerification(targetType, targetID string) map[string]any {
	if targetType == "" || targetID == "" {
		return nil
	}
	var issuerServer, issuerPublicKey, issuerContractID, originalOwner, status, detail, verificationContractID, exceptionContractID, debtContractID string
	var lastChecked float64
	err := s.DB.QueryRow(`SELECT issuer_server, issuer_public_key, issuer_contract_id, original_owner, status, detail, last_checked, verification_contract_id, exception_contract_id, debt_contract_id
		FROM issuer_verifications WHERE target_type = ? AND target_id = ?`,
		targetType, targetID).Scan(&issuerServer, &issuerPublicKey, &issuerContractID, &originalOwner, &status, &detail, &lastChecked, &verificationContractID, &exceptionContractID, &debtContractID)
	if err != nil {
		return nil
	}
	return map[string]any{
		"target_type":              targetType,
		"target_id":                targetID,
		"issuer_server":            issuerServer,
		"issuer_public_key":        issuerPublicKey,
		"issuer_contract_id":       issuerContractID,
		"original_owner":           originalOwner,
		"status":                   status,
		"detail":                   detail,
		"last_checked":             lastChecked,
		"verification_contract_id": verificationContractID,
		"exception_contract_id":    exceptionContractID,
		"debt_contract_id":         debtContractID,
	}
}

func (s *Server) LoadIssuerBinding(targetType, targetID string) map[string]any {
	switch targetType {
	case "content":
		var owner, issuerServer, issuerPublicKey, issuerContractID string
		var issuedAt float64
		err := s.DB.QueryRow(`SELECT username, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at
			FROM content WHERE content_hash = ?`, targetID).Scan(&owner, &issuerServer, &issuerPublicKey, &issuerContractID, &issuedAt)
		if err != nil {
			return nil
		}
		return map[string]any{
			"original_owner":     owner,
			"issuer_server":      issuerServer,
			"issuer_public_key":  issuerPublicKey,
			"issuer_contract_id": issuerContractID,
			"issuer_issued_at":   issuedAt,
		}
	case "domain":
		var owner, issuerServer, issuerPublicKey, issuerContractID string
		var issuedAt float64
		err := s.DB.QueryRow(`SELECT original_owner, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at
			FROM dns_records WHERE domain = ?`, targetID).Scan(&owner, &issuerServer, &issuerPublicKey, &issuerContractID, &issuedAt)
		if err != nil {
			return nil
		}
		return map[string]any{
			"original_owner":     owner,
			"issuer_server":      issuerServer,
			"issuer_public_key":  issuerPublicKey,
			"issuer_contract_id": issuerContractID,
			"issuer_issued_at":   issuedAt,
		}
	}
	return nil
}

func (s *Server) CreatePhpsDebt(reason, targetType, targetID, sourceContractID string, principal int) string {
	if principal <= 0 {
		return ""
	}
	debtID := NewUUID()
	payoutTotal := ComputePhpsPayout(principal)
	_, _ = s.DB.Exec(`INSERT INTO phps_debts
		(debt_id, reason, target_type, target_id, source_contract_id, principal, payout_total, reserved_amount, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		debtID, reason, targetType, targetID, sourceContractID, principal, payoutTotal, "open", now())
	s.SaveServerContract("pHPS_issue", []ContractDetail{
		{Key: "DEBT_ID", Value: debtID},
		{Key: "REASON", Value: reason},
		{Key: "TARGET_TYPE", Value: targetType},
		{Key: "TARGET_ID", Value: targetID},
		{Key: "PRINCIPAL", Value: principal},
		{Key: "PAYOUT_TOTAL", Value: payoutTotal},
		{Key: "SOURCE_CONTRACT_ID", Value: sourceContractID},
	}, debtID)
	return debtID
}

func (s *Server) AddCustodyFunds(amount int, reason string) {
	if amount <= 0 {
		return
	}
	s.IncrementEconomyStat("custody_balance", float64(amount))
	if reason != "" {
		s.RecordEconomyEvent(reason)
		s.RecordEconomyContract(reason)
	}
	s.TryRepayPhpsDebts()
}

func (s *Server) SpendCustodyFundsWithDebt(amount int, debtReason, targetType, targetID, sourceContractID string) int {
	if amount <= 0 {
		return 0
	}
	balance := s.GetEconomyStat("custody_balance", 0.0)
	available := int(math.Max(balance, 0))
	covered := amount
	if covered > available {
		covered = available
	}
	if covered > 0 {
		s.SetEconomyStat("custody_balance", balance-float64(covered))
	}
	shortfall := amount - covered
	if shortfall > 0 {
		_ = s.RegisterCustodyShortfall(debtReason, targetType, targetID, sourceContractID, shortfall)
	}
	return shortfall
}

func (s *Server) RegisterCustodyShortfall(reason, targetType, targetID, sourceContractID string, amount int) string {
	if amount <= 0 {
		return ""
	}
	balance := s.GetEconomyStat("custody_balance", 0.0)
	s.SetEconomyStat("custody_balance", balance-float64(amount))
	s.RecordEconomyEvent("custody_shortfall:" + reason)
	s.RecordEconomyContract("custody_shortfall:" + reason)
	return s.CreatePhpsDebt(reason, targetType, targetID, sourceContractID, amount)
}

func (s *Server) EmitVoucherOfferToUser(username string, value int, reason string, details []ContractDetail) (string, string) {
	if username == "" || value <= 0 {
		return "", ""
	}
	ownerKey := s.GetUserPublicKey(username)
	if ownerKey == "" {
		return "", ""
	}
	offer := s.CreateVoucherOffer(username, ownerKey, value, reason, nil, map[string]any{
		"type":   "custody_subsidy",
		"reason": reason,
	}, "")
	voucherID := asString(offer["voucher_id"])
	if len(details) > 0 {
		contractDetails := append([]ContractDetail{}, details...)
		contractDetails = append(contractDetails, ContractDetail{Key: "VOUCHER_ID", Value: voucherID})
		s.SaveServerContract("custody_subsidy", contractDetails, voucherID)
	}
	if s.UserEventEmitter != nil {
		s.UserEventEmitter(username, "hps_voucher_offer", offer)
	}
	return asString(offer["offer_id"]), voucherID
}

func (s *Server) IssueCustodyRefundWithDebt(username string, amount int, reason, targetType, targetID, sourceContractID string) (string, string) {
	if username == "" || amount <= 0 {
		return "", ""
	}
	shortfall := s.SpendCustodyFundsWithDebt(amount, "custody_refund:"+reason, targetType, targetID, sourceContractID)
	s.RecordEconomyEvent("custody_refund:" + reason)
	s.RecordEconomyContract("custody_refund:" + reason)
	_, voucherID := s.EmitVoucherOfferToUser(username, amount, "custody_refund:"+reason, []ContractDetail{
		{Key: "TARGET_TYPE", Value: targetType},
		{Key: "TARGET_ID", Value: targetID},
		{Key: "VALUE", Value: amount},
		{Key: "SOURCE_CONTRACT_ID", Value: sourceContractID},
		{Key: "SHORTFALL", Value: shortfall},
	})
	return "", voucherID
}

func (s *Server) OpenPhpsDebt(debtID, username, publicKey, fundingContractID string) bool {
	if debtID == "" || username == "" {
		return false
	}
	result, err := s.DB.Exec(`UPDATE phps_debts
		SET creditor_username = ?, creditor_public_key = ?, funding_contract_id = ?, status = ?, funded_at = ?
		WHERE debt_id = ? AND status = ?`,
		username, publicKey, fundingContractID, "funded", now(), debtID, "open")
	if err != nil {
		return false
	}
	rows, _ := result.RowsAffected()
	return rows > 0
}

func (s *Server) TryRepayPhpsDebts() {
	rows, err := s.DB.Query(`SELECT debt_id, principal, payout_total, reserved_amount, creditor_username, creditor_public_key, funding_contract_id
		FROM phps_debts WHERE status = ? ORDER BY funded_at ASC, created_at ASC`, "funded")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var debtID, creditorUsername, creditorPublicKey, fundingContractID string
		var principal, payoutTotal, reservedAmount int
		if rows.Scan(&debtID, &principal, &payoutTotal, &reservedAmount, &creditorUsername, &creditorPublicKey, &fundingContractID) != nil {
			continue
		}
		if creditorUsername == "" || payoutTotal <= 0 {
			continue
		}
		needed := payoutTotal - reservedAmount
		if needed <= 0 {
			needed = 0
		}
		if needed > 0 {
			balance := s.GetEconomyStat("custody_balance", 0.0)
			if balance > 0 {
				cover := int(math.Min(float64(needed), balance))
				if cover > 0 {
					_, _ = s.DB.Exec(`UPDATE phps_debts SET reserved_amount = reserved_amount + ? WHERE debt_id = ?`, cover, debtID)
					s.SetEconomyStat("custody_balance", balance-float64(cover))
					reservedAmount += cover
				}
			}
		}
		if reservedAmount < payoutTotal {
			continue
		}
		if creditorPublicKey == "" {
			creditorPublicKey = s.GetUserPublicKey(creditorUsername)
		}
		if creditorPublicKey == "" {
			continue
		}
		offer := s.CreateVoucherOffer(creditorUsername, creditorPublicKey, payoutTotal, "phps_payout:"+debtID, nil, map[string]any{
			"type":    "phps_payout",
			"debt_id": debtID,
		}, "")
		voucherID := asString(offer["voucher_id"])
		_, _ = s.DB.Exec(`UPDATE phps_debts
			SET status = ?, payout_voucher_id = ?, repaid_at = ?
			WHERE debt_id = ?`, "repaid", voucherID, now(), debtID)
		s.SaveServerContract("pHPS_repaid", []ContractDetail{
			{Key: "DEBT_ID", Value: debtID},
			{Key: "PAYOUT_TOTAL", Value: payoutTotal},
			{Key: "PRINCIPAL", Value: principal},
			{Key: "FUNDING_CONTRACT_ID", Value: fundingContractID},
			{Key: "PAYOUT_VOUCHER_ID", Value: voucherID},
		}, debtID)
		if s.UserEventEmitter != nil {
			s.UserEventEmitter(creditorUsername, "hps_voucher_offer", offer)
		}
	}
}

func (s *Server) BuildPhpsMarketPayload(username string) map[string]any {
	s.TryRepayPhpsDebts()
	rows, err := s.DB.Query(`SELECT debt_id, reason, target_type, target_id, source_contract_id, principal, payout_total, reserved_amount,
		creditor_username, funding_contract_id, payout_voucher_id, status, created_at, funded_at, repaid_at
		FROM phps_debts ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return map[string]any{
			"success": false,
			"error":   err.Error(),
		}
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	myItems := make([]map[string]any, 0)
	for rows.Next() {
		var debtID, reason, targetType, targetID, sourceContractID, creditorUsername, fundingContractID, payoutVoucherID, status string
		var principal, payoutTotal, reservedAmount int
		var createdAt, fundedAt, repaidAt float64
		if rows.Scan(&debtID, &reason, &targetType, &targetID, &sourceContractID, &principal, &payoutTotal, &reservedAmount,
			&creditorUsername, &fundingContractID, &payoutVoucherID, &status, &createdAt, &fundedAt, &repaidAt) != nil {
			continue
		}
		item := map[string]any{
			"debt_id":             debtID,
			"reason":              reason,
			"target_type":         targetType,
			"target_id":           targetID,
			"source_contract_id":  sourceContractID,
			"principal":           principal,
			"payout_total":        payoutTotal,
			"reserved_amount":     reservedAmount,
			"remaining_reserved":  maxInt(0, payoutTotal-reservedAmount),
			"creditor_username":   creditorUsername,
			"funding_contract_id": fundingContractID,
			"payout_voucher_id":   payoutVoucherID,
			"status":              status,
			"created_at":          createdAt,
			"funded_at":           fundedAt,
			"repaid_at":           repaidAt,
			"is_open":             status == "open",
		}
		items = append(items, item)
		if username != "" && strings.EqualFold(username, creditorUsername) {
			myItems = append(myItems, item)
		}
	}
	return map[string]any{
		"success":         true,
		"custody_balance": s.GetEconomyStat("custody_balance", 0.0),
		"items":           items,
		"my_items":        myItems,
	}
}

func (s *Server) FundPhpsDebt(username, publicKey, debtID, contractID string, voucherIDs []string, paidAmount int) (map[string]any, string) {
	if username == "" || debtID == "" {
		return nil, "Dados insuficientes"
	}
	var principal int
	var status string
	err := s.DB.QueryRow(`SELECT principal, status FROM phps_debts WHERE debt_id = ?`, debtID).Scan(&principal, &status)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, "Dívida não encontrada"
		}
		return nil, err.Error()
	}
	if status != "open" {
		return nil, "Essa dívida já foi assumida"
	}
	if principal <= 0 || paidAmount < principal {
		return nil, "Valor insuficiente"
	}
	sessionID := "phps-" + NewUUID()
	okReserve, totalValue, reserveErr := s.ReserveVouchersForSession(username, sessionID, voucherIDs)
	if !okReserve {
		return nil, reserveErr
	}
	if totalValue < principal {
		s.ReleaseVouchersForSession(sessionID)
		return nil, "Saldo insuficiente"
	}
	s.MarkVouchersSpent(sessionID)
	changeValue := totalValue - principal
	if changeValue > 0 {
		s.IssueChangeOffer(username, changeValue, "phps_fund_change:"+debtID, sessionID, "phps_fund_change", []ContractDetail{
			{Key: "DEBT_ID", Value: debtID},
			{Key: "PAYER", Value: username},
			{Key: "VOUCHERS", Value: CanonicalJSON(voucherIDs)},
		})
	}
	if !s.OpenPhpsDebt(debtID, username, publicKey, contractID) {
		return nil, "Não foi possível assumir a dívida"
	}
	s.AddCustodyFunds(principal, "phps_fund")
	s.SaveServerContract("pHPS_funded", []ContractDetail{
		{Key: "DEBT_ID", Value: debtID},
		{Key: "PAYER", Value: username},
		{Key: "PRINCIPAL", Value: principal},
		{Key: "VOUCHERS", Value: CanonicalJSON(voucherIDs)},
		{Key: "FUNDING_CONTRACT_ID", Value: contractID},
	}, debtID)
	return s.BuildPhpsMarketPayload(username), ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *Server) PurchasePhpsTitle(username, publicKey string, purchasePrice int, voucherIDs []string, contractID string) (map[string]any, string) {
	if username == "" || purchasePrice <= 0 {
		return nil, "Parâmetros inválidos"
	}

	sessionID := "phps-title-" + NewUUID()
	okReserve, totalValue, reserveErr := s.ReserveVouchersForSession(username, sessionID, voucherIDs)
	if !okReserve {
		return nil, reserveErr
	}
	if totalValue < purchasePrice {
		s.ReleaseVouchersForSession(sessionID)
		return nil, "Saldo insuficiente"
	}

	s.MarkVouchersSpent(sessionID)

	totalMinted := s.GetEconomyStat("total_minted", 1.0)
	totalBurned := s.GetEconomyStat("total_burned", 0.0)
	circulatingSupply := math.Max(1.0, totalMinted-totalBurned)
	outstandingDebt := s.GetOutstandingPhpsDebt()

	burnImpact := float64(purchasePrice) / circulatingSupply
	projectedSubsidy := s.ComputeProjectedSubsidy()
	savings := burnImpact * projectedSubsidy

	needFactor := outstandingDebt / math.Max(1.0, outstandingDebt+circulatingSupply*0.01)
	if outstandingDebt <= 0 {
		effRate := s.GetEffectiveInflationRate()
		needFactor = math.Min(1.0, effRate/10.0)
	}
	if needFactor < 0.05 {
		needFactor = 0.05
	}
	if needFactor > 1.0 {
		needFactor = 1.0
	}

	maxReturn := int(math.Ceil(savings * needFactor))
	if maxReturn < 1 {
		maxReturn = 1
	}

	liquidityPremiumRate := 0.01 + (0.09 * needFactor)

	s.RecordBurn(purchasePrice, "phps_title_purchase")

	changeValue := totalValue - purchasePrice
	if changeValue > 0 {
		s.IssueChangeOffer(username, changeValue, "phps_title_change:"+contractID, sessionID, "phps_title_change", []ContractDetail{
			{Key: "PURCHASER", Value: username},
			{Key: "PURCHASE_PRICE", Value: purchasePrice},
		})
	}

	titleID := NewUUID()
	nowTs := now()
	_, _ = s.DB.Exec(`INSERT INTO phps_titles
		(title_id, holder_username, holder_public_key, share_percent, purchase_price, max_return,
		 liquidity_premium_rate, status, created_at, last_payout_at)
		VALUES (?, ?, ?, 1.0, ?, ?, ?, 'active', ?, ?)`,
		titleID, username, publicKey, purchasePrice, maxReturn,
		liquidityPremiumRate, nowTs, nowTs)

	s.SaveServerContract("phps_title_purchase", []ContractDetail{
		{Key: "TITLE_ID", Value: titleID},
		{Key: "PURCHASER", Value: username},
		{Key: "PURCHASE_PRICE", Value: purchasePrice},
		{Key: "MAX_RETURN", Value: maxReturn},
		{Key: "LIQUIDITY_PREMIUM_RATE", Value: liquidityPremiumRate},
		{Key: "NEED_FACTOR", Value: needFactor},
		{Key: "SAVINGS", Value: savings},
		{Key: "VOUCHERS", Value: CanonicalJSON(voucherIDs)},
	}, titleID)

	return map[string]any{
		"title_id":              titleID,
		"holder":                username,
		"purchase_price":        purchasePrice,
		"max_return":            maxReturn,
		"liquidity_premium_rate": liquidityPremiumRate,
		"total_investment":      purchasePrice,
		"total_return_cap":      purchasePrice + maxReturn,
	}, ""
}

func (s *Server) ComputeProjectedSubsidy() float64 {
	totalMinted := s.GetEconomyStat("total_minted", 0.0)
	multiplier := s.GetEconomyMultiplier()
	avgCost := totalMinted / 100.0
	if avgCost < 1 {
		avgCost = 1
	}
	return avgCost * (multiplier - 1.0) * 100.0
}

func (s *Server) RedeemPhpsTitle(titleID, username string) (map[string]any, string) {
	if titleID == "" || username == "" {
		return nil, "Parâmetros inválidos"
	}

	var storedHolder string
	var purchasePrice, maxReturn, totalEarned int
	var liquidityPremiumRate float64
	var status string
	var createdAt float64

	err := s.DB.QueryRow(`SELECT holder_username, purchase_price, max_return, total_earned,
		liquidity_premium_rate, status, created_at FROM phps_titles WHERE title_id = ?`, titleID).
		Scan(&storedHolder, &purchasePrice, &maxReturn, &totalEarned, &liquidityPremiumRate, &status, &createdAt)
	if err != nil {
		return nil, "Título não encontrado"
	}
	if storedHolder != username {
		return nil, "Este título não pertence a você"
	}
	if status != "active" {
		return nil, "Título já foi resgatado ou concluído"
	}

	timeServed := now() - createdAt
	expectedLifespan := 30.0 * 86400.0
	if expectedLifespan <= 0 {
		expectedLifespan = 86400.0
	}
	timeFactor := math.Min(1.0, timeServed/expectedLifespan)

	progressFactor := 0.0
	if maxReturn > 0 {
		progressFactor = math.Min(1.0, float64(totalEarned)/float64(maxReturn))
	}

	basePremium := int(math.Ceil(float64(purchasePrice) * liquidityPremiumRate * timeFactor))
	earnedPremium := int(math.Ceil(float64(maxReturn) * progressFactor * timeFactor))
	liquidityPremium := basePremium + earnedPremium
	if liquidityPremium > maxReturn {
		liquidityPremium = maxReturn
	}
	if liquidityPremium < 1 {
		liquidityPremium = 1
	}

	totalPayout := purchasePrice + liquidityPremium

	ownerKey := s.GetUserPublicKey(username)
	if ownerKey == "" {
		return nil, "Chave pública não encontrada"
	}

	s.CreateVoucherOffer(username, ownerKey, totalPayout,
		"phps_title_redeem:"+titleID, nil,
		map[string]any{
			"type":              "phps_title_redeem",
			"title_id":          titleID,
			"purchase_price":    purchasePrice,
			"liquidity_premium": liquidityPremium,
			"total_payout":      totalPayout,
		}, "")

	_, _ = s.DB.Exec(`UPDATE phps_titles
		SET status = 'redeemed', expires_at = ?
		WHERE title_id = ?`, now(), titleID)

	s.SaveServerContract("phps_title_redeem", []ContractDetail{
		{Key: "TITLE_ID", Value: titleID},
		{Key: "HOLDER", Value: username},
		{Key: "PURCHASE_PRICE", Value: purchasePrice},
		{Key: "LIQUIDITY_PREMIUM", Value: liquidityPremium},
		{Key: "TOTAL_PAYOUT", Value: totalPayout},
		{Key: "TOTAL_EARNED", Value: totalEarned},
		{Key: "TIME_SERVED", Value: timeServed},
	}, titleID)

	return map[string]any{
		"title_id":          titleID,
		"purchase_price":    purchasePrice,
		"liquidity_premium": liquidityPremium,
		"total_payout":      totalPayout,
		"total_earned":      totalEarned,
		"time_served_secs":  timeServed,
	}, ""
}

func (s *Server) GetPhpsTitlesForUser(username string) []map[string]any {
	rows, err := s.DB.Query(`SELECT title_id, holder_username, share_percent, purchase_price, total_earned, created_at, expires_at
		FROM phps_titles WHERE holder_username = ? AND status = 'active'`, username)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var titles []map[string]any
	for rows.Next() {
		var titleID, holder string
		var sharePct float64
		var purchasePrice, totalEarned int
		var createdAt, expiresAt float64
		if rows.Scan(&titleID, &holder, &sharePct, &purchasePrice, &totalEarned, &createdAt, &expiresAt) != nil {
			continue
		}
		titles = append(titles, map[string]any{
			"title_id":       titleID,
			"holder":         holder,
			"share_percent":  sharePct,
			"purchase_price": purchasePrice,
			"total_earned":   totalEarned,
			"created_at":     createdAt,
			"expires_at":     expiresAt,
		})
	}
	return titles
}

func (s *Server) BuildPhpsMarketPayloadV2(username string) map[string]any {
	s.TryRepayPhpsDebts()

	rows, err := s.DB.Query(`SELECT debt_id, reason, target_type, target_id, source_contract_id, principal, payout_total, reserved_amount,
		creditor_username, funding_contract_id, payout_voucher_id, status, created_at, funded_at, repaid_at
		FROM phps_debts ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return map[string]any{"success": false, "error": err.Error()}
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	myItems := make([]map[string]any, 0)
	for rows.Next() {
		var debtID, reason, targetType, targetID, sourceContractID, creditorUsername, fundingContractID, payoutVoucherID, status string
		var principal, payoutTotal, reservedAmount int
		var createdAt, fundedAt, repaidAt float64
		if rows.Scan(&debtID, &reason, &targetType, &targetID, &sourceContractID, &principal, &payoutTotal, &reservedAmount,
			&creditorUsername, &fundingContractID, &payoutVoucherID, &status, &createdAt, &fundedAt, &repaidAt) != nil {
			continue
		}
		item := map[string]any{
			"debt_id":             debtID,
			"reason":              reason,
			"target_type":         targetType,
			"target_id":           targetID,
			"source_contract_id":  sourceContractID,
			"principal":           principal,
			"payout_total":        payoutTotal,
			"reserved_amount":     reservedAmount,
			"remaining_reserved":  maxInt(0, payoutTotal-reservedAmount),
			"creditor_username":   creditorUsername,
			"funding_contract_id": fundingContractID,
			"payout_voucher_id":   payoutVoucherID,
			"status":              status,
			"created_at":          createdAt,
			"funded_at":           fundedAt,
			"repaid_at":           repaidAt,
			"is_open":             status == "open",
		}
		items = append(items, item)
		if username != "" && strings.EqualFold(username, creditorUsername) {
			myItems = append(myItems, item)
		}
	}

	var titles []map[string]any
	if username != "" {
		titles = s.GetPhpsTitlesForUser(username)
	}
	allTitles := s.GetAllActiveTitles()

	return map[string]any{
		"success":           true,
		"custody_balance":   s.GetEconomyStat("custody_balance", 0.0),
		"subsidy_price":     s.ComputeSubsidyPrice(),
		"subsidy_share":     s.GetCustodySubsidyShare(),
		"inflation_rate":    s.GetEffectiveInflationRate(),
		"items":             items,
		"my_items":          myItems,
		"my_titles":         titles,
		"active_titles":     allTitles,
		"total_burned":      s.GetEconomyStat("total_burned", 0.0),
		"total_minted":      s.GetEconomyStat("total_minted", 0.0),
	}
}

func (s *Server) GetAllActiveTitles() []map[string]any {
	rows, err := s.DB.Query(`SELECT title_id, holder_username, share_percent, purchase_price, total_earned, created_at
		FROM phps_titles WHERE status = 'active' ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var titles []map[string]any
	for rows.Next() {
		var titleID, holder string
		var sharePct float64
		var purchasePrice, totalEarned int
		var createdAt float64
		if rows.Scan(&titleID, &holder, &sharePct, &purchasePrice, &totalEarned, &createdAt) != nil {
			continue
		}
		titles = append(titles, map[string]any{
			"title_id":       titleID,
			"holder":         holder,
			"share_percent":  sharePct,
			"purchase_price": purchasePrice,
			"total_earned":   totalEarned,
			"created_at":     createdAt,
		})
	}
	return titles
}

func (s *Server) BuildIssuerVerificationContract(actionType, targetType, targetID, issuerServer, issuerContractID, status, detail, originalOwner string) string {
	return s.SaveServerContract(actionType, []ContractDetail{
		{Key: "TARGET_TYPE", Value: targetType},
		{Key: "TARGET_ID", Value: targetID},
		{Key: "ISSUER_SERVER", Value: issuerServer},
		{Key: "ISSUER_CONTRACT_ID", Value: issuerContractID},
		{Key: "STATUS", Value: status},
		{Key: "DETAIL", Value: detail},
		{Key: "ORIGINAL_OWNER", Value: originalOwner},
	}, fmt.Sprintf("%s:%s", targetType, targetID))
}
