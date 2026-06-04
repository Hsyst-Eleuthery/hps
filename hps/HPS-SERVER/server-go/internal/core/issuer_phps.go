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
