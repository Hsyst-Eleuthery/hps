package core

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"time"
)

func (s *Server) AuthorizePowOrHPS(clientIdentifier, username, actionType, powNonce string, hashrateObserved float64, hpsPayment map[string]any) (bool, string, bool, map[string]any) {
	if s.IsUserFraudRestricted(username) {
		return false, "Conta restrita por fraude; apenas cambio permitido", false, nil
	}
	if strings.TrimSpace(powNonce) != "" {
		if valid, powInfo := s.VerifyPowSolutionDetails(clientIdentifier, powNonce, hashrateObserved, actionType); valid {
			if actionType != "hps_mint" && actionType != "login" {
				powInfo = castMap(powInfo)
				powInfo["nonce"] = powNonce
				powValue := s.GetHpsPowCostWithDiscount(actionType, false)
				if powValue > 0 {
					s.IssueCustodyVoucher(powValue, "pow:"+actionType, powInfo, map[string]any{
						"type":   "pow_action",
						"action": actionType,
						"user":   username,
					})
				}
			}
			return true, "", false, nil
		}
		if len(hpsPayment) > 0 {
			return s.SpendHPSForAction(username, hpsPayment, actionType)
		}
		return false, "Invalid PoW solution", true, nil
	}
	if len(hpsPayment) > 0 {
		return s.SpendHPSForAction(username, hpsPayment, actionType)
	}
	return false, "Missing PoW or HPS payment", false, nil
}

func (s *Server) ReassignMinerForTransfer(transferID, excludeUser string) string {
	_ = excludeUser
	var miner string
	_ = s.DB.QueryRow(`SELECT ms.username FROM miner_stats ms
		WHERE (ms.banned_until IS NULL OR ms.banned_until < ?)
		AND NOT EXISTS (
			SELECT 1 FROM miner_pending_sigs mps
			WHERE mps.username = ms.username AND mps.blocked_until > ?
		)
		ORDER BY ms.pending_signatures ASC, ms.last_updated ASC LIMIT 1`, now(), now()).Scan(&miner)
	if miner == "" {
		return ""
	}
	s.InitMinerPendingSig(miner)
	maxTxTime := s.GetMinerMaxTxTime(miner)
	if maxTxTime < s.cfg.MinTxTimeSeconds {
		maxTxTime = s.cfg.MinTxTimeSeconds
	}
	if maxTxTime > s.cfg.MaxTxTimeSeconds {
		maxTxTime = s.cfg.MaxTxTimeSeconds
	}
	_, _ = s.DB.Exec(`UPDATE monetary_transfers
		SET assigned_miner = ?, miner_deadline = ?, status = ?
		WHERE transfer_id = ?`, miner, now()+maxTxTime, "pending_signature", transferID)
	s.SetMinerBlocked(miner, maxTxTime)
	return miner
}

func (s *Server) SettleMinerSignature(transferID, miner string, contractContent []byte, signature string) error {
	transfer := s.GetMonetaryTransferByID(transferID)
	if transfer == nil {
		return nil
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO transfer_signatures
		(signature_id, transfer_id, miner, signature, contract_content, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, NewUUID(), transferID, miner, signature, base64.StdEncoding.EncodeToString(contractContent), now())
	_, _ = s.DB.Exec(`UPDATE monetary_transfers
		SET status = ?, signed_by = ?, signed_at = ?, miner_deadline = NULL
		WHERE transfer_id = ?`, "signed", miner, now(), transferID)

	resolved := s.ResolveMinerDebtEntriesLimited(miner, []string{"signature_immediate", "signature_last_resort"}, 1)
	if len(resolved) > 0 {
		s.SyncMinerPendingCounts(miner)
	} else {
		s.InitMinerPendingSig(miner)
		_, _ = s.DB.Exec(`UPDATE miner_pending_sigs
			SET negative_balance = negative_balance + 1,
			    last_signed_at = ?, updated_at = ?
			WHERE username = ?`, now(), now(), miner)
	}

	pendingSig := s.GetMinerPendingSig(miner)
	pendingCount := asInt(pendingSig["pending_count"])
	negBalance := asInt(pendingSig["negative_balance"])
	if pendingCount <= 0 && negBalance >= 0 {
		s.UnblockMiner(miner)
		s.ReleaseWithheldOffersForMiner(miner)
	}

	s.UnlockTransferVouchers(transferID)
	s.PayMinerSignatureFee(transfer, miner)
	s.PaySelectorFee(transfer)
	return nil
}

func (s *Server) ProcessPendingMonetaryAction(transferID string) {
	action := s.GetPendingMonetaryAction(transferID)
	if action == nil {
		return
	}
	if asString(action["status"]) != "pending" {
		return
	}
	actionID := asString(action["action_id"])
	s.UpdatePendingMonetaryActionStatus(actionID, "processing")
	payload := castMap(action["payload"])
	paymentInfo := castMap(payload["payment"])
	if err := s.FinalizeSpendHPSPayment(paymentInfo); err != nil {
		s.UpdatePendingMonetaryActionStatus(actionID, "failed")
		return
	}
	s.UpdatePendingMonetaryActionStatus(actionID, "completed")
}

func (s *Server) ExtendMinerDeadline(transferID string, extraSeconds float64) {
	var current sql.NullFloat64
	err := s.DB.QueryRow(`SELECT miner_deadline FROM monetary_transfers WHERE transfer_id = ?`, transferID).Scan(&current)
	if err != nil {
		return
	}
	base := now()
	if current.Valid && current.Float64 > base {
		base = current.Float64
	}
	_, _ = s.DB.Exec(`UPDATE monetary_transfers SET miner_deadline = ? WHERE transfer_id = ?`, base+extraSeconds, transferID)
}

func (s *Server) BanClient(clientIdentifier string, durationSeconds float64, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	banUntil := float64(time.Now().Unix()) + durationSeconds
	s.BannedClients[clientIdentifier] = banUntil
	// M-03 FIX: Persist ban to DB (survives restart)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO rate_limits 
		(client_identifier, action_type, last_action, attempt_count, ban_until) 
		VALUES (?, 'ban', ?, 0, ?)`,
		clientIdentifier, time.Now().Unix(), banUntil)
	_ = reason
}

func (s *Server) GetTransferByVoucherID(voucherID string) map[string]any {
	if voucherID == "" {
		return nil
	}
	var transferID string
	err := s.DB.QueryRow(`SELECT transfer_id FROM monetary_transfers
		WHERE locked_voucher_ids LIKE ? ORDER BY created_at DESC LIMIT 1`, "%"+voucherID+"%").Scan(&transferID)
	if err != nil || transferID == "" {
		return nil
	}
	return s.GetMonetaryTransferByID(transferID)
}

func (s *Server) GetMonetaryTransferByID(transferID string) map[string]any {
	var transferType, sender, receiver, status, contractID, lockedVoucherIDs, assignedMiner, feeSource, interPayload string
	var selectorUsername, selectorStatus sql.NullString
	var selectorRewarded sql.NullInt64
	var selectorFeeAmount int
	var amount, feeAmount int
	var createdAt, signedAt sql.NullFloat64
	err := s.DB.QueryRow(`SELECT transfer_type, sender, receiver, amount, status, contract_id, locked_voucher_ids,
		assigned_miner, fee_amount, selector_fee_amount, fee_source, inter_server_payload, selector_username, selector_status, selector_rewarded, created_at, signed_at
		FROM monetary_transfers WHERE transfer_id = ?`, transferID).
		Scan(&transferType, &sender, &receiver, &amount, &status, &contractID, &lockedVoucherIDs,
			&assignedMiner, &feeAmount, &selectorFeeAmount, &feeSource, &interPayload, &selectorUsername, &selectorStatus, &selectorRewarded, &createdAt, &signedAt)
	if err != nil {
		return nil
	}
	return map[string]any{
		"transfer_id":          transferID,
		"transfer_type":        transferType,
		"sender":               sender,
		"receiver":             receiver,
		"amount":               amount,
		"status":               status,
		"contract_id":          contractID,
		"locked_voucher_ids":   parseJSONStrSlice(lockedVoucherIDs),
		"assigned_miner":       assignedMiner,
		"fee_amount":           feeAmount,
		"selector_fee_amount":  selectorFeeAmount,
		"fee_source":           feeSource,
		"inter_server_payload": parseJSONMapAny(interPayload),
		"selector_username": func() any {
			if selectorUsername.Valid {
				return selectorUsername.String
			}
			return ""
		}(),
		"selector_status": func() any {
			if selectorStatus.Valid {
				return selectorStatus.String
			}
			return ""
		}(),
		"selector_rewarded": func() any {
			if selectorRewarded.Valid {
				return selectorRewarded.Int64
			}
			return int64(0)
		}(),
	}
}

func (s *Server) GetMonetaryTransferByContract(contractID, transferType string) map[string]any {
	if contractID == "" || transferType == "" {
		return nil
	}
	var transferID string
	err := s.DB.QueryRow(`SELECT transfer_id FROM monetary_transfers
		WHERE contract_id = ? AND transfer_type = ?
		ORDER BY created_at DESC LIMIT 1`, contractID, transferType).Scan(&transferID)
	if err != nil || transferID == "" {
		return nil
	}
	return s.GetMonetaryTransferByID(transferID)
}

func (s *Server) LockTransferVouchers(transferID string) {
	_, _ = s.DB.Exec(`UPDATE hps_vouchers
		SET status = ?, last_updated = ?
		WHERE voucher_id IN (
			SELECT value FROM json_each((SELECT locked_voucher_ids FROM monetary_transfers WHERE transfer_id = ?))
		)`, "locked", now(), transferID)
}

func (s *Server) UnlockTransferVouchers(transferID string) {
	_, _ = s.DB.Exec(`UPDATE hps_vouchers
		SET status = ?, last_updated = ?
		WHERE voucher_id IN (
			SELECT value FROM json_each((SELECT locked_voucher_ids FROM monetary_transfers WHERE transfer_id = ?))
		) AND status = ?`, "valid", now(), transferID, "locked")
}

func (s *Server) PayMinerSignatureFee(transfer map[string]any, miner string) {
	feeAmount := asInt(transfer["fee_amount"])
	if feeAmount <= 0 || miner == "" {
		return
	}
	if s.cfg.VolatileFees {
		feeAmount = s.ApplyMinerVolatileFee(miner, feeAmount)
	}
	feeSource := asString(transfer["fee_source"])
	if feeSource == "custody" || asString(transfer["receiver"]) == CustodyUsername {
		custodyBalance := s.GetEconomyStat("custody_balance", 0.0)
		if custodyBalance > 0 {
			next := custodyBalance - float64(feeAmount)
			if next < 0 {
				next = 0
			}
			s.SetEconomyStat("custody_balance", next)
		}
	}
	ownerKey := s.GetUserPublicKey(miner)
	if ownerKey == "" {
		return
	}
	s.CreateVoucherOffer(
		miner,
		ownerKey,
		feeAmount,
		"signature_fee:"+asString(transfer["transfer_id"]),
		nil,
		map[string]any{"type": "signature_fee", "transfer_id": asString(transfer["transfer_id"])},
		"",
	)
	s.RecordEconomyEvent("miner_signature_fee")
	s.RecordEconomyContract("miner_signature_fee")
}

func (s *Server) PaySelectorFee(transfer map[string]any) {
	selector := asString(transfer["selector_username"])
	selectorFee := asInt(transfer["selector_fee_amount"])
	if selectorFee <= 0 || selector == "" {
		return
	}
	if asInt(transfer["selector_rewarded"]) != 0 {
		return
	}
	if s.cfg.VolatileFees {
		selectorFee = s.ApplyMinerVolatileFee(selector, selectorFee)
	}
	feeSource := asString(transfer["fee_source"])
	if feeSource == "custody" || asString(transfer["receiver"]) == CustodyUsername {
		custodyBalance := s.GetEconomyStat("custody_balance", 0.0)
		if custodyBalance > 0 {
			next := custodyBalance - float64(selectorFee)
			if next < 0 {
				next = 0
			}
			s.SetEconomyStat("custody_balance", next)
		}
	}
	ownerKey := s.GetUserPublicKey(selector)
	if ownerKey == "" {
		return
	}
	s.CreateVoucherOffer(
		selector,
		ownerKey,
		selectorFee,
		"selector_fee:"+asString(transfer["transfer_id"]),
		nil,
		map[string]any{"type": "selector_fee", "transfer_id": asString(transfer["transfer_id"])},
		"",
	)
	_, _ = s.DB.Exec(`UPDATE monetary_transfers SET selector_rewarded = 1 WHERE transfer_id = ?`, asString(transfer["transfer_id"]))
	s.AdjustReputation(selector, 10)
	s.RecordEconomyEvent("selector_fee")
	s.RecordEconomyContract("selector_fee")
}

func parseJSONStrSlice(raw string) []string {
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func parseJSONMapAny(raw string) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func (s *Server) SpendHPSForAction(username string, hpsPayment map[string]any, actionType string) (bool, string, bool, map[string]any) {
	cost := s.GetHpsPowCostWithDiscount(actionType, true)
	return s.SpendHPSForActionWithCost(username, hpsPayment, actionType, cost)
}

func (s *Server) SpendHPSForActionWithCost(username string, hpsPayment map[string]any, actionType string, cost int) (bool, string, bool, map[string]any) {
	if cost <= 0 {
		return false, "HPS cost not configured", false, nil
	}
	voucherIDs := toStringSliceAny(hpsPayment["voucher_ids"])
	contractContentB64 := asString(hpsPayment["contract_content"])
	if contractContentB64 == "" {
		return false, "Missing spend contract", false, nil
	}
	contractContent, err := base64.StdEncoding.DecodeString(contractContentB64)
	if err != nil {
		return false, "Invalid spend contract: invalid base64", false, nil
	}
	valid, errorMsg, contractInfo := ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		return false, "Invalid spend contract: " + errorMsg, false, nil
	}
	if contractInfo.Action != "spend_hps" {
		return false, "Invalid spend contract action", false, nil
	}
	if contractInfo.User != username {
		return false, "Spend contract user mismatch", false, nil
	}
	if !s.VerifyContractSignature(contractContent, username, contractInfo.Signature, "") {
		return false, "Invalid spend contract signature", false, nil
	}
	contractActionType := strings.TrimSpace(ExtractContractDetail(contractInfo, "ACTION_TYPE"))
	if contractActionType != "" && contractActionType != actionType {
		return false, "Spend contract action type mismatch", false, nil
	}
	contractCost := ExtractContractDetail(contractInfo, "COST")
	if contractCost != "" {
		contractCostValue := int(asFloat(contractCost))
		if contractCostValue < cost {
			return false, "Spend contract cost mismatch", false, nil
		}
	}
	contractVouchers := ExtractContractDetail(contractInfo, "VOUCHERS")
	if contractVouchers != "" {
		contractList := parseJSONStrSlice(contractVouchers)
		if !sameStringSet(contractList, voucherIDs) {
			return false, "Spend contract vouchers mismatch", false, nil
		}
	}
	contractID := s.SaveContract("spend_hps", "", "", username, contractInfo.Signature, contractContent)
	sessionID := "pow-" + NewUUID()
	okReserve, totalValue, reserveError := s.ReserveVouchersForSession(username, sessionID, voucherIDs)
	if !okReserve {
		return false, reserveError, false, nil
	}
	actualCost := cost
	if totalValue < actualCost {
		s.ReleaseVouchersForSession(sessionID)
		return false, "Insufficient HPS balance", false, nil
	}
	if isImmediateSpendHpsAction(actionType) {
		paymentInfo := map[string]any{
			"session_id":  sessionID,
			"contract_id": contractID,
			"voucher_ids": voucherIDs,
			"actual_cost": actualCost,
			"total_value": totalValue,
			"action_type": actionType,
			"username":    username,
		}
		if err := s.FinalizeSpendHPSPayment(paymentInfo); err != nil {
			s.ReleaseVouchersForSession(sessionID)
			return false, err.Error(), false, nil
		}
		return true, "", false, nil
	}
	feeAmount, selectorFee, feeSource, _ := s.AllocateSignatureFees(actualCost)
	transferID := s.CreateMonetaryTransfer(
		"spend_hps:"+actionType,
		username,
		CustodyUsername,
		actualCost,
		voucherIDs,
		contractID,
		feeAmount,
		selectorFee,
		feeSource,
		nil,
	)
	pendingInfo := map[string]any{
		"transfer_id": transferID,
		"session_id":  sessionID,
		"contract_id": contractID,
		"voucher_ids": voucherIDs,
		"actual_cost": actualCost,
		"total_value": totalValue,
		"action_type": actionType,
		"username":    username,
	}
	return true, "", false, pendingInfo
}

func isImmediateSpendHpsAction(actionType string) bool {
	switch strings.ToLower(strings.TrimSpace(actionType)) {
	case "upload", "dns", "report", "hps_mint", "register_dns", "report_content", "publish_content":
		return true
	default:
		return false
	}
}

func (s *Server) CreateMonetaryTransfer(transferType, sender, receiver string, amount int, lockedVoucherIDs []string, contractID string, feeAmount int, selectorFee int, feeSource string, interServerPayload map[string]any) string {
	transferID := NewUUID()
	nowTs := now()
	lockedRaw, _ := json.Marshal(lockedVoucherIDs)
	interRaw, _ := json.Marshal(interServerPayload)
	maxTxTime := s.cfg.MaxTxTimeSeconds
	if maxTxTime <= 0 {
		maxTxTime = 120.0
	}
	_, _ = s.DB.Exec(`INSERT INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, assigned_miner, deadline, miner_deadline, fee_amount, selector_fee_amount, fee_source, inter_server_payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transferID, transferType, sender, receiver, amount, nowTs, "awaiting_selector", contractID, string(lockedRaw), "", nowTs+maxTxTime, 0.0, feeAmount, selectorFee, feeSource, string(interRaw))
	return transferID
}

func (s *Server) FinalizeSpendHPSPayment(paymentInfo map[string]any) error {
	sessionID := asString(paymentInfo["session_id"])
	username := asString(paymentInfo["username"])
	voucherIDs := toStringSliceAny(paymentInfo["voucher_ids"])
	actualCost := asInt(paymentInfo["actual_cost"])
	totalValue := asInt(paymentInfo["total_value"])
	actionType := asString(paymentInfo["action_type"])
	contractID := asString(paymentInfo["contract_id"])
	if sessionID == "" || username == "" {
		return nil
	}
	// Verify supply chain for each voucher before spending
	for _, vid := range voucherIDs {
		if !s.VerifyVoucherSupplyChain(vid) {
			return nil
		}
	}
	s.MarkVouchersSpent(sessionID)
	s.RecordBurn(actualCost, "spend_hps:"+actionType)
	s.AllocateEconomyRevenueWithVouchers(actualCost, "spend_hps:"+actionType, voucherIDs)
	s.SaveServerContract("hps_spend_receipt", []ContractDetail{
		{Key: "PAYER", Value: username},
		{Key: "ACTION", Value: actionType},
		{Key: "COST", Value: actualCost},
		{Key: "VOUCHERS", Value: CanonicalJSON(voucherIDs)},
		{Key: "CONTRACT_ID", Value: contractID},
	}, sessionID)
	changeValue := totalValue - actualCost
	if changeValue > 0 {
		s.IssueChangeOffer(
			username,
			changeValue,
			"spend_hps_change:"+actionType,
			sessionID,
			"hps_spend_refund",
			[]ContractDetail{
				{Key: "PAYER", Value: username},
				{Key: "ACTION", Value: actionType},
				{Key: "ORIGINAL_COST", Value: actualCost},
				{Key: "VOUCHERS", Value: CanonicalJSON(voucherIDs)},
			},
		)
	}
	return nil
}

func (s *Server) AllocateEconomyRevenue(amount int, reason string) {
	if amount <= 0 {
		return
	}
	if s.cfg.OwnerEnabled {
		ownerShare := int(math.Floor(float64(amount) / 2.0))
		custodyShare := amount - ownerShare
		s.IncrementEconomyStat("owner_balance", float64(ownerShare))
		s.IssueOwnerShare(ownerShare, reason)
		s.SaveServerContract("hps_owner_share", []ContractDetail{
			{Key: "OWNER", Value: s.cfg.OwnerUsername},
			{Key: "VALUE", Value: ownerShare},
			{Key: "REASON", Value: reason},
		}, "")
		s.AddCustodyFunds(custodyShare, reason)
	} else {
		s.AddCustodyFunds(amount, reason)
	}
}

// AllocateEconomyRevenueWithVouchers: only pays owner share if ALL vouchers have direct PoW
// AND are verified in the supply chain (anti-forgery + anti-laundering)
func (s *Server) AllocateEconomyRevenueWithVouchers(amount int, reason string, voucherIDs []string) {
	if amount <= 0 {
		return
	}
	if s.cfg.OwnerEnabled && len(voucherIDs) > 0 {
		allDirectPow := true
		allInSupplyChain := true
		for _, vid := range voucherIDs {
			// Supply chain check first (anti-forgery)
			if !s.VerifyVoucherSupplyChain(vid) || !s.VerifyVoucherSupplyChainIntegrity(vid) {
				allInSupplyChain = false
				break
			}
			hasPow, powType := s.GetVoucherPowStatus(vid)
			if !hasPow || powType != "hps_mint" {
				info := s.GetVoucherAuditInfo(vid)
				if info == nil {
					allDirectPow = false
					break
				}
				payload := mapValue(info["payload"])
				powOK, _, powDetails := s.VerifyVoucherPowPayload(payload)
				if !powOK || asString(powDetails["action_type"]) != "hps_mint" {
					allDirectPow = false
					break
				}
				s.CacheVoucherPowStatus(vid, true, "hps_mint")
			}
		}
		if allDirectPow && allInSupplyChain {
			ownerShare := int(math.Floor(float64(amount) / 2.0))
			custodyShare := amount - ownerShare
			s.IncrementEconomyStat("owner_balance", float64(ownerShare))
			s.IssueOwnerShare(ownerShare, reason)
			s.SaveServerContract("hps_owner_share", []ContractDetail{
				{Key: "OWNER", Value: s.cfg.OwnerUsername},
				{Key: "VALUE", Value: ownerShare},
				{Key: "REASON", Value: reason},
				{Key: "POW_VERIFIED", Value: "true"},
				{Key: "SUPPLY_CHAIN_VERIFIED", Value: "true"},
			}, "")
			s.AddCustodyFunds(custodyShare, reason)
		} else {
			skipReasons := []string{}
			if !allDirectPow {
				skipReasons = append(skipReasons, "vouchers_without_direct_pow")
			}
			if !allInSupplyChain {
				skipReasons = append(skipReasons, "vouchers_not_in_supply_chain")
			}
			s.AddCustodyFunds(amount, reason)
			s.SaveServerContract("hps_owner_share_skipped", []ContractDetail{
				{Key: "AMOUNT", Value: amount},
				{Key: "REASON", Value: reason},
				{Key: "VOUCHER_COUNT", Value: len(voucherIDs)},
				{Key: "SKIP_REASON", Value: strings.Join(skipReasons, ",")},
			}, "")
		}
	} else if s.cfg.OwnerEnabled {
		ownerShare := int(math.Floor(float64(amount) / 2.0))
		custodyShare := amount - ownerShare
		s.IncrementEconomyStat("owner_balance", float64(ownerShare))
		s.IssueOwnerShare(ownerShare, reason)
		s.SaveServerContract("hps_owner_share", []ContractDetail{
			{Key: "OWNER", Value: s.cfg.OwnerUsername},
			{Key: "VALUE", Value: ownerShare},
			{Key: "REASON", Value: reason},
		}, "")
		s.AddCustodyFunds(custodyShare, reason)
	} else {
		s.AddCustodyFunds(amount, reason)
	}
}

func (s *Server) IssueOwnerShare(amount int, reason string) {
	if amount <= 0 || !s.cfg.OwnerEnabled || s.cfg.OwnerUsername == "" {
		return
	}
	ownerKey := s.GetUserPublicKey(s.cfg.OwnerUsername)
	if ownerKey == "" {
		return
	}
	s.CreateVoucherOffer(
		s.cfg.OwnerUsername,
		ownerKey,
		amount,
		"owner_share:"+reason,
		nil,
		map[string]any{"type": "owner_share", "reason": reason},
		"",
	)
}

func toStringSliceAny(v any) []string {
	switch t := v.(type) {
	case []string:
		return append([]string{}, t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s := asString(item)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return parseJSONStrSlice(t)
	default:
		return nil
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	freq := map[string]int{}
	for _, value := range a {
		freq[value]++
	}
	for _, value := range b {
		if freq[value] == 0 {
			return false
		}
		freq[value]--
	}
	for _, count := range freq {
		if count != 0 {
			return false
		}
	}
	return true
}
