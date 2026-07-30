package core

import (
	"database/sql"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const priceStatPrefix = "price:"

func (s *Server) GetEconomyStat(key string, defaultValue float64) float64 {
	s.economyMu.Lock()
	defer s.economyMu.Unlock()
	var value any
	err := s.TxQueryRow("SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?", key).Scan(&value)
	if err != nil {
		return defaultValue
	}
	return parseNumeric(value, defaultValue)
}

func (s *Server) SetEconomyStat(key string, value float64) {
	s.economyMu.Lock()
	defer s.economyMu.Unlock()
	_, _ = s.TxExec("INSERT OR REPLACE INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)", key, value)
}

func (s *Server) GetEconomyStatText(key string, defaultValue string) string {
	if key == "" {
		return defaultValue
	}
	s.economyMu.Lock()
	defer s.economyMu.Unlock()
	var value sql.NullString
	err := s.TxQueryRow("SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?", key).Scan(&value)
	if err != nil || !value.Valid {
		return defaultValue
	}
	return value.String
}

func (s *Server) SetEconomyStatText(key string, value string) {
	s.economyMu.Lock()
	defer s.economyMu.Unlock()
	_, _ = s.TxExec("INSERT OR REPLACE INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)", key, value)
}

func (s *Server) GetEconomyMultiplier() float64 {
	totalMinted := s.GetEconomyStat("total_minted", 0.0)
	totalBurned := s.GetEconomyStat("total_burned", 0.0)
	outstandingDebt := s.GetOutstandingPhpsDebt()
	rawInflation := 1.0 + totalMinted/10000.0
	effective := math.Max(1.0, rawInflation-totalBurned/10000.0+outstandingDebt/10000.0)
	if effective < 1.0 {
		effective = 1.0
	}
	return effective
}

func (s *Server) GetInflationRate() float64 {
	totalMinted := s.GetEconomyStat("total_minted", 0.0)
	inflation := 1.0 + totalMinted/10000.0
	rate := inflation - 1.0
	if rate < 0 {
		return 0
	}
	return rate
}

func (s *Server) GetEffectiveInflationRate() float64 {
	return s.GetEconomyMultiplier() - 1.0
}

func (s *Server) ComputeSubsidyPrice() int {
	inflationRate := s.GetEffectiveInflationRate()
	if inflationRate <= 0 {
		return 0
	}
	totalMinted := s.GetEconomyStat("total_minted", 0.0)
	avgCost := totalMinted / 100.0
	if avgCost < 1 {
		avgCost = 1
	}
	projectedSubsidy := avgCost * inflationRate * 100.0
	price := int(math.Ceil(projectedSubsidy * 0.5))
	if price < 1 {
		price = 1
	}
	return price
}

func (s *Server) incrementEconomyStatInt(key string, delta int64) {
	s.economyMu.Lock()
	defer s.economyMu.Unlock()
	_ = s.BeginTx()
	txDone := false
	defer func() {
		if !txDone {
			s.RollbackTx()
		}
	}()
	var value int64
	err := s.TxQueryRow("SELECT CAST(stat_value AS INTEGER) FROM hps_economy_stats WHERE stat_key = ?", key).Scan(&value)
	if err != nil {
		value = 0
	}
	_, _ = s.TxExec("INSERT OR REPLACE INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)", key, value+delta)
	s.CommitTx()
	txDone = true
}

func (s *Server) RecordBurn(amount int, reason string) {
	if amount <= 0 {
		return
	}
	s.incrementEconomyStatInt("total_burned", int64(amount))
	s.RecordEconomyEvent("burn:" + reason)
	s.RecordEconomyContract("burn:" + reason)
}

func (s *Server) RecordMint(amount int, reason string) {
	if amount <= 0 {
		return
	}
	s.incrementEconomyStatInt("total_minted", int64(amount))
	s.RecordEconomyEvent("mint:" + reason)
}

func (s *Server) GetOutstandingPhpsDebt() float64 {
	var total sql.NullFloat64
	err := s.DB.QueryRow(`SELECT COALESCE(SUM(payout_total - reserved_amount), 0)
		FROM phps_debts WHERE status = 'funded'`).Scan(&total)
	if err != nil || !total.Valid {
		return 0
	}
	if total.Float64 < 0 {
		return 0
	}
	return total.Float64
}

func (s *Server) ProcessOutgoingExchange(totalValue int, targetServer string) (int, int, int) {
	if totalValue <= 0 {
		return 0, 0, 0
	}

	remaining := float64(totalValue)

	paidToDebts := s.PayDebtsFromValue(remaining)
	remaining -= paidToDebts

	if remaining <= 0 {
		s.RecordEconomyEvent("exchange_outgoing:all_to_debts:" + targetServer)
		return int(paidToDebts), 0, 0
	}

	distributedToUsers, burned := s.DistributeEquallyToUsers(int(remaining), "exchange_outgoing:"+targetServer)

	s.RecordEconomyEvent("exchange_outgoing:" + targetServer)
	s.RecordEconomyContract("exchange_outgoing:" + targetServer)

	return int(paidToDebts), distributedToUsers, burned
}

func (s *Server) ProcessIncomingExchangeOnDestination(totalValue int, sourceServer, username string) (int, int) {
	if totalValue <= 0 || username == "" {
		return 0, 0
	}

	custodyBalance := s.GetEconomyStat("custody_balance", 0.0)
	var totalPaid, debtCreated int
	var titleID string

	if custodyBalance >= float64(totalValue) {
		s.SetEconomyStat("custody_balance", custodyBalance-float64(totalValue))
		totalPaid = totalValue
	} else {
		availableFromCustody := int(math.Floor(custodyBalance))
		if availableFromCustody > 0 {
			s.SetEconomyStat("custody_balance", 0)
			totalPaid = availableFromCustody
		}
		shortfall := totalValue - totalPaid
		if shortfall > 0 {
			rootVoucherRef := "exchange:" + sourceServer + ":" + NewUUID()
			titleID = s.CreateExchangeTitle(rootVoucherRef, sourceServer, totalValue, shortfall, "computational")
			if titleID != "" {
				debtCreated = shortfall
				s.RecordEconomyEvent("exchange_title_issued:" + sourceServer)
				s.RecordEconomyContract("exchange_title_issued:" + sourceServer)
			}
		}
	}

	ownerKey := s.GetUserPublicKey(username)
	if ownerKey == "" {
		ownerKey = base64Encode(s.PublicKeyPEM)
	}

	emittedAmount := totalValue
	if totalPaid > 0 {
		emittedAmount = totalPaid
	}

	s.CreateVoucherOffer(username, ownerKey, emittedAmount,
		"exchange_incoming:"+sourceServer, nil,
		map[string]any{
			"type":         titleID,
			"source":       sourceServer,
			"total_value":  totalValue,
			"debt_created": debtCreated,
			"title_id":     titleID,
		}, "")

	if debtCreated > 0 {
		s.RecordMint(emittedAmount, "exchange_title_emission:"+sourceServer)
	}

	s.RecordEconomyEvent("exchange_incoming:" + sourceServer)
	s.RecordEconomyContract("exchange_incoming:" + sourceServer)
	return totalPaid, debtCreated
}

func (s *Server) PayDebtsFromValue(available float64) float64 {
	if available <= 0 {
		return 0
	}

	rows, err := s.DB.Query(`SELECT debt_id, payout_total, reserved_amount
		FROM phps_debts WHERE status = 'funded' ORDER BY funded_at ASC, created_at ASC`)
	if err != nil {
		return 0
	}
	defer rows.Close()

	totalPaid := 0.0
	for rows.Next() {
		if available <= 0 {
			break
		}
		var debtID string
		var payoutTotal, reservedAmount int
		if rows.Scan(&debtID, &payoutTotal, &reservedAmount) != nil {
			continue
		}
		needed := payoutTotal - reservedAmount
		if needed <= 0 {
			continue
		}
		payment := int(math.Min(float64(needed), available))
		if payment <= 0 {
			continue
		}
		_, _ = s.DB.Exec(`UPDATE phps_debts SET reserved_amount = reserved_amount + ? WHERE debt_id = ?`, payment, debtID)
		available -= float64(payment)
		totalPaid += float64(payment)

		var newReserved int
		_ = s.DB.QueryRow(`SELECT reserved_amount FROM phps_debts WHERE debt_id = ?`, debtID).Scan(&newReserved)
		if newReserved >= payoutTotal {
			creditorUsername := ""
			_ = s.DB.QueryRow(`SELECT creditor_username FROM phps_debts WHERE debt_id = ?`, debtID).Scan(&creditorUsername)
			if creditorUsername != "" {
				creditorKey := s.GetUserPublicKey(creditorUsername)
				if creditorKey != "" {
					offer := s.CreateVoucherOffer(creditorUsername, creditorKey, payoutTotal,
						"phps_payout:"+debtID, nil,
						map[string]any{"type": "phps_payout", "debt_id": debtID}, "")
					voucherID := ""
					if offer != nil {
						voucherID, _ = offer["voucher_id"].(string)
					}
					_, _ = s.DB.Exec(`UPDATE phps_debts
						SET status = ?, payout_voucher_id = ?, repaid_at = ?
						WHERE debt_id = ?`, "repaid", voucherID, now(), debtID)
				}
			}
		}
	}

	return totalPaid
}

func (s *Server) DistributeEquallyToUsers(totalValue int, reason string) (int, int) {
	if totalValue <= 0 {
		return 0, 0
	}

	var userCount int
	err := s.DB.QueryRow(`SELECT COUNT(DISTINCT username) FROM hps_vouchers
		WHERE status = 'valid' AND invalidated = 0 AND username != ''`).Scan(&userCount)
	if err != nil || userCount <= 0 {
		s.RecordBurn(totalValue, "distribution_no_users:"+reason)
		return 0, totalValue
	}

	sharePerUser := totalValue / userCount
	if sharePerUser <= 0 {
		s.RecordBurn(totalValue, "distribution_too_small:"+reason)
		return 0, totalValue
	}

	burned := totalValue - (sharePerUser * userCount)

	rows, err := s.DB.Query(`SELECT DISTINCT username FROM hps_vouchers
		WHERE status = 'valid' AND invalidated = 0 AND username != ''`)
	if err != nil {
		s.RecordBurn(totalValue, "distribution_error:"+reason)
		return 0, totalValue
	}
	defer rows.Close()

	totalDistributed := 0
	for rows.Next() {
		var username string
		if rows.Scan(&username) != nil {
			continue
		}
		ownerKey := s.GetUserPublicKey(username)
		if ownerKey == "" {
			burned += sharePerUser
			continue
		}
		s.CreateVoucherOffer(username, ownerKey, sharePerUser,
			"distribution:"+reason, nil,
			map[string]any{"type": "distribution", "reason": reason}, "")
		totalDistributed += sharePerUser

		if s.UserEventEmitter != nil {
			s.UserEventEmitter(username, "hps_distribution", map[string]any{
				"amount": sharePerUser,
				"reason": reason,
				"type":   "distribution",
			})
		}
	}

	if burned > 0 {
		s.RecordBurn(burned, "distribution_remainder:"+reason)
	}

	s.RecordEconomyEvent("distribution:" + reason)
	return totalDistributed, burned
}

func (s *Server) GetServerHealthRate() float64 {
	multiplier := s.GetEconomyMultiplier()
	outstandingDebt := s.GetOutstandingPhpsDebt()
	totalMinted := s.GetEconomyStat("total_minted", 0.0)
	totalBurned := s.GetEconomyStat("total_burned", 0.0)

	baseRate := 1.0 / math.Max(multiplier, 0.01)

	circulating := math.Max(1.0, totalMinted-totalBurned)
	burnRatio := totalBurned / math.Max(totalMinted, 1.0)
	burnBonus := burnRatio * 0.5

	debtPenalty := outstandingDebt / math.Max(1.0, circulating)
	debtPenalty = math.Min(debtPenalty, 0.5)

	rate := baseRate + burnBonus - debtPenalty
	if rate < 0.01 {
		rate = 0.01
	}
	return rate
}

func (s *Server) ComputeExchangeRate(sourceHealthRate, destinationHealthRate float64) float64 {
	if sourceHealthRate <= 0 || destinationHealthRate <= 0 {
		return 1.0
	}
	return destinationHealthRate / sourceHealthRate
}

func (s *Server) GetCustodySubsidyShare() float64 {
	share := s.GetEconomyStat("custody_subsidy_share", 0.5)
	if share < 0 || share > 1 {
		return 0.5
	}
	return share
}

func (s *Server) GetHpsPowCost(actionType string) int {
	return s.GetHpsPowCostWithDiscount(actionType, true)
}

func (s *Server) LoadConfiguredPrices() {
	rows, err := s.DB.Query("SELECT stat_key, stat_value FROM hps_economy_stats WHERE stat_key LIKE ?", priceStatPrefix+"%")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var key string
			var value any
			if rows.Scan(&key, &value) != nil {
				continue
			}
			actionType := strings.TrimSpace(strings.TrimPrefix(key, priceStatPrefix))
			if actionType == "" {
				continue
			}
			parsed := int(math.Round(parseNumeric(value, 0)))
			if parsed <= 0 {
				continue
			}
			s.SetHpsPowCost(actionType, parsed)
		}
	}

	for actionType, value := range s.ListHpsPowCostBases() {
		if value <= 0 {
			continue
		}
		s.SetEconomyStat(priceStatPrefix+actionType, float64(value))
	}
}

func (s *Server) SetConfiguredPrice(actionType string, value int) {
	actionType = strings.TrimSpace(strings.ToLower(actionType))
	if actionType == "" || value <= 0 {
		return
	}
	s.SetHpsPowCost(actionType, value)
	s.SetEconomyStat(priceStatPrefix+actionType, float64(value))
}

func (s *Server) ListConfiguredPrices() map[string]int {
	bases := s.ListHpsPowCostBases()
	keys := make([]string, 0, len(bases))
	for actionType := range bases {
		keys = append(keys, actionType)
	}
	sort.Strings(keys)

	prices := make(map[string]int, len(keys))
	for _, actionType := range keys {
		value := bases[actionType]
		if value > 0 {
			prices[actionType] = value
		}
	}
	return prices
}

func (s *Server) GetHpsPowCostWithDiscount(actionType string, applyDiscount bool) int {
	base := float64(s.GetHpsPowCostBase(actionType))
	if base <= 0 {
		return 0
	}
	effectiveInflation := s.GetEconomyMultiplier()
	inflated := base * effectiveInflation
	actual := inflated
	if applyDiscount {
		actual = s.ApplyCustodyDiscount(base, inflated, actionType, true)
	}
	return int(math.Max(1, math.Ceil(actual)))
}

func (s *Server) ApplyCustodyDiscount(baseCost, inflatedCost float64, reason string, apply bool) float64 {
	if inflatedCost <= baseCost {
		return inflatedCost
	}
	custodyBalance := s.GetEconomyStat("custody_balance", 0.0)
	if custodyBalance <= 0 {
		return inflatedCost
	}
	delta := inflatedCost - baseCost
	covered := math.Min(delta, custodyBalance)
	if covered <= 0 {
		return inflatedCost
	}
	if apply {
		s.SetEconomyStat("custody_balance", custodyBalance-covered)
		s.RecordEconomyEvent("custody_price_support:" + reason)
		s.RecordEconomyContract("custody_price_support:" + reason)
		s.DistributeSubsidyToTitleHolders(covered, reason)
	}
	return inflatedCost - covered
}

func (s *Server) DistributeSubsidyToTitleHolders(subsidyAmount float64, reason string) {
	if subsidyAmount <= 0 {
		return
	}
	sharePercent := s.GetCustodySubsidyShare()
	titlePayout := int(math.Ceil(subsidyAmount * sharePercent))
	if titlePayout <= 0 {
		return
	}

	rows, err := s.DB.Query(`SELECT title_id, holder_username, share_percent FROM phps_titles WHERE status = 'active'`)
	if err != nil {
		return
	}
	defer rows.Close()

	type titleHolder struct {
		titleID  string
		username string
		sharePct float64
	}
	var holders []titleHolder
	for rows.Next() {
		var h titleHolder
		if rows.Scan(&h.titleID, &h.username, &h.sharePct) != nil {
			continue
		}
		holders = append(holders, h)
	}
	if len(holders) == 0 {
		return
	}

	totalSharePct := 0.0
	for _, h := range holders {
		totalSharePct += h.sharePct
	}
	if totalSharePct <= 0 {
		return
	}

	for _, h := range holders {
		payout := int(math.Ceil(float64(titlePayout) * (h.sharePct / totalSharePct)))
		if payout <= 0 {
			continue
		}
		s.EmitVoucherOfferToUser(h.username, payout, "phps_title_payout:"+reason, []ContractDetail{
			{Key: "TITLE_ID", Value: h.titleID},
			{Key: "SUBSIDY_AMOUNT", Value: subsidyAmount},
			{Key: "SHARE_PERCENT", Value: h.sharePct},
			{Key: "REASON", Value: reason},
		})
	}
}

func (s *Server) ListUserVouchersWithBalance(username string) ([]map[string]any, int) {
	if username == "" {
		return nil, 0
	}
	rows, err := s.DB.Query(`SELECT voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated
		FROM hps_vouchers WHERE owner = ? ORDER BY issued_at DESC`, username)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()
	var vouchers []map[string]any
	totalBalance := 0
	for rows.Next() {
		var voucherID, issuer, owner, reason, payloadText, issuerSignature, ownerSignature, status string
		var value int
		var issuedAt, lastUpdated float64
		var sessionID sql.NullString
		var invalidated int
		if err := rows.Scan(&voucherID, &issuer, &owner, &value, &reason, &issuedAt, &payloadText, &issuerSignature, &ownerSignature, &status, &sessionID, &invalidated, &lastUpdated); err != nil {
			continue
		}
		vouchers = append(vouchers, map[string]any{
			"voucher_id":       voucherID,
			"issuer":           issuer,
			"is_local_issuer":  s.IsLocalIssuer(issuer),
			"owner":            owner,
			"value":            value,
			"reason":           reason,
			"issued_at":        issuedAt,
			"payload":          payloadText,
			"issuer_signature": issuerSignature,
			"owner_signature":  ownerSignature,
			"status":           status,
			"invalidated":      invalidated != 0,
			"last_updated":     lastUpdated,
		})
		if status == "valid" && invalidated == 0 {
			totalBalance += value
		}
	}
	return vouchers, totalBalance
}

func (s *Server) BuildEconomyReport() map[string]any {
	powCosts := map[string]any{}
	for key := range s.ListHpsPowCostBases() {
		powCosts[key] = s.GetHpsPowCost(key)
	}
	payload := map[string]any{
		"issuer":                    s.Address,
		"issuer_public_key":         base64Encode(s.PublicKeyPEM),
		"timestamp":                 float64(time.Now().UnixNano()) / 1e9,
		"total_minted":              s.GetEconomyStat("total_minted", 0.0),
		"total_burned":              s.GetEconomyStat("total_burned", 0.0),
		"custody_balance":           s.GetEconomyStat("custody_balance", 0.0),
		"owner_balance":             s.GetEconomyStat("owner_balance", 0.0),
		"rebate_balance":            s.GetEconomyStat("rebate_balance", 0.0),
		"multiplier":                s.GetEconomyMultiplier(),
		"inflation_rate":            s.GetInflationRate(),
		"effective_inflation_rate":  s.GetEffectiveInflationRate(),
		"subsidy_price":             s.ComputeSubsidyPrice(),
		"custody_subsidy_share":     s.GetCustodySubsidyShare(),
		"outstanding_phps_debt":     s.GetOutstandingPhpsDebt(),
		"server_health_rate":        s.GetServerHealthRate(),
		"exchange_fee_rate":         s.ExchangeFeeRate,
		"exchange_fee_min":          s.ExchangeFeeMin,
		"pow_costs":                 powCosts,
	}
	payloadCanonical := CanonicalJSON(payload)
	signature := s.SignRawText(payloadCanonical)
	return map[string]any{"payload": payload, "payload_canonical": payloadCanonical, "signature": signature}
}

func parseNumeric(value any, defaultValue float64) float64 {
	if value == nil {
		return defaultValue
	}
	switch v := value.(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	case int:
		return float64(v)
	case string:
		if v == "" {
			return defaultValue
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return defaultValue
		}
		return f
	case []byte:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return defaultValue
		}
		return f
	default:
		return defaultValue
	}
}

func scanOptionalFloat(row *sql.Row) float64 {
	var value any
	if err := row.Scan(&value); err != nil {
		return 0
	}
	return parseNumeric(value, 0)
}
