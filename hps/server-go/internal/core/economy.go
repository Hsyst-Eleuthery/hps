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
	var value any
	err := s.DB.QueryRow("SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?", key).Scan(&value)
	if err != nil {
		return defaultValue
	}
	return parseNumeric(value, defaultValue)
}

func (s *Server) SetEconomyStat(key string, value float64) {
	_, _ = s.DB.Exec("INSERT OR REPLACE INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)", key, value)
}

func (s *Server) GetEconomyStatText(key string, defaultValue string) string {
	if key == "" {
		return defaultValue
	}
	var value sql.NullString
	err := s.DB.QueryRow("SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?", key).Scan(&value)
	if err != nil || !value.Valid {
		return defaultValue
	}
	return value.String
}

func (s *Server) SetEconomyStatText(key string, value string) {
	_, _ = s.DB.Exec("INSERT OR REPLACE INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)", key, value)
}

func (s *Server) GetEconomyMultiplier() float64 {
	totalMinted := s.GetEconomyStat("total_minted", 0.0)
	custodyBalance := s.GetEconomyStat("custody_balance", 0.0)
	inflation := 1.0 + math.Min(totalMinted/10000.0, 5.0)
	var effective float64
	if custodyBalance > 0 {
		effective = math.Max(1.0, inflation-math.Min(inflation-1.0, custodyBalance))
	} else {
		effective = inflation
	}
	if effective < 1.0 {
		effective = 1.0
	}
	if effective > 10.0 {
		effective = 10.0
	}
	return effective
}

func (s *Server) GetInflationRate() float64 {
	totalMinted := s.GetEconomyStat("total_minted", 0.0)
	inflation := 1.0 + math.Min(totalMinted/10000.0, 5.0)
	rate := inflation - 1.0
	if rate < 0 {
		return 0
	}
	return rate
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
			s.HpsPowCosts[actionType] = parsed
		}
	}

	for actionType, value := range s.HpsPowCosts {
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
	s.HpsPowCosts[actionType] = value
	s.SetEconomyStat(priceStatPrefix+actionType, float64(value))
}

func (s *Server) ListConfiguredPrices() map[string]int {
	keys := make([]string, 0, len(s.HpsPowCosts))
	for actionType := range s.HpsPowCosts {
		keys = append(keys, actionType)
	}
	sort.Strings(keys)

	prices := make(map[string]int, len(keys))
	for _, actionType := range keys {
		value := s.HpsPowCosts[actionType]
		if value > 0 {
			prices[actionType] = value
		}
	}
	return prices
}

func (s *Server) GetHpsPowCostWithDiscount(actionType string, applyDiscount bool) int {
	base := float64(s.HpsPowCosts[actionType])
	if base <= 0 {
		return 0
	}
	inflation := 1.0 + math.Min(s.GetEconomyStat("total_minted", 0.0)/10000.0, 5.0)
	inflated := base * inflation
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
	}
	return inflatedCost - covered
}

func (s *Server) BuildEconomyReport() map[string]any {
	powCosts := map[string]any{}
	for key := range s.HpsPowCosts {
		powCosts[key] = s.GetHpsPowCost(key)
	}
	payload := map[string]any{
		"issuer":            s.Address,
		"issuer_public_key": base64Encode(s.PublicKeyPEM),
		"timestamp":         float64(time.Now().UnixNano()) / 1e9,
		"total_minted":      s.GetEconomyStat("total_minted", 0.0),
		"custody_balance":   s.GetEconomyStat("custody_balance", 0.0),
		"owner_balance":     s.GetEconomyStat("owner_balance", 0.0),
		"rebate_balance":    s.GetEconomyStat("rebate_balance", 0.0),
		"multiplier":        s.GetEconomyMultiplier(),
		"exchange_fee_rate": s.ExchangeFeeRate,
		"exchange_fee_min":  s.ExchangeFeeMin,
		"pow_costs":         powCosts,
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
