package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func (s *Server) IncrementEconomyStat(key string, delta float64) {
	current := s.GetEconomyStat(key, 0.0)
	s.SetEconomyStat(key, current+delta)
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
