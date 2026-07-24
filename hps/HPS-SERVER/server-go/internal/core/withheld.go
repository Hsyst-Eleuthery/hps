package core

import "encoding/json"

func (s *Server) ConsumeWithheldOffers(username string, amount int) (int, []string) {
	used, _, ids := s.ConsumeWithheldOffersDetailed(username, amount)
	return used, ids
}

func (s *Server) ConsumeWithheldOffersDetailed(username string, neededAmount int) (int, int, []string) {
	if neededAmount <= 0 || username == "" {
		return 0, 0, []string{}
	}
	rows, err := s.DB.Query(`SELECT offer_id, value FROM hps_voucher_offers
		WHERE owner = ? AND status = ? ORDER BY issued_at ASC`, username, "withheld")
	if err != nil {
		return 0, 0, []string{}
	}
	type withheldOffer struct {
		offerID string
		value   int
	}
	offers := []withheldOffer{}
	for rows.Next() {
		var offerID string
		var value int
		if rows.Scan(&offerID, &value) != nil {
			continue
		}
		offers = append(offers, withheldOffer{offerID: offerID, value: value})
	}
	rows.Close()

	usedAmount := 0
	changeAmount := 0
	usedOfferIDs := []string{}
	for _, offer := range offers {
		if usedAmount >= neededAmount {
			break
		}
		offerID := offer.offerID
		value := offer.value
		if value <= 0 {
			_, _ = s.DB.Exec(`UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ?`, "expired", offerID)
			continue
		}
		remaining := neededAmount - usedAmount
		if value <= remaining {
			usedAmount += value
			_, _ = s.DB.Exec(`UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ?`, "spent", offerID)
			usedOfferIDs = append(usedOfferIDs, offerID)
			continue
		}
		usedAmount += remaining
		changeAmount = value - remaining
		_, _ = s.DB.Exec(`UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ?`, "spent", offerID)
		usedOfferIDs = append(usedOfferIDs, offerID)
		break
	}
	if changeAmount > 0 {
		s.CreateVoucherOfferWithStatus(
			username,
			s.GetUserPublicKey(username),
			changeAmount,
			"withheld_change",
			nil,
			map[string]any{"type": "withheld_change"},
			"",
			"pending",
		)
	}
	return usedAmount, changeAmount, usedOfferIDs
}

func (s *Server) GetWithheldOfferSummary(owner string) map[string]any {
	if owner == "" {
		return map[string]any{"count": 0, "total": 0}
	}
	var count, total int
	_ = s.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(value), 0) FROM hps_voucher_offers
		WHERE owner = ? AND status = ?`, owner, "withheld").Scan(&count, &total)
	return map[string]any{
		"count": count,
		"total": total,
	}
}

func (s *Server) ReleaseWithheldOffersForMiner(username string) int {
	if username == "" {
		return 0
	}
	rows, err := s.DB.Query(`SELECT offer_id, expires_at FROM hps_voucher_offers
		WHERE owner = ? AND status = ? ORDER BY issued_at ASC`, username, "withheld")
	if err != nil {
		return 0
	}
	type withheldRelease struct {
		offerID   string
		expiresAt float64
	}
	offers := []withheldRelease{}
	for rows.Next() {
		var offerID string
		var expiresAt float64
		if rows.Scan(&offerID, &expiresAt) != nil {
			continue
		}
		offers = append(offers, withheldRelease{offerID: offerID, expiresAt: expiresAt})
	}
	rows.Close()
	released := 0
	for _, offer := range offers {
		offerID := offer.offerID
		expiresAt := offer.expiresAt
		status := "pending"
		if expiresAt > 0 && expiresAt <= now() {
			status = "expired"
		}
		_, _ = s.DB.Exec(`UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ?`, status, offerID)
		released++
	}
	return released
}

func (s *Server) ListPendingVoucherOffers(owner string) []map[string]any {
	if owner == "" {
		return []map[string]any{}
	}
	rows, err := s.DB.Query(`SELECT offer_id, voucher_id, payload, expires_at FROM hps_voucher_offers
		WHERE owner = ? AND status = ? AND expires_at > ? ORDER BY issued_at ASC`, owner, "pending", now())
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var offerID, voucherID, payloadText string
		var expiresAt float64
		if rows.Scan(&offerID, &voucherID, &payloadText, &expiresAt) != nil {
			continue
		}
		payload := map[string]any{}
		if err := json.Unmarshal([]byte(payloadText), &payload); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"offer_id":          offerID,
			"voucher_id":        voucherID,
			"payload":           payload,
			"payload_canonical": payloadText,
			"expires_at":        expiresAt,
		})
	}
	return out
}
