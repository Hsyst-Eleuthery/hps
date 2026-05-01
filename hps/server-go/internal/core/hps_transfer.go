package core

import (
	"encoding/json"
)

func (s *Server) CreateHpsTransferSession(payer, target string, voucherIDs []string, amount int) (map[string]any, string) {
	sessionID := NewUUID()
	ok, totalValue, errMsg := s.ReserveVouchersForSession(payer, sessionID, voucherIDs)
	if !ok {
		return nil, errMsg
	}
	if totalValue < amount {
		s.ReleaseVouchersForSession(sessionID)
		return nil, "Insufficient HPS balance"
	}
	expiresAt := now() + (7 * 24 * 3600)
	voucherIDsText, _ := json.Marshal(voucherIDs)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO hps_transfer_sessions
		(session_id, offer_id, voucher_id, payer, target, voucher_ids, amount, total_value, status, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, "", "", payer, target, string(voucherIDsText), amount, totalValue, "pending_confirmation", now(), expiresAt)
	return map[string]any{
		"session_id":  sessionID,
		"payer":       payer,
		"target":      target,
		"amount":      amount,
		"total_value": totalValue,
		"voucher_ids": voucherIDs,
		"expires_at":  expiresAt,
		"offer_id":    "",
		"voucher_id":  "",
		"status":      "pending_confirmation",
	}, ""
}

func (s *Server) GetHpsTransferSession(sessionID string) map[string]any {
	var out map[string]any
	var offerID, voucherID, payer, target, voucherIDsText, status string
	var amount, totalValue int
	var expiresAt float64
	err := s.DB.QueryRow(`SELECT offer_id, voucher_id, payer, target, voucher_ids, amount, total_value, status, expires_at
		FROM hps_transfer_sessions WHERE session_id = ?`, sessionID).
		Scan(&offerID, &voucherID, &payer, &target, &voucherIDsText, &amount, &totalValue, &status, &expiresAt)
	if err != nil {
		return nil
	}
	var voucherIDs []string
	_ = json.Unmarshal([]byte(voucherIDsText), &voucherIDs)
	out = map[string]any{
		"session_id":  sessionID,
		"offer_id":    offerID,
		"voucher_id":  voucherID,
		"payer":       payer,
		"target":      target,
		"voucher_ids": voucherIDs,
		"amount":      amount,
		"total_value": totalValue,
		"status":      status,
		"expires_at":  expiresAt,
	}
	return out
}

func (s *Server) GetHpsTransferSessionByVoucher(voucherID string) map[string]any {
	var sessionID string
	err := s.DB.QueryRow(`SELECT session_id FROM hps_transfer_sessions WHERE voucher_id = ?`, voucherID).Scan(&sessionID)
	if err != nil || sessionID == "" {
		return nil
	}
	return s.GetHpsTransferSession(sessionID)
}

func (s *Server) UpdateHpsTransferSessionOffer(sessionID, offerID, voucherID string, expiresAt float64) {
	_, _ = s.DB.Exec(`UPDATE hps_transfer_sessions
		SET offer_id = ?, voucher_id = ?, status = ?, expires_at = ?
		WHERE session_id = ?`, offerID, voucherID, "pending", expiresAt, sessionID)
}

func (s *Server) UpdateHpsTransferSessionTarget(sessionID, target string) {
	_, _ = s.DB.Exec(`UPDATE hps_transfer_sessions SET target = ? WHERE session_id = ?`, target, sessionID)
}

func (s *Server) DeleteHpsTransferSession(sessionID string) {
	_, _ = s.DB.Exec(`DELETE FROM hps_transfer_sessions WHERE session_id = ?`, sessionID)
}

func (s *Server) UpdateTransferLockedVouchers(transferID string, voucherIDs []string) {
	raw, _ := json.Marshal(voucherIDs)
	_, _ = s.DB.Exec(`UPDATE monetary_transfers SET locked_voucher_ids = ? WHERE transfer_id = ?`, string(raw), transferID)
}

func (s *Server) DeletePendingTransfersBySessionID(sessionID string) {
	_, _ = s.DB.Exec(`DELETE FROM pending_transfers WHERE hps_session_id = ?`, sessionID)
}

func (s *Server) CompleteHpsTransfer(voucherID string) {
	transfer := s.GetHpsTransferSessionByVoucher(voucherID)
	if transfer == nil || asString(transfer["status"]) != "pending" {
		return
	}
	sessionID := asString(transfer["session_id"])
	payer := asString(transfer["payer"])
	target := asString(transfer["target"])
	amount := asInt(transfer["amount"])
	totalValue := asInt(transfer["total_value"])
	s.MarkVouchersSpent(sessionID)
	_, _ = s.DB.Exec(`UPDATE hps_transfer_sessions SET status = ? WHERE session_id = ?`, "completed", sessionID)
	s.SaveServerContract("hps_transfer_complete", []ContractDetail{
		{Key: "PAYER", Value: payer},
		{Key: "TARGET", Value: target},
		{Key: "AMOUNT", Value: amount},
		{Key: "TOTAL_VALUE", Value: totalValue},
		{Key: "VOUCHERS", Value: CanonicalJSON(transfer["voucher_ids"])},
		{Key: "TRANSFER_VOUCHER_ID", Value: voucherID},
	}, sessionID)
	refundValue := totalValue - amount
	if refundValue > 0 {
		ownerKey := s.GetUserPublicKey(payer)
		if ownerKey != "" {
			refundOffer := s.CreateVoucherOffer(
				payer, ownerKey, refundValue,
				"hps_transfer_refund:"+voucherID,
				nil, map[string]any{"source_voucher_id": voucherID}, "",
			)
			s.SaveServerContract("hps_transfer_refund", []ContractDetail{
				{Key: "PAYER", Value: payer},
				{Key: "REFUND_VALUE", Value: refundValue},
				{Key: "ORIGINAL_VOUCHER_ID", Value: voucherID},
				{Key: "REFUND_VOUCHER_ID", Value: asString(refundOffer["voucher_id"])},
				{Key: "SESSION_ID", Value: sessionID},
			}, asString(refundOffer["voucher_id"]))
		}
	}
}

func (s *Server) MoveHpsTransferSessionToCustody(sessionID string) {
	session := s.GetHpsTransferSession(sessionID)
	if session == nil {
		return
	}
	status := asString(session["status"])
	if status != "pending_confirmation" && status != "pending" {
		return
	}
	payer := asString(session["payer"])
	amount := asInt(session["amount"])
	totalValue := asInt(session["total_value"])
	s.MarkVouchersSpent(sessionID)
	_, _ = s.DB.Exec(`UPDATE hps_transfer_sessions SET status = ? WHERE session_id = ?`, "custody", sessionID)
	if amount > 0 {
		s.CreateVoucherOffer(CustodyUsername, base64Encode(s.PublicKeyPEM), amount, "hps_transfer_custody:"+sessionID, nil, map[string]any{
			"source_voucher_ids": toStringSliceAny(session["voucher_ids"]),
		}, "")
	}
	refundValue := totalValue - amount
	if refundValue > 0 && payer != "" {
		ownerKey := s.GetUserPublicKey(payer)
		if ownerKey != "" {
			refundOffer := s.CreateVoucherOffer(
				payer, ownerKey, refundValue,
				"hps_transfer_custody_refund:"+sessionID,
				nil, map[string]any{"source_voucher_ids": toStringSliceAny(session["voucher_ids"])}, "",
			)
			s.SaveServerContract("hps_transfer_custody_refund", []ContractDetail{
				{Key: "PAYER", Value: payer},
				{Key: "REFUND_VALUE", Value: refundValue},
				{Key: "SESSION_ID", Value: sessionID},
				{Key: "VOUCHERS", Value: CanonicalJSON(session["voucher_ids"])},
			}, asString(refundOffer["voucher_id"]))
		}
	}
}

func (s *Server) CleanupHpsTransferSessions() {
	rows, err := s.DB.Query(`SELECT session_id, payer FROM hps_transfer_sessions
		WHERE status IN (?, ?) AND expires_at < ?`, "pending", "pending_confirmation", now())
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sessionID, payer string
		if rows.Scan(&sessionID, &payer) != nil {
			continue
		}
		s.ReleaseVouchersForSession(sessionID)
		_, _ = s.DB.Exec(`UPDATE hps_transfer_sessions SET status = ? WHERE session_id = ?`, "expired", sessionID)
		s.DeletePendingTransfersBySessionID(sessionID)
		_ = payer
	}
}
