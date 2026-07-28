package core

func (s *Server) IssueCustodyVoucher(value int, reason string, powInfo map[string]any, conditions map[string]any) string {
	if value <= 0 {
		return ""
	}
	s.AddCustodyFunds(value, reason)
	ownerKey := base64Encode(s.PublicKeyPEM)
	offer := s.CreateVoucherOfferWithStatus(
		CustodyUsername,
		ownerKey,
		value,
		reason,
		powInfo,
		conditions,
		"",
		"pending",
	)
	ownerSignature := s.SignPayload(castMap(offer["payload"]))
	voucherID := asString(offer["voucher_id"])
	if voucherID == "" {
		return ""
	}
	voucher := s.FinalizeVoucher(voucherID, ownerSignature)
	if voucher == nil {
		return ""
	}
	return voucherID
}
