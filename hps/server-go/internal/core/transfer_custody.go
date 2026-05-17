package core

func (s *Server) NotifyPendingTransfers(username string) {
	// Notification fan-out is done by socket layer.
	_ = username
}

func (s *Server) NotifyMonetaryTransferUpdate(transferID, status, reason string, details map[string]any) {
	_ = details
	_, _ = s.DB.Exec(`UPDATE monetary_transfers SET status = ? WHERE transfer_id = ?`, status, transferID)
	if reason != "" {
		_ = s.SaveServerContract("monetary_transfer_status", []ContractDetail{
			{Key: "TRANSFER_ID", Value: transferID},
			{Key: "STATUS", Value: status},
			{Key: "REASON", Value: reason},
		}, transferID)
	}
}

func (s *Server) MoveTransferToCustody(transferID string) {
	_, _ = s.DB.Exec(`UPDATE pending_transfers
		SET custody_user = ?, status = ?
		WHERE transfer_id = ?`, CustodyUsername, "moved_to_custody", transferID)
}

func (s *Server) MoveHpsTransferToCustody(transferID string) {
	_, _ = s.DB.Exec(`UPDATE pending_transfers
		SET custody_user = ?, status = ?
		WHERE transfer_id = ? AND transfer_type = ?`, CustodyUsername, "moved_to_custody", transferID, "hps_transfer")
}
