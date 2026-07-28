package core

import "encoding/json"

func (s *Server) CreatePendingMonetaryAction(transferID, actionName, username, clientIdentifier string, payload map[string]any, responseEvent string) string {
	actionID := NewUUID()
	raw, _ := json.Marshal(payload)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO pending_monetary_actions
		(action_id, transfer_id, action_name, username, client_identifier, payload, response_event, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		actionID, transferID, actionName, username, clientIdentifier, string(raw), responseEvent, "pending", now(), now())
	return actionID
}

func (s *Server) BuildPendingMonetaryAck(transferID string) map[string]any {
	transfer := s.GetMonetaryTransferByID(transferID)
	miner := ""
	if transfer != nil {
		miner = asString(transfer["assigned_miner"])
	}
	message := "Aguardando mineradores disponiveis para analisar a transacao."
	if miner != "" {
		message = "Transacao em analise pelo minerador " + miner + "."
	}
	return map[string]any{
		"success":     true,
		"pending":     true,
		"transfer_id": transferID,
		"message":     message,
	}
}

func (s *Server) GetPendingMonetaryPayload(transferID string) map[string]any {
	var raw string
	err := s.DB.QueryRow(`SELECT payload FROM pending_monetary_actions
		WHERE transfer_id = ? ORDER BY created_at DESC LIMIT 1`, transferID).Scan(&raw)
	if err != nil || raw == "" {
		return nil
	}
	out := map[string]any{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func (s *Server) GetPendingMonetaryAction(transferID string) map[string]any {
	var actionID, actionName, username, clientIdentifier, payloadRaw, responseEvent, status string
	var createdAt, updatedAt float64
	err := s.DB.QueryRow(`SELECT action_id, transfer_id, action_name, username, client_identifier,
		payload, response_event, status, created_at, updated_at
		FROM pending_monetary_actions WHERE transfer_id = ?
		ORDER BY created_at DESC LIMIT 1`, transferID).
		Scan(&actionID, &transferID, &actionName, &username, &clientIdentifier, &payloadRaw, &responseEvent, &status, &createdAt, &updatedAt)
	if err != nil {
		return nil
	}
	payload := map[string]any{}
	if payloadRaw != "" {
		_ = json.Unmarshal([]byte(payloadRaw), &payload)
	}
	return map[string]any{
		"action_id":         actionID,
		"transfer_id":       transferID,
		"action_name":       actionName,
		"username":          username,
		"client_identifier": clientIdentifier,
		"payload":           payload,
		"response_event":    responseEvent,
		"status":            status,
		"created_at":        createdAt,
		"updated_at":        updatedAt,
	}
}

func (s *Server) UpdatePendingMonetaryActionStatus(actionID, status string) {
	if actionID == "" || status == "" {
		return
	}
	_, _ = s.DB.Exec(`UPDATE pending_monetary_actions SET status = ?, updated_at = ? WHERE action_id = ?`, status, now(), actionID)
}

func (s *Server) DeletePendingMonetaryAction(actionID string) {
	if actionID == "" {
		return
	}
	_, _ = s.DB.Exec(`DELETE FROM pending_monetary_actions WHERE action_id = ?`, actionID)
}

func (s *Server) CancelPendingMonetaryAction(transferID, reason string) {
	_, _ = s.DB.Exec(`UPDATE pending_monetary_actions SET status = ?, updated_at = ? WHERE transfer_id = ? AND status = ?`,
		"cancelled:"+reason, now(), transferID, "pending")
}

func (s *Server) CompletePendingMonetaryAction(transferID string) {
	_, _ = s.DB.Exec(`UPDATE pending_monetary_actions SET status = ?, updated_at = ? WHERE transfer_id = ? AND status = ?`,
		"completed", now(), transferID, "pending")
}
