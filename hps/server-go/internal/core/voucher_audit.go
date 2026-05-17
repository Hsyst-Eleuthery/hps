package core

import "encoding/json"

func (s *Server) GetVoucherAuditInfo(voucherID string) map[string]any {
	if voucherID == "" {
		return nil
	}
	var payloadText, issuerSig, ownerSig, status string
	var invalidated int
	var lineageRoot, lineageParent, lineageParentHash, lineageOrigin string
	var lineageDepth int
	err := s.DB.QueryRow(`SELECT payload, issuer_signature, owner_signature, status, invalidated,
		COALESCE(lineage_root_voucher_id, ''), COALESCE(lineage_parent_voucher_id, ''),
		COALESCE(lineage_parent_hash, ''), COALESCE(lineage_origin, ''), COALESCE(lineage_depth, 0)
		FROM hps_vouchers WHERE voucher_id = ?`, voucherID).
		Scan(&payloadText, &issuerSig, &ownerSig, &status, &invalidated, &lineageRoot, &lineageParent, &lineageParentHash, &lineageOrigin, &lineageDepth)
	if err != nil {
		return nil
	}
	payload := map[string]any{}
	_ = json.Unmarshal([]byte(payloadText), &payload)
	var issueContract string
	_ = s.DB.QueryRow(`SELECT contract_content FROM contracts
		WHERE action_type = ? AND content_hash = ? ORDER BY timestamp DESC LIMIT 1`, "voucher_issue", voucherID).Scan(&issueContract)
	var invalidContract string
	_ = s.DB.QueryRow(`SELECT contract_content FROM contracts
		WHERE action_type = ? AND content_hash = ? ORDER BY timestamp DESC LIMIT 1`, "voucher_invalidate", voucherID).Scan(&invalidContract)
	rows, err := s.DB.Query(`SELECT contract_id, action_type, contract_content FROM contracts
		WHERE content_hash = ? AND action_type IN (?, ?, ?, ?)
		ORDER BY timestamp DESC`, voucherID, "hps_spend_refund", "hps_transfer_refund", "hps_transfer_custody_refund", "miner_fine_refund")
	if err != nil {
		rows = nil
	}
	traceContracts := []map[string]any{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var contractID, actionType, content string
			if err := rows.Scan(&contractID, &actionType, &content); err == nil {
				traceContracts = append(traceContracts, map[string]any{
					"contract_id":      contractID,
					"action_type":      actionType,
					"contract_content": content,
				})
			}
		}
	}
	return map[string]any{
		"voucher_id":                voucherID,
		"payload":                   payload,
		"payload_raw":               payloadText,
		"signatures":                map[string]any{"owner": ownerSig, "issuer": issuerSig},
		"status":                    status,
		"invalidated":               invalidated != 0,
		"superseded":                s.IsVoucherSuperseded(voucherID, payload),
		"lineage_root_voucher_id":   defaultString(lineageRoot, asString(payload["lineage_root_voucher_id"])),
		"lineage_parent_voucher_id": defaultString(lineageParent, asString(payload["lineage_parent_voucher_id"])),
		"lineage_parent_hash":       defaultString(lineageParentHash, asString(payload["lineage_parent_hash"])),
		"lineage_depth":             maxInt(lineageDepth, asInt(payload["lineage_depth"])),
		"lineage_origin":            defaultString(lineageOrigin, asString(payload["lineage_origin"])),
		"issue_contract":            issueContract,
		"invalidate_contract":       invalidContract,
		"trace_contracts":           traceContracts,
	}
}
