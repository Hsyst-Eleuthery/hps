package core

import "encoding/json"

type VoucherLineageMetadata struct {
	RootVoucherID    string
	ParentVoucherID  string
	ParentHash       string
	Depth            int
	Origin           string
	SourceVoucherIDs []string
}

func (s *Server) ResolveVoucherLineage(voucherID string, conditions map[string]any) VoucherLineageMetadata {
	sourceIDs := lineageSourceVoucherIDs(conditions)
	origin := asString(conditions["lineage_origin"])
	if origin == "" {
		switch {
		case asString(conditions["type"]) == "exchange":
			origin = "exchange_in"
		case len(sourceIDs) > 1:
			origin = "merge"
		case len(sourceIDs) == 1:
			origin = "derived"
		default:
			origin = "pow_root"
		}
	}
	meta := VoucherLineageMetadata{
		RootVoucherID:    voucherID,
		Depth:            0,
		Origin:           origin,
		SourceVoucherIDs: sourceIDs,
	}
	if origin == "exchange_in" || len(sourceIDs) != 1 {
		return meta
	}
	parent := s.GetVoucherAuditInfo(sourceIDs[0])
	if parent == nil {
		return meta
	}
	parentPayload := mapValue(parent["payload"])
	parentRoot := asString(parentPayload["lineage_root_voucher_id"])
	if parentRoot == "" {
		parentRoot = asString(parentPayload["voucher_id"])
	}
	parentDepth := asInt(parentPayload["lineage_depth"])
	meta.RootVoucherID = defaultString(parentRoot, voucherID)
	meta.ParentVoucherID = sourceIDs[0]
	meta.ParentHash = ComputeVoucherIntegrityHash(parentPayload, mapValue(parent["signatures"]))
	meta.Depth = parentDepth + 1
	return meta
}

func lineageSourceVoucherIDs(conditions map[string]any) []string {
	sourceIDs := dedupeStrings(strSliceValue(conditions["source_voucher_ids"]))
	if len(sourceIDs) > 0 {
		return sourceIDs
	}
	if sourceID := asString(conditions["source_voucher_id"]); sourceID != "" {
		return []string{sourceID}
	}
	if raw := asString(conditions["source_voucher_ids_json"]); raw != "" {
		var parsed []string
		if json.Unmarshal([]byte(raw), &parsed) == nil {
			return dedupeStrings(parsed)
		}
	}
	return []string{}
}

func (s *Server) IsVoucherSuperseded(voucherID string, payload map[string]any) bool {
	if voucherID == "" {
		return false
	}
	rootID := asString(payload["lineage_root_voucher_id"])
	if rootID == "" {
		rootID = voucherID
	}
	depth := asInt(payload["lineage_depth"])
	var newer int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM hps_vouchers
		WHERE lineage_root_voucher_id = ?
		  AND voucher_id != ?
		  AND lineage_depth > ?
		  AND invalidated = 0`, rootID, voucherID, depth).Scan(&newer)
	return newer > 0
}

func BuildLineageTransitionDetails(meta VoucherLineageMetadata, newVoucherID string) []ContractDetail {
	if len(meta.SourceVoucherIDs) == 0 || newVoucherID == "" {
		return nil
	}
	details := []ContractDetail{
		{Key: "NEW_VOUCHER_ID", Value: newVoucherID},
		{Key: "LINEAGE_ROOT_VOUCHER_ID", Value: meta.RootVoucherID},
		{Key: "LINEAGE_DEPTH", Value: meta.Depth},
		{Key: "LINEAGE_ORIGIN", Value: meta.Origin},
		{Key: "SOURCE_VOUCHER_IDS", Value: CanonicalJSON(meta.SourceVoucherIDs)},
	}
	if meta.ParentVoucherID != "" {
		details = append(details, ContractDetail{Key: "PARENT_VOUCHER_ID", Value: meta.ParentVoucherID})
	}
	if meta.ParentHash != "" {
		details = append(details, ContractDetail{Key: "PARENT_VOUCHER_HASH", Value: meta.ParentHash})
	}
	return details
}
