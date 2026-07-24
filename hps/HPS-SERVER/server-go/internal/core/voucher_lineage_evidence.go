package core

import "strings"

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return map[string]any{}
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func inheritStringCondition(dst, src map[string]any, key string) {
	if strings.TrimSpace(asString(dst[key])) != "" {
		return
	}
	value := strings.TrimSpace(asString(src[key]))
	if value == "" {
		return
	}
	dst[key] = value
}

func (s *Server) EnrichVoucherConditions(conditions map[string]any) map[string]any {
	out := cloneAnyMap(conditions)
	sourceIDs := lineageSourceVoucherIDs(out)
	if len(sourceIDs) == 0 {
		return out
	}
	var inheritedIssuerVoucherIDs []string
	for _, sourceID := range sourceIDs {
		info := s.GetVoucherAuditInfo(sourceID)
		if info == nil {
			continue
		}
		payload := mapValue(info["payload"])
		parentConditions := mapValue(payload["conditions"])
		inheritStringCondition(out, parentConditions, "exchange_contract_id")
		inheritStringCondition(out, parentConditions, "dkvhps_disclosure_contract_id")
		inheritStringCondition(out, parentConditions, "dkvhps_disclosure_contract_hash")
		inheritStringCondition(out, parentConditions, "lineage_close_contract_id")
		if len(inheritedIssuerVoucherIDs) == 0 {
			inheritedIssuerVoucherIDs = dedupeStrings(strSliceValue(parentConditions["issuer_voucher_ids"]))
		}
	}
	if len(strSliceValue(out["issuer_voucher_ids"])) == 0 && len(inheritedIssuerVoucherIDs) > 0 {
		out["issuer_voucher_ids"] = inheritedIssuerVoucherIDs
	}
	return out
}
