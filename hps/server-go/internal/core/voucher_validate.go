package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
)

func (s *Server) VerifyVoucherBlob(voucher map[string]any) (bool, string) {
	payload := mapValue(voucher["payload"])
	signatures := mapValue(voucher["signatures"])
	rawPayload := asString(voucher["payload_raw"])
	if len(payload) == 0 || len(signatures) == 0 {
		return false, "Voucher payload/signatures missing"
	}
	ownerKey := asString(payload["owner_public_key"])
	issuerKey := asString(payload["issuer_public_key"])
	if ownerKey == "" || issuerKey == "" {
		return false, "Voucher public keys missing"
	}
	if !VerifyPayloadSignatureFlexible(payload, rawPayload, asString(signatures["issuer"]), issuerKey) {
		return false, "Issuer signature invalid"
	}
	return true, ""
}

func (s *Server) VerifyVoucherPowPayload(payload map[string]any) (bool, string, map[string]any) {
	powInfo := mapValue(payload["pow"])
	challenge := asString(powInfo["challenge"])
	nonce := asString(powInfo["nonce"])
	targetBits := asInt(powInfo["target_bits"])
	actionType := asString(powInfo["action_type"])
	voucherID := asString(payload["voucher_id"])
	powVoucherID := asString(powInfo["voucher_id"])
	details := map[string]any{
		"challenge":         challenge,
		"nonce":             nonce,
		"target_bits":       targetBits,
		"action_type":       actionType,
		"voucher_id_match":  powVoucherID != "" && powVoucherID == voucherID,
		"leading_zero_bits": 0,
	}
	if challenge == "" || nonce == "" || targetBits <= 0 {
		return false, "pow_missing", details
	}
	if powVoucherID != "" && powVoucherID != voucherID {
		return false, "pow_voucher_mismatch", details
	}
	if expectedBits, ok := s.lookupPowTargetBits(challenge); ok {
		details["expected_target_bits"] = expectedBits
		if targetBits != expectedBits {
			return false, "pow_target_mismatch", details
		}
	} else {
		minBits := minPowBitsForAction(actionType)
		details["min_target_bits"] = minBits
		if minBits > 0 && targetBits < minBits {
			return false, "pow_target_too_low", details
		}
	}
	challengeBytes, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return false, "pow_invalid", details
	}
	nonceInt := uint64(asInt(nonce))
	data := make([]byte, len(challengeBytes)+8)
	copy(data, challengeBytes)
	binary.BigEndian.PutUint64(data[len(challengeBytes):], nonceInt)
	sum := sha256.Sum256(data)
	lzb := voucherLeadingZeroBits(sum[:])
	details["leading_zero_bits"] = lzb
	if lzb < targetBits {
		return false, "pow_invalid", details
	}
	if actionType == "hps_mint" {
		challengeText := string(challengeBytes)
		if !strings.HasPrefix(challengeText, "HPSMINT:"+voucherID+":") {
			return false, "pow_challenge_mismatch", details
		}
	}
	return true, "", details
}

func (s *Server) lookupPowTargetBits(challenge string) (int, bool) {
	if strings.TrimSpace(challenge) == "" {
		return 0, false
	}
	var bits int
	if err := s.DB.QueryRow("SELECT target_bits FROM pow_history WHERE challenge = ? ORDER BY timestamp DESC LIMIT 1", challenge).Scan(&bits); err != nil {
		return 0, false
	}
	if bits <= 0 {
		return 0, false
	}
	return bits, true
}

func minPowBitsForAction(actionType string) int {
	switch actionType {
	case "upload":
		return 8
	case "dns":
		return 6
	case "report":
		return 6
	case "hps_mint":
		return 12
	case "login":
		return 12
	case "usage_contract":
		return 10
	case "contract_transfer":
		return 10
	case "contract_reset":
		return 10
	case "contract_certify":
		return 10
	case "hps_transfer":
		return 10
	default:
		return 1
	}
}

func (s *Server) GetTraceSourceVouchers(voucherID string) []string {
	if strings.TrimSpace(voucherID) == "" {
		return []string{}
	}
	rows, err := s.DB.Query(`SELECT action_type, contract_content FROM contracts
		WHERE content_hash = ? AND action_type IN (?, ?, ?, ?)
		ORDER BY timestamp DESC`,
		voucherID, "hps_spend_refund", "hps_transfer_refund", "hps_transfer_custody_refund", "miner_fine_refund")
	if err != nil {
		return []string{}
	}
	defer rows.Close()
	var traceIDs []string
	for rows.Next() {
		var actionType, contractB64 string
		if rows.Scan(&actionType, &contractB64) != nil || contractB64 == "" {
			continue
		}
		contractBytes, err := base64.StdEncoding.DecodeString(contractB64)
		if err != nil {
			continue
		}
		valid, _, contractInfo := ValidateContractStructure(contractBytes)
		if !valid || contractInfo == nil {
			continue
		}
		if actionType == "hps_spend_refund" || actionType == "miner_fine_refund" || actionType == "hps_transfer_custody_refund" {
			raw := ExtractContractDetail(contractInfo, "VOUCHERS")
			if raw == "" {
				continue
			}
			var ids []string
			if json.Unmarshal([]byte(raw), &ids) == nil {
				traceIDs = append(traceIDs, ids...)
			}
			continue
		}
		if actionType == "hps_transfer_refund" {
			sourceID := ExtractContractDetail(contractInfo, "ORIGINAL_VOUCHER_ID")
			if sourceID != "" {
				traceIDs = append(traceIDs, sourceID)
			}
		}
	}
	return dedupeStrings(traceIDs)
}

func (s *Server) ValidateVouchers(voucherIDs []string, enforcePow bool) (bool, map[string]string) {
	failures := map[string]string{}
	powCache := map[string]bool{}
	var traceHasPow func(voucherID string, visited map[string]bool, depth int) bool
	traceHasPow = func(voucherID string, visited map[string]bool, depth int) bool {
		if depth <= 0 || voucherID == "" {
			return false
		}
		if cached, ok := powCache[voucherID]; ok {
			return cached
		}
		info := s.GetVoucherAuditInfo(voucherID)
		if info == nil {
			powCache[voucherID] = false
			return false
		}
		payload := mapValue(info["payload"])
		powOK, _, powDetails := s.VerifyVoucherPowPayload(payload)
		if powOK && asString(powDetails["action_type"]) == "hps_mint" {
			powCache[voucherID] = true
			return true
		}
		traceIDs := s.GetTraceSourceVouchers(voucherID)
		conditions := mapValue(payload["conditions"])
		if asString(conditions["type"]) == "exchange" {
			issuerIDs := strSliceValue(conditions["issuer_voucher_ids"])
			if len(issuerIDs) > 0 {
				traceIDs = issuerIDs
			}
		}
		for _, src := range traceIDs {
			if src == "" || visited[src] {
				continue
			}
			visited[src] = true
			if traceHasPow(src, visited, depth-1) {
				powCache[voucherID] = true
				return true
			}
		}
		powCache[voucherID] = false
		return false
	}
	for _, voucherID := range voucherIDs {
		info := s.GetVoucherAuditInfo(voucherID)
		if info == nil {
			failures[voucherID] = "voucher_missing"
			continue
		}
		status := asString(info["status"])
		if asBool(info["invalidated"]) || (status != "valid" && status != "reserved" && status != "locked") {
			failures[voucherID] = "voucher_invalidated"
			continue
		}
		voucher := map[string]any{
			"payload":     mapValue(info["payload"]),
			"payload_raw": asString(info["payload_raw"]),
			"signatures":  mapValue(info["signatures"]),
		}
		if ok, errMsg := s.VerifyVoucherBlob(voucher); !ok {
			if errMsg == "" {
				errMsg = "voucher_signature_invalid"
			}
			failures[voucherID] = errMsg
			continue
		}
		issueContract := asString(info["issue_contract"])
		if issueContract == "" {
			failures[voucherID] = "missing_issue_contract"
			continue
		}
		contractBytes, err := base64.StdEncoding.DecodeString(issueContract)
		if err != nil {
			failures[voucherID] = "issue_contract_decode_error"
			continue
		}
		valid, _, contractInfo := ValidateContractStructure(contractBytes)
		if !valid || contractInfo == nil || contractInfo.Action != "voucher_issue" {
			failures[voucherID] = "issue_contract_invalid"
			continue
		}
		if !s.VerifyContractSignature(contractBytes, contractInfo.User, contractInfo.Signature, "") {
			failures[voucherID] = "issue_contract_signature_invalid"
			continue
		}
		expectedID := ExtractContractDetail(contractInfo, "VOUCHER_ID")
		expectedOwner := ExtractContractDetail(contractInfo, "OWNER")
		expectedIssuer := ExtractContractDetail(contractInfo, "ISSUER")
		expectedValue := ExtractContractDetail(contractInfo, "VALUE")
		payload := mapValue(info["payload"])
		if expectedID != "" && expectedID != voucherID {
			failures[voucherID] = "issue_contract_voucher_mismatch"
			continue
		}
		if expectedOwner != "" && expectedOwner != asString(payload["owner"]) {
			failures[voucherID] = "issue_contract_owner_mismatch"
			continue
		}
		if expectedIssuer != "" && expectedIssuer != asString(payload["issuer"]) {
			failures[voucherID] = "issue_contract_issuer_mismatch"
			continue
		}
		if expectedValue != "" && expectedValue != asString(payload["value"]) {
			failures[voucherID] = "issue_contract_value_mismatch"
			continue
		}
		if s.IsVoucherSuperseded(voucherID, payload) {
			failures[voucherID] = "voucher_superseded"
			continue
		}
		if enforcePow {
			powOK, powReason, powDetails := s.VerifyVoucherPowPayload(payload)
			powMintOK := powOK && asString(powDetails["action_type"]) == "hps_mint"
			if !powMintOK && !traceHasPow(voucherID, map[string]bool{voucherID: true}, 5) {
				if powReason == "" {
					powReason = "pow_invalid"
				}
				failures[voucherID] = powReason
			}
		}
	}
	return len(failures) == 0, failures
}

func voucherLeadingZeroBits(hash []byte) int {
	total := 0
	for _, b := range hash {
		if b == 0 {
			total += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if (b>>uint(i))&1 == 0 {
				total++
			} else {
				return total
			}
		}
	}
	return total
}

func mapValue(v any) map[string]any {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return map[string]any{}
}

func strSliceValue(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, asString(item))
		}
		return out
	default:
		return []string{}
	}
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
