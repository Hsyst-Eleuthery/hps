package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

func ComputeVoucherIntegrityHash(payload map[string]any, signatures map[string]any) string {
	data := map[string]any{"payload": payload, "signatures": signatures}
	canonical := canonicalJSON(data)
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

func AttachVoucherIntegrity(voucher map[string]any) map[string]any {
	payload, _ := voucher["payload"].(map[string]any)
	signatures, _ := voucher["signatures"].(map[string]any)
	voucher["integrity"] = map[string]any{
		"hash": ComputeVoucherIntegrityHash(payload, signatures),
		"algo": "sha256",
	}
	return voucher
}

func RenderVoucherHTML(voucher map[string]any) string {
	payload, _ := voucher["payload"].(map[string]any)
	value := asInt(payload["value"])
	owner := asString(payload["owner"])
	issuer := asString(payload["issuer"])
	reason := asString(payload["reason"])
	issuedAt := asFloat(payload["issued_at"])
	issuedText := ""
	if issuedAt > 0 {
		issuedText = time.Unix(int64(issuedAt), 0).Format("2006-01-02 15:04:05")
	}
	conditions := payload["conditions"]
	conditionsText := "{}"
	if conditions != nil {
		conditionsText = canonicalJSON(conditions)
	}
	return fmt.Sprintf(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>HPS Voucher</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f5f1e6; }
    .note { width: 520px; margin: 40px auto; padding: 24px; border: 3px solid #8b6b3f; background: #f2e6c9; }
    .header { display: flex; justify-content: space-between; font-weight: bold; color: #5a432a; }
    .row { margin-top: 10px; color: #5a432a; }
    .label { font-weight: bold; }
  </style>
</head>
<body>
  <div class="note">
    <div class="header">
      <div>HPS</div>
      <div>%d HPS</div>
    </div>
    <div class="row"><span class="label">Owner:</span> %s</div>
    <div class="row"><span class="label">Issuer:</span> %s</div>
    <div class="row"><span class="label">Reason:</span> %s</div>
    <div class="row"><span class="label">Issued at:</span> %s</div>
    <div class="row"><span class="label">Conditions:</span> %s</div>
  </div>
</body>
</html>`, value, owner, issuer, reason, issuedText, conditionsText)
}

func FormatHpsVoucherHsyst(voucher map[string]any) string {
	payload, _ := voucher["payload"].(map[string]any)
	signatures, _ := voucher["signatures"].(map[string]any)
	integrity, _ := voucher["integrity"].(map[string]any)
	powInfo := payload["pow"]
	conditions := payload["conditions"]
	powText := canonicalJSON(powInfo)
	conditionsText := canonicalJSON(conditions)
	if powInfo == nil {
		powText = "{}"
	}
	if conditions == nil {
		conditionsText = "{}"
	}
	lines := []string{
		"# HSYST P2P SERVICE",
		"## HPS VOUCHER:",
		"### DETAILS:",
		"# VERSION: " + fmt.Sprint(payload["version"]),
		"# VOUCHER_ID: " + asString(payload["voucher_id"]),
		"# VALUE: " + fmt.Sprint(payload["value"]),
		"# ISSUER: " + asString(payload["issuer"]),
		"# ISSUER_PUBLIC_KEY: " + asString(payload["issuer_public_key"]),
		"# OWNER: " + asString(payload["owner"]),
		"# OWNER_PUBLIC_KEY: " + asString(payload["owner_public_key"]),
		"# REASON: " + asString(payload["reason"]),
		"# ISSUED_AT: " + fmt.Sprint(payload["issued_at"]),
		"# POW: " + powText,
		"# CONDITIONS: " + conditionsText,
		"# DKVHPS: " + canonicalJSON(payload["dkvhps"]),
		"# LINEAGE_ROOT_VOUCHER_ID: " + asString(payload["lineage_root_voucher_id"]),
		"# LINEAGE_PARENT_VOUCHER_ID: " + asString(payload["lineage_parent_voucher_id"]),
		"# LINEAGE_PARENT_HASH: " + asString(payload["lineage_parent_hash"]),
		"# LINEAGE_DEPTH: " + fmt.Sprint(payload["lineage_depth"]),
		"# LINEAGE_ORIGIN: " + asString(payload["lineage_origin"]),
		"### :END DETAILS",
		"### SIGNATURES:",
		"# OWNER: " + asString(signatures["owner"]),
		"# ISSUER: " + asString(signatures["issuer"]),
		"# INTEGRITY_HASH: " + asString(integrity["hash"]),
		"# INTEGRITY_ALGO: " + asString(integrity["algo"]),
		"### :END SIGNATURES",
		"## :END HPS VOUCHER",
	}
	return strings.Join(lines, "\n") + "\n"
}

func ParseHpsVoucherHsyst(text string) map[string]any {
	if !strings.HasPrefix(text, "# HSYST P2P SERVICE") {
		return nil
	}
	details := map[string]string{}
	signatures := map[string]string{}
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "### ") {
			if strings.HasSuffix(line, ":") {
				section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "### "), ":"))
			} else if strings.HasPrefix(line, "### :END") {
				section = ""
			}
			continue
		}
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		keyValue := strings.TrimPrefix(line, "# ")
		parts := strings.SplitN(keyValue, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if section == "details" {
			details[key] = value
		} else if section == "signatures" {
			signatures[key] = value
		}
	}
	if len(details) == 0 {
		return nil
	}
	payload := map[string]any{
		"voucher_type":              "HPS",
		"version":                   asInt(details["version"]),
		"voucher_id":                details["voucher_id"],
		"value":                     asInt(details["value"]),
		"issuer":                    details["issuer"],
		"issuer_public_key":         details["issuer_public_key"],
		"owner":                     details["owner"],
		"owner_public_key":          details["owner_public_key"],
		"reason":                    details["reason"],
		"issued_at":                 asFloat(details["issued_at"]),
		"pow":                       parseJSONField(details["pow"]),
		"conditions":                parseJSONField(details["conditions"]),
		"dkvhps":                    parseJSONField(details["dkvhps"]),
		"lineage_root_voucher_id":   details["lineage_root_voucher_id"],
		"lineage_parent_voucher_id": details["lineage_parent_voucher_id"],
		"lineage_parent_hash":       details["lineage_parent_hash"],
		"lineage_depth":             asInt(details["lineage_depth"]),
		"lineage_origin":            details["lineage_origin"],
	}
	voucher := map[string]any{
		"voucher_type": "HPS",
		"payload":      payload,
		"signatures": map[string]any{
			"owner":  signatures["owner"],
			"issuer": signatures["issuer"],
		},
		"integrity": map[string]any{
			"hash": signatures["integrity_hash"],
			"algo": defaultString(signatures["integrity_algo"], "sha256"),
		},
	}
	return voucher
}

func parseJSONField(text string) any {
	if strings.TrimSpace(text) == "" {
		return map[string]any{}
	}
	var out any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return map[string]any{}
	}
	return out
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func asInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		i, _ := strconv.Atoi(t)
		return i
	default:
		return 0
	}
}

func asFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func canonicalJSON(value any) string {
	var b strings.Builder
	encodeCanonical(&b, value)
	return b.String()
}

func CanonicalJSON(value any) string {
	return canonicalJSON(value)
}

func encodeCanonical(b *strings.Builder, value any) {
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
	case string:
		encoded, _ := json.Marshal(v)
		b.Write(encoded)
	case float64:
		b.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
	case float32:
		b.WriteString(strconv.FormatFloat(float64(v), 'f', -1, 32))
	case int:
		b.WriteString(strconv.Itoa(v))
	case int64:
		b.WriteString(strconv.FormatInt(v, 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(v), 10))
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case []any:
		b.WriteString("[")
		for i, item := range v {
			if i > 0 {
				b.WriteString(",")
			}
			encodeCanonical(b, item)
		}
		b.WriteString("]")
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(",")
			}
			keyEnc, _ := json.Marshal(k)
			b.Write(keyEnc)
			b.WriteString(":")
			encodeCanonical(b, v[k])
		}
		b.WriteString("}")
	case map[string]string:
		converted := map[string]any{}
		for k, val := range v {
			converted[k] = val
		}
		encodeCanonical(b, converted)
	default:
		encoded, _ := json.Marshal(v)
		b.Write(encoded)
	}
}
