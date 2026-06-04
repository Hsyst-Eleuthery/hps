package core

import (
	"encoding/base64"
	"strconv"
	"strings"
)

func itoa(v int) string {
	return strconv.Itoa(v)
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func NewUUID() string {
	return newUUID()
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	default:
		return false
	}
}

func castMap(v any) map[string]any {
	if out, ok := v.(map[string]any); ok && out != nil {
		return out
	}
	return map[string]any{}
}
