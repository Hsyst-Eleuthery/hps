package core

import (
	"encoding/base64"
	"log"
	"strconv"
	"strings"
	"unicode"
)

func execDB(db interface{ Exec(string, ...any) (interface{}, error) }, query string, args ...any) {
	if _, err := db.Exec(query, args...); err != nil {
		log.Printf("DB ERROR: %s err=%v", query[:min(len(query), 120)], err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

func base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func NewUUID() string {
	return newUUID()
}

// IsValidUsername valida username: apenas [a-zA-Z0-9_.-], max 64 chars
func IsValidUsername(username string) bool {
	return isValidUsername(username)
}

func isValidUsername(username string) bool {
	if len(username) == 0 || len(username) > 64 {
		return false
	}
	for _, c := range username {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
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

// sanitizeString removes control characters from a string.
// H-04 FIX: Prevent injection via control characters in reason field.
func sanitizeString(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1 // remove control chars
		}
		return r
	}, s)
}
