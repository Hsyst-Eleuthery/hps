package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func nowPlus(ttl time.Duration) time.Time {
	return time.Now().Add(ttl)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		if t == nil {
			return ""
		}
		return fmt.Sprint(t)
	}
}
