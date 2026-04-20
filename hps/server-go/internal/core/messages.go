package core

import (
	"strings"
)

func NormalizeMessageServerAddress(raw string) string {
	value := strings.TrimSpace(strings.TrimRight(raw, "/"))
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	value = strings.ToLower(strings.TrimSpace(strings.TrimRight(value, "/")))
	host := value
	port := ""
	if strings.Count(value, ":") == 1 {
		lastColon := strings.LastIndex(value, ":")
		if lastColon > 0 && lastColon < len(value)-1 {
			host = value[:lastColon]
			port = value[lastColon+1:]
		}
	}
	switch strings.TrimSpace(host) {
	case "localhost", "127.0.0.1", "[::1]", "::1":
		host = "127.0.0.1"
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

func splitNormalizedMessageAddress(raw string) (string, string) {
	value := NormalizeMessageServerAddress(raw)
	if value == "" {
		return "", ""
	}
	if strings.Count(value, ":") == 1 {
		lastColon := strings.LastIndex(value, ":")
		if lastColon > 0 && lastColon < len(value)-1 {
			return value[:lastColon], value[lastColon+1:]
		}
	}
	return value, ""
}

func isMessageLoopbackHost(host string) bool {
	switch strings.TrimSpace(strings.ToLower(host)) {
	case "localhost", "127.0.0.1", "[::1]", "::1":
		return true
	default:
		return false
	}
}

func MessageServerAddressesEqual(left string, candidates ...string) bool {
	leftHost, leftPort := splitNormalizedMessageAddress(left)
	if leftHost == "" {
		return false
	}
	for _, candidate := range candidates {
		rightHost, rightPort := splitNormalizedMessageAddress(candidate)
		if rightHost == "" {
			continue
		}
		if leftHost == rightHost && leftPort == rightPort {
			return true
		}
		if leftPort != "" && leftPort == rightPort {
			if isMessageLoopbackHost(leftHost) && (isMessageLoopbackHost(rightHost) || rightHost == "0.0.0.0") {
				return true
			}
			if isMessageLoopbackHost(rightHost) && (isMessageLoopbackHost(leftHost) || leftHost == "0.0.0.0") {
				return true
			}
		}
	}
	return false
}
