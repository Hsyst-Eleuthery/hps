package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"hpsserver/internal/core"
)

const (
	headerInterServerAddress   = "X-HPS-Server-Address"
	headerInterServerTimestamp = "X-HPS-Timestamp"
	headerInterServerNonce     = "X-HPS-Nonce"
	headerInterServerSignature = "X-HPS-Signature"
	headerInterServerBodyHash  = "X-HPS-Body-SHA256"
	headerInterServerPublicKey = "X-HPS-Server-Public-Key"
)

var (
	interServerNonceMu   sync.Mutex
	interServerNonceSeen = map[string]float64{}
)

func RequireInterServerAuth(server *core.Server) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			issuerAddress := strings.TrimSpace(r.Header.Get(headerInterServerAddress))
			timestampRaw := strings.TrimSpace(r.Header.Get(headerInterServerTimestamp))
			nonce := strings.TrimSpace(r.Header.Get(headerInterServerNonce))
			signature := strings.TrimSpace(r.Header.Get(headerInterServerSignature))
			bodyHashHeader := strings.TrimSpace(strings.ToLower(r.Header.Get(headerInterServerBodyHash)))
			if issuerAddress == "" || timestampRaw == "" || nonce == "" || signature == "" || bodyHashHeader == "" {
				writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Missing inter-server auth headers"})
				return
			}

			ts, err := strconv.ParseFloat(timestampRaw, 64)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Invalid inter-server timestamp"})
				return
			}
			nowTs := float64(time.Now().UnixNano()) / 1e9
			if ts < nowTs-120 || ts > nowTs+30 {
				writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Inter-server timestamp out of range"})
				return
			}

			if len(nonce) < 16 || len(nonce) > 128 {
				writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Invalid inter-server nonce"})
				return
			}
			nonceKey := normalizeServerAddressForMatch(issuerAddress) + "|" + nonce
			if !registerInterServerNonce(nonceKey, nowTs) {
				writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Replayed inter-server nonce"})
				return
			}

			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Failed to read request body"})
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			bodyHash := sha256.Sum256(bodyBytes)
			calculatedBodyHash := hex.EncodeToString(bodyHash[:])
			if calculatedBodyHash != bodyHashHeader {
				writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Invalid inter-server body hash"})
				return
			}

			issuerPublicKey := resolveServerNodePublicKey(server, issuerAddress)
			headerPublicKey := strings.TrimSpace(r.Header.Get(headerInterServerPublicKey))
			if issuerPublicKey == "" {
				if headerPublicKey == "" && !isKnownServerAddress(server, issuerAddress) {
					writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Unknown inter-server issuer"})
					return
				}
				issuerPublicKey = headerPublicKey
			}
			if issuerPublicKey != "" && headerPublicKey != "" && normalizePublicKeyForCompare(issuerPublicKey) != normalizePublicKeyForCompare(headerPublicKey) {
				writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Inter-server key mismatch"})
				return
			}
			if issuerPublicKey == "" {
				writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Unknown inter-server issuer"})
				return
			}

			signedPayload := map[string]any{
				"issuer":      issuerAddress,
				"target":      r.Host,
				"method":      strings.ToUpper(r.Method),
				"path":        r.URL.Path,
				"query":       r.URL.RawQuery,
				"timestamp":   ts,
				"nonce":       nonce,
				"body_sha256": calculatedBodyHash,
			}
			if !core.VerifyPayloadSignature(signedPayload, signature, issuerPublicKey) {
				writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Invalid inter-server signature"})
				return
			}
			rememberKnownInterServer(server, issuerAddress)
			rememberInterServerNode(server, issuerAddress, issuerPublicKey)
			next.ServeHTTP(w, r)
		})
	}
}

func registerInterServerNonce(key string, nowTs float64) bool {
	interServerNonceMu.Lock()
	defer interServerNonceMu.Unlock()

	for nonceKey, expiresAt := range interServerNonceSeen {
		if expiresAt <= nowTs {
			delete(interServerNonceSeen, nonceKey)
		}
	}
	if _, exists := interServerNonceSeen[key]; exists {
		return false
	}
	interServerNonceSeen[key] = nowTs + 300
	return true
}

func resolveServerNodePublicKey(server *core.Server, issuerAddress string) string {
	if server == nil || strings.TrimSpace(issuerAddress) == "" {
		return ""
	}
	var exact string
	if err := server.DB.QueryRow(`SELECT public_key FROM server_nodes WHERE address = ? LIMIT 1`, issuerAddress).Scan(&exact); err == nil && strings.TrimSpace(exact) != "" {
		return exact
	}

	rows, err := server.DB.Query(`SELECT address, public_key FROM server_nodes`)
	if err != nil {
		return ""
	}
	defer rows.Close()

	want := normalizeServerAddressForMatch(issuerAddress)
	for rows.Next() {
		var address, publicKey string
		if scanErr := rows.Scan(&address, &publicKey); scanErr != nil {
			continue
		}
		if normalizeServerAddressForMatch(address) == want {
			return publicKey
		}
	}
	return ""
}

func normalizeServerAddressForMatch(raw string) string {
	trimmed := strings.TrimSpace(strings.TrimRight(raw, "/"))
	if trimmed == "" {
		return ""
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "http://"), "https://")))
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Host))
	return strings.TrimRight(host, "/")
}

func isKnownServerAddress(server *core.Server, issuerAddress string) bool {
	if server == nil || strings.TrimSpace(issuerAddress) == "" {
		return false
	}
	var exact string
	if err := server.DB.QueryRow(`SELECT address FROM known_servers WHERE address = ? LIMIT 1`, issuerAddress).Scan(&exact); err == nil && exact != "" {
		return true
	}
	rows, err := server.DB.Query(`SELECT address FROM known_servers`)
	if err != nil {
		return false
	}
	defer rows.Close()
	want := normalizeServerAddressForMatch(issuerAddress)
	for rows.Next() {
		var address string
		if scanErr := rows.Scan(&address); scanErr != nil {
			continue
		}
		if normalizeServerAddressForMatch(address) == want {
			return true
		}
	}
	return false
}

func normalizePEMForCompare(raw string) string {
	return strings.ReplaceAll(strings.TrimSpace(raw), "\r\n", "\n")
}

func normalizePublicKeyForCompare(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "BEGIN PUBLIC KEY") {
		return normalizePEMForCompare(trimmed)
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		decodedText := strings.TrimSpace(string(decoded))
		if strings.Contains(decodedText, "BEGIN PUBLIC KEY") {
			return normalizePEMForCompare(decodedText)
		}
	}
	return trimmed
}

func rememberKnownInterServer(server *core.Server, issuerAddress string) {
	if server == nil {
		return
	}
	issuerAddress = strings.TrimSpace(issuerAddress)
	if issuerAddress == "" {
		return
	}
	server.RememberKnownServer(issuerAddress)
}

func rememberInterServerNode(server *core.Server, issuerAddress string, publicKey string) {
	if server == nil {
		return
	}
	issuerAddress = strings.TrimSpace(issuerAddress)
	publicKey = strings.TrimSpace(publicKey)
	if issuerAddress == "" || publicKey == "" {
		return
	}
	nowTs := float64(time.Now().UnixNano()) / 1e9
	_, _ = server.DB.Exec(`INSERT OR REPLACE INTO server_nodes
		(server_id, address, public_key, last_seen, is_active, reputation, sync_priority)
		VALUES (
			COALESCE((SELECT server_id FROM server_nodes WHERE address = ?), ?),
			?,
			?,
			?,
			1,
			COALESCE((SELECT reputation FROM server_nodes WHERE address = ?), 100),
			1
		)`,
		issuerAddress,
		issuerAddress,
		issuerAddress,
		publicKey,
		nowTs,
		issuerAddress,
	)
}
