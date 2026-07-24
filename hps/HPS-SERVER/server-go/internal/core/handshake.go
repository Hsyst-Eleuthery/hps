package core

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	handshakeTTL        = 300 // 5 minutes
	handshakeTimeoutSec = 30
)

// HandshakeState holds an in-progress handshake with a remote server.
type HandshakeState struct {
	ServerID    string
	Nonce       []byte
	PublicKey   string
	StartedAt   float64
	RemoteNonce []byte
	RemoteKey   string
	Completed   bool
}

var (
	handshakeMu sync.Mutex
	// handshakeStates keyed by normalized server address
	handshakeStates = map[string]*HandshakeState{}
)

// GenerateNonce creates a cryptographically random 16-byte nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	return nonce, err
}

// ServerHandshakeInit is sent when server A initiates a handshake with server B.
type ServerHandshakeInit struct {
	ServerID  string `json:"server_id"`
	Nonce     string `json:"nonce"`
	PublicKey string `json:"public_key"`
	Timestamp float64 `json:"timestamp"`
}

// ServerHandshakeResponse is returned by server B after receiving init.
type ServerHandshakeResponse struct {
	ServerID  string `json:"server_id"`
	Nonce     string `json:"nonce"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
	Timestamp float64 `json:"timestamp"`
}

// ServerHandshakeComplete is sent by server A to finalize.
type ServerHandshakeComplete struct {
	ServerID  string `json:"server_id"`
	Signature string `json:"signature"`
	Timestamp float64 `json:"timestamp"`
}

// InitHandshake initiates a handshake with a remote server.
// Returns (success, errorMsg).
func (s *Server) InitHandshake(remoteAddr string) (bool, string) {
	remoteAddr = s.ensureAddressProtocol(remoteAddr)

	nonce, err := GenerateNonce()
	if err != nil {
		return false, "failed to generate nonce"
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	initPayload := ServerHandshakeInit{
		ServerID:  s.ServerID,
		Nonce:     nonceB64,
		PublicKey: base64.StdEncoding.EncodeToString(s.PublicKeyPEM),
		Timestamp: now(),
	}

	ok, respRaw, errMsg := s.MakeRemoteRequestJSON(remoteAddr, "/handshake/init", "POST", map[string]any{
		"server_id":  initPayload.ServerID,
		"nonce":      initPayload.Nonce,
		"public_key": initPayload.PublicKey,
		"timestamp":  initPayload.Timestamp,
	})
	if !ok {
		return false, errMsg
	}

	// Parse response
	remoteNonceB64 := asString(respRaw["nonce"])
	remotePubKey := asString(respRaw["public_key"])
	remoteSig := asString(respRaw["signature"])
	remoteServerID := asString(respRaw["server_id"])

	if remoteNonceB64 == "" || remotePubKey == "" || remoteSig == "" {
		return false, "incomplete handshake response"
	}

	remoteNonce, err := base64.StdEncoding.DecodeString(remoteNonceB64)
	if err != nil {
		return false, "invalid remote nonce"
	}

	// Verify B's signature over A's nonce
	if !VerifyRawTextSignature(nonceB64, remoteSig, remotePubKey) {
		return false, "remote server signature invalid"
	}

	// Store handshake state
	handshakeMu.Lock()
	handshakeStates[normalizeAddress(remoteAddr)] = &HandshakeState{
		ServerID:    remoteServerID,
		Nonce:       nonce,
		PublicKey:   remotePubKey,
		StartedAt:   now(),
		RemoteNonce: remoteNonce,
		RemoteKey:   remotePubKey,
	}
	handshakeMu.Unlock()

	// Complete: sign B's nonce
	completeSig := s.SignRawText(remoteNonceB64)

	ok, completeResp, errMsg := s.MakeRemoteRequestJSON(remoteAddr, "/handshake/complete", "POST", map[string]any{
		"server_id":  s.ServerID,
		"signature":  completeSig,
		"timestamp":  now(),
	})
	if !ok {
		return false, errMsg
	}

	success, _ := completeResp["success"].(bool)
	if !success {
		return false, "handshake completion rejected"
	}

	// Mark handshake completed
	handshakeMu.Lock()
	if state, ok := handshakeStates[normalizeAddress(remoteAddr)]; ok {
		state.Completed = true
	}
	handshakeMu.Unlock()

	// Persist in DB
	s.saveHandshake(remoteServerID, remoteAddr, nonce, remoteNonce, base64.StdEncoding.EncodeToString(s.PublicKeyPEM), remotePubKey)

	log.Printf("handshake completed with %s (server_id=%s)", remoteAddr, remoteServerID)
	return true, ""
}

// HandleHandshakeInit handles the /handshake/init endpoint (called by remote server A).
func (s *Server) HandleHandshakeInit(data map[string]any) map[string]any {
	serverID := asString(data["server_id"])
	nonceB64 := asString(data["nonce"])
	pubKey := asString(data["public_key"])
	timestamp := asFloat(data["timestamp"])

	if serverID == "" || nonceB64 == "" || pubKey == "" {
		return map[string]any{"success": false, "error": "missing fields"}
	}

	// Reject if timestamp too old
	nowTs := now()
	if nowTs-timestamp > handshakeTimeoutSec || timestamp-nowTs > handshakeTimeoutSec {
		return map[string]any{"success": false, "error": "timestamp out of range"}
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil || len(nonce) != 16 {
		return map[string]any{"success": false, "error": "invalid nonce"}
	}

	// Generate our nonce
	ourNonce, err := GenerateNonce()
	if err != nil {
		return map[string]any{"success": false, "error": "failed to generate nonce"}
	}
	ourNonceB64 := base64.StdEncoding.EncodeToString(ourNonce)

	// Sign the remote nonce
	sig := s.SignRawText(nonceB64)

	// Store state for completion
	handshakeMu.Lock()
	handshakeStates[serverID] = &HandshakeState{
		ServerID:    serverID,
		Nonce:       ourNonce,
		PublicKey:   pubKey,
		StartedAt:   nowTs,
		RemoteNonce: nonce,
		RemoteKey:   pubKey,
	}
	handshakeMu.Unlock()

	return map[string]any{
		"success":   true,
		"server_id": s.ServerID,
		"nonce":     ourNonceB64,
		"public_key": base64.StdEncoding.EncodeToString(s.PublicKeyPEM),
		"signature": sig,
		"timestamp": nowTs,
	}
}

// HandleHandshakeComplete handles the /handshake/complete endpoint.
func (s *Server) HandleHandshakeComplete(data map[string]any) map[string]any {
	serverID := asString(data["server_id"])
	sig := asString(data["signature"])
	timestamp := asFloat(data["timestamp"])

	if serverID == "" || sig == "" {
		return map[string]any{"success": false, "error": "missing fields"}
	}

	nowTs := now()
	if nowTs-timestamp > handshakeTimeoutSec || timestamp-nowTs > handshakeTimeoutSec {
		return map[string]any{"success": false, "error": "timestamp out of range"}
	}

	handshakeMu.Lock()
	state, ok := handshakeStates[serverID]
	if !ok {
		handshakeMu.Unlock()
		return map[string]any{"success": false, "error": "no pending handshake"}
	}
	handshakeMu.Unlock()

	// Verify the signature over our nonce
	ourNonceB64 := base64.StdEncoding.EncodeToString(state.Nonce)
	if !VerifyRawTextSignature(ourNonceB64, sig, state.PublicKey) {
		return map[string]any{"success": false, "error": "invalid signature"}
	}

	// Mark completed
	handshakeMu.Lock()
	state.Completed = true
	handshakeMu.Unlock()

	// Persist in DB
	remoteAddr := serverID
	s.saveHandshake(serverID, remoteAddr, state.RemoteNonce, state.Nonce, state.PublicKey, base64.StdEncoding.EncodeToString(s.PublicKeyPEM))

	log.Printf("handshake completed from %s (server_id=%s)", remoteAddr, serverID)
	return map[string]any{"success": true}
}

// VerifyHandshake checks if a handshake was previously completed with a server.
func (s *Server) VerifyHandshake(serverAddress string) bool {
	serverAddress = strings.TrimSpace(serverAddress)
	if serverAddress == "" {
		return false
	}
	// Check in-memory cache first
	handshakeMu.Lock()
	if state, ok := handshakeStates[normalizeAddress(serverAddress)]; ok {
		if state.Completed && (now()-state.StartedAt) < handshakeTTL {
			handshakeMu.Unlock()
			return true
		}
	}
	handshakeMu.Unlock()

	// Check DB
	var completedAt float64
	_ = s.DB.QueryRow(`SELECT completed_at FROM server_handshakes
		WHERE (server_a = ? OR server_b = ?) AND completed_at > ? LIMIT 1`,
		serverAddress, serverAddress, now()-handshakeTTL).Scan(&completedAt)

	return completedAt > 0
}

// GetKnownServers returns a list of server addresses that have completed handshakes.
func (s *Server) GetKnownServers() []string {
	rows, err := s.DB.Query(`SELECT DISTINCT
		CASE WHEN server_a = ? THEN server_b ELSE server_a END AS peer
		FROM server_handshakes WHERE completed_at > ?`,
		s.Address, now()-handshakeTTL)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var servers []string
	for rows.Next() {
		var addr string
		if rows.Scan(&addr) == nil {
			servers = append(servers, addr)
		}
	}
	return servers
}

// cleanupExpiredHandshakes removes in-memory handshake states older than TTL.
func cleanupExpiredHandshakes() {
	handshakeMu.Lock()
	defer handshakeMu.Unlock()
	nowTs := now()
	for addr, state := range handshakeStates {
		if nowTs-state.StartedAt > handshakeTTL {
			delete(handshakeStates, addr)
		}
	}
}

func init() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			cleanupExpiredHandshakes()
		}
	}()
}

func (s *Server) saveHandshake(serverID, remoteAddr string, nonceA, nonceB []byte, pubkeyA, pubkeyB string) {
	nowTs := now()
	expiresAt := nowTs + handshakeTTL
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO server_handshakes
		(server_a, server_b, nonce_a, nonce_b, pubkey_a, pubkey_b, sig_a, sig_b, completed_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, '', '', ?, ?)`,
		s.Address, remoteAddr, nonceA, nonceB, pubkeyA, pubkeyB, nowTs, expiresAt)
}

func normalizeAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimRight(addr, "/")
	if addr == "" {
		return ""
	}
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	return strings.ToLower(addr)
}
