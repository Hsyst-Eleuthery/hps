package httpapi

import (
	"bytes"
	"encoding/json"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"hpsserver/internal/core"
)

func newTestCoreServer(t *testing.T) *core.Server {
	t.Helper()
	baseDir := t.TempDir()
	server, err := core.NewServer(core.Config{
		DBPath:           filepath.Join(baseDir, "test.db"),
		FilesDir:         filepath.Join(baseDir, "files"),
		Host:             "127.0.0.1",
		Port:             0,
		MasterPassphrase: "test-passphrase",
	})
	if err != nil {
		t.Fatalf("new test server: %v", err)
	}
	t.Cleanup(func() {
		_ = server.DB.Close()
	})
	return server
}

func TestExchangeRelayForwardsEventToEmitter(t *testing.T) {
	targetServer := newTestCoreServer(t)
	remoteServer := newTestCoreServer(t)
	remoteAddress := remoteServer.Address
	remotePublicKey := base64.StdEncoding.EncodeToString(remoteServer.PublicKeyPEM)
	_, _ = targetServer.DB.Exec(`INSERT INTO known_servers (address, added_date, last_connected, is_active) VALUES (?, 0, 0, 1)`, remoteAddress)
	_, _ = targetServer.DB.Exec(`INSERT INTO server_nodes (server_id, address, public_key, last_seen, is_active, reputation, sync_priority) VALUES (?, ?, ?, 0, 1, 100, 1)`,
		remoteServer.ServerID, remoteAddress, remotePublicKey)

	var gotUsername string
	var gotEvent string
	var gotTransferID string
	targetServer.UserEventEmitter = func(username, event string, payload map[string]any) {
		gotUsername = username
		gotEvent = event
		gotTransferID = asString(payload["transfer_id"])
	}

	httpServer := httptest.NewServer(NewRouter(targetServer))
	defer httpServer.Close()

	ok, _, errMsg := remoteServer.MakeRemoteRequestJSON(httpServer.URL, "/exchange/relay", "POST", map[string]any{
		"username": "alice",
		"event":    "exchange_complete",
		"payload": map[string]any{
			"transfer_id": "tx-123",
			"status":      "signed",
		},
	})
	if !ok {
		t.Fatalf("relay request failed: %s", errMsg)
	}
	if gotUsername != "alice" {
		t.Fatalf("username mismatch: got %q", gotUsername)
	}
	if gotEvent != "exchange_complete" {
		t.Fatalf("event mismatch: got %q", gotEvent)
	}
	if gotTransferID != "tx-123" {
		t.Fatalf("transfer id mismatch: got %q", gotTransferID)
	}
}

func TestExchangeRelayAcceptsUnknownIssuerUsingSignedHeaderKey(t *testing.T) {
	targetServer := newTestCoreServer(t)
	remoteServer := newTestCoreServer(t)

	var gotUsername string
	targetServer.UserEventEmitter = func(username, event string, payload map[string]any) {
		gotUsername = username
	}

	httpServer := httptest.NewServer(NewRouter(targetServer))
	defer httpServer.Close()

	ok, _, errMsg := remoteServer.MakeRemoteRequestJSON(httpServer.URL, "/exchange/relay", "POST", map[string]any{
		"username": "alice",
		"event":    "exchange_pending",
		"payload": map[string]any{
			"transfer_id": "tx-unknown",
			"status":      "pending_signature",
		},
	})
	if !ok {
		t.Fatalf("relay request failed: %s", errMsg)
	}
	if gotUsername != "alice" {
		t.Fatalf("username mismatch: got %q", gotUsername)
	}

	var knownAddress string
	if err := targetServer.DB.QueryRow(`SELECT address FROM known_servers WHERE address = ?`, remoteServer.Address).Scan(&knownAddress); err != nil {
		t.Fatalf("expected remote server to be remembered, query err: %v", err)
	}
	if knownAddress != remoteServer.Address {
		t.Fatalf("known server mismatch: got %q", knownAddress)
	}
}

func TestExchangeConfirmExpiredTokenReleasesReservedVouchers(t *testing.T) {
	server := newTestCoreServer(t)

	nowTs := float64(time.Now().Unix())
	_, _ = server.DB.Exec(`INSERT INTO hps_vouchers
		(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"voucher-expired-confirm", server.Address, "alice", 9, "test", nowTs, `{}`, "issuer-sig", "owner-sig", "valid", nil, 0, nowTs)

	ok, _, errMsg := server.ReserveVouchersForSession("alice", "exchange-session-expired-confirm", []string{"voucher-expired-confirm"})
	if !ok {
		t.Fatalf("reserve vouchers: %s", errMsg)
	}

	server.ExchangeTokens["token-expired-confirm"] = map[string]any{
		"payload": map[string]any{
			"token_id": "token-expired-confirm",
		},
		"signature":  "token-signature",
		"session_id": "exchange-session-expired-confirm",
		"expires_at": nowTs - 1,
	}

	body, err := json.Marshal(map[string]any{
		"token": map[string]any{
			"token_id": "token-expired-confirm",
		},
		"signature": "token-signature",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/exchange/confirm", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewRouter(server).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}

	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["error"] != "Token expired" {
		t.Fatalf("expected token expired error, got %#v", response)
	}
	if _, ok := server.ExchangeTokens["token-expired-confirm"]; ok {
		t.Fatalf("expected expired token to be deleted after confirm attempt")
	}

	var status string
	if err := server.DB.QueryRow(`SELECT status FROM hps_vouchers WHERE voucher_id = ?`, "voucher-expired-confirm").Scan(&status); err != nil {
		t.Fatalf("read voucher after confirm: %v", err)
	}
	if status != "valid" {
		t.Fatalf("expected voucher to be released after expired confirm, got %q", status)
	}
}

func TestExchangeConfirmKeepsVouchersReservedUntilCompletion(t *testing.T) {
	server := newTestCoreServer(t)

	nowTs := float64(time.Now().Unix())
	_, _ = server.DB.Exec(`INSERT INTO hps_vouchers
		(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"voucher-confirm-hold", server.Address, "alice", 9, "test", nowTs, `{}`, "issuer-sig", "owner-sig", "valid", nil, 0, nowTs)

	ok, _, errMsg := server.ReserveVouchersForSession("alice", "exchange-session-confirm-hold", []string{"voucher-confirm-hold"})
	if !ok {
		t.Fatalf("reserve vouchers: %s", errMsg)
	}

	server.ExchangeTokens["token-confirm-hold"] = map[string]any{
		"payload": map[string]any{
			"token_id":      "token-confirm-hold",
			"owner":         "alice",
			"target_server": "target-server.test",
			"voucher_ids":   []string{"voucher-confirm-hold"},
			"total_value":   9,
		},
		"signature":  "token-signature",
		"session_id": "exchange-session-confirm-hold",
		"expires_at": nowTs + 60,
	}

	body, _ := json.Marshal(map[string]any{
		"token": map[string]any{
			"token_id":      "token-confirm-hold",
			"owner":         "alice",
			"target_server": "target-server.test",
			"voucher_ids":   []string{"voucher-confirm-hold"},
			"total_value":   9,
		},
		"signature": "token-signature",
	})

	req := httptest.NewRequest(http.MethodPost, "/exchange/confirm", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewRouter(server).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var status string
	if err := server.DB.QueryRow(`SELECT status FROM hps_vouchers WHERE voucher_id = ?`, "voucher-confirm-hold").Scan(&status); err != nil {
		t.Fatalf("read voucher after confirm: %v", err)
	}
	if status != "reserved" {
		t.Fatalf("expected voucher to remain reserved after confirm, got %q", status)
	}
	if _, ok := server.ExchangeTokens["token-confirm-hold"]; !ok {
		t.Fatalf("expected token to remain stored until completion")
	}
}

func TestExchangeCompleteMarksReservedVouchersSpent(t *testing.T) {
	server := newTestCoreServer(t)
	httpServer := httptest.NewServer(NewRouter(server))
	defer httpServer.Close()

	nowTs := float64(time.Now().Unix())
	_, _ = server.DB.Exec(`INSERT INTO hps_vouchers
		(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"voucher-complete", server.Address, "alice", 9, "test", nowTs, `{}`, "issuer-sig", "owner-sig", "valid", nil, 0, nowTs)

	ok, _, errMsg := server.ReserveVouchersForSession("alice", "exchange-session-complete", []string{"voucher-complete"})
	if !ok {
		t.Fatalf("reserve vouchers: %s", errMsg)
	}

	server.ExchangeTokens["token-complete"] = map[string]any{
		"payload": map[string]any{
			"token_id":      "token-complete",
			"owner":         "alice",
			"target_server": "target-server.test",
			"voucher_ids":   []string{"voucher-complete"},
			"total_value":   9,
		},
		"signature":  "token-signature",
		"session_id": "exchange-session-complete",
		"expires_at": nowTs + 3600,
	}

	okRemote, response, errMsg := server.MakeRemoteRequestJSON(httpServer.URL, "/exchange/complete", http.MethodPost, map[string]any{
		"token_id":    "token-complete",
		"transfer_id": "tx-complete",
	})
	if !okRemote {
		t.Fatalf("remote complete failed: %s", errMsg)
	}
	if success, _ := response["success"].(bool); !success {
		t.Fatalf("expected complete success, got %#v", response)
	}

	var status string
	if err := server.DB.QueryRow(`SELECT status FROM hps_vouchers WHERE voucher_id = ?`, "voucher-complete").Scan(&status); err != nil {
		t.Fatalf("read voucher after complete: %v", err)
	}
	if status != "spent" {
		t.Fatalf("expected voucher to be spent after completion, got %q", status)
	}
	if _, ok := server.ExchangeTokens["token-complete"]; ok {
		t.Fatalf("expected token to be removed after completion")
	}
}

func TestExchangeRollbackReleasesReservedVouchersWhenTokenStillPending(t *testing.T) {
	server := newTestCoreServer(t)
	httpServer := httptest.NewServer(NewRouter(server))
	defer httpServer.Close()

	nowTs := float64(time.Now().Unix())
	_, _ = server.DB.Exec(`INSERT INTO hps_vouchers
		(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"voucher-rollback-release", server.Address, "alice", 9, "test", nowTs, `{}`, "issuer-sig", "owner-sig", "valid", nil, 0, nowTs)

	ok, _, errMsg := server.ReserveVouchersForSession("alice", "exchange-session-rollback-release", []string{"voucher-rollback-release"})
	if !ok {
		t.Fatalf("reserve vouchers: %s", errMsg)
	}

	server.ExchangeTokens["token-rollback-release"] = map[string]any{
		"payload": map[string]any{
			"token_id":      "token-rollback-release",
			"owner":         "alice",
			"target_server": "target-server.test",
			"voucher_ids":   []string{"voucher-rollback-release"},
			"total_value":   9,
		},
		"signature":  "token-signature",
		"session_id": "exchange-session-rollback-release",
		"expires_at": nowTs + 3600,
	}

	okRemote, response, errMsg := server.MakeRemoteRequestJSON(httpServer.URL, "/exchange/rollback", http.MethodPost, map[string]any{
		"token_id":    "token-rollback-release",
		"transfer_id": "tx-rollback-release",
		"owner":       "alice",
		"total_value": 9,
		"reason":      "exchange_failed",
	})
	if !okRemote {
		t.Fatalf("remote rollback failed: %s", errMsg)
	}
	if success, _ := response["success"].(bool); !success {
		t.Fatalf("expected rollback success, got %#v", response)
	}

	var status string
	if err := server.DB.QueryRow(`SELECT status FROM hps_vouchers WHERE voucher_id = ?`, "voucher-rollback-release").Scan(&status); err != nil {
		t.Fatalf("read voucher after rollback: %v", err)
	}
	if status != "valid" {
		t.Fatalf("expected voucher to be released after rollback, got %q", status)
	}
	if _, ok := server.ExchangeTokens["token-rollback-release"]; ok {
		t.Fatalf("expected token to be removed after rollback")
	}
}
