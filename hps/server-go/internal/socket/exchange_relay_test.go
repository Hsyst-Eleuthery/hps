package socket

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"hpsserver/internal/core"
	"hpsserver/internal/httpapi"
	"hpsserver/internal/socketio"
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

type testConn struct {
	id      string
	emitted []emittedEvent
}

type emittedEvent struct {
	event   string
	payload any
}

func waitForCondition(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fn()
}

func (c *testConn) ID() string {
	return c.id
}

func (c *testConn) Emit(event string, payload any) {
	c.emitted = append(c.emitted, emittedEvent{event: event, payload: payload})
}

func TestRelayExchangeEventToIssuerPostsOriginUserEvent(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{server: coreServer}

	var gotUsername string
	var gotEvent string
	var gotTransferID string

	issuerHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		gotUsername = asString(body["username"])
		gotEvent = asString(body["event"])
		gotTransferID = asString(castMap(body["payload"])["transfer_id"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer issuerHTTP.Close()

	s.relayExchangeEventToIssuer(map[string]any{
		"transfer_type": "exchange_in",
		"inter_server_payload": map[string]any{
			"issuer":          issuerHTTP.URL,
			"origin_username": "alice",
		},
	}, "exchange_pending", map[string]any{
		"transfer_id": "tx-456",
		"status":      "pending_signature",
	})

	if gotUsername != "alice" {
		t.Fatalf("username mismatch: got %q", gotUsername)
	}
	if gotEvent != "exchange_pending" {
		t.Fatalf("event mismatch: got %q", gotEvent)
	}
	if gotTransferID != "tx-456" {
		t.Fatalf("transfer id mismatch: got %q", gotTransferID)
	}
}

func TestRequestHpsWalletFlagsLocalIssuerVouchers(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	conn := &testConn{id: "sid-wallet"}
	s.clients[conn.id] = &ClientState{
		Authenticated: true,
		Username:      "alice",
		NodeType:      "client",
	}
	s.conns[conn.id] = conn

	nowTs := float64(time.Now().Unix())
	_, _ = coreServer.DB.Exec(`INSERT INTO hps_vouchers
		(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"voucher-local", coreServer.Address, "alice", 10, "local", nowTs, `{}`, "issuer-sig", "owner-sig", "valid", nil, 0, nowTs)
	_, _ = coreServer.DB.Exec(`INSERT INTO hps_vouchers
		(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"voucher-remote", "issuer.remote.test", "alice", 8, "remote", nowTs-1, `{}`, "issuer-sig", "owner-sig", "valid", nil, 0, nowTs-1)
	offer := coreServer.CreateVoucherOffer("alice", "owner-key", 4, "change", nil, nil, "")

	s.handleRequestHpsWallet(conn, map[string]any{})

	payload := findEvent(conn, "hps_wallet_sync")
	if payload == nil {
		t.Fatalf("expected hps_wallet_sync payload")
	}
	rawVouchers, ok := payload["vouchers"].([]map[string]any)
	if !ok {
		rawAny, okAny := payload["vouchers"].([]any)
		if !okAny {
			t.Fatalf("unexpected vouchers payload: %#v", payload["vouchers"])
		}
		rawVouchers = make([]map[string]any, 0, len(rawAny))
		for _, item := range rawAny {
			voucher, okMap := item.(map[string]any)
			if okMap {
				rawVouchers = append(rawVouchers, voucher)
			}
		}
	}
	if len(rawVouchers) != 2 {
		t.Fatalf("expected two vouchers, got %#v", rawVouchers)
	}

	flags := map[string]bool{}
	for _, voucher := range rawVouchers {
		flags[asString(voucher["voucher_id"])] = asBool(voucher["is_local_issuer"])
	}
	if !flags["voucher-local"] {
		t.Fatalf("expected local voucher to be flagged as local: %#v", rawVouchers)
	}
	if flags["voucher-remote"] {
		t.Fatalf("expected remote voucher to be flagged as non-local: %#v", rawVouchers)
	}

	rawOffers, okOffers := payload["pending_offers"].([]map[string]any)
	if !okOffers {
		rawAny, okAny := payload["pending_offers"].([]any)
		if !okAny {
			t.Fatalf("unexpected pending_offers payload: %#v", payload["pending_offers"])
		}
		rawOffers = make([]map[string]any, 0, len(rawAny))
		for _, item := range rawAny {
			offerMap, okMap := item.(map[string]any)
			if okMap {
				rawOffers = append(rawOffers, offerMap)
			}
		}
	}
	if len(rawOffers) != 1 || asString(rawOffers[0]["voucher_id"]) != asString(offer["voucher_id"]) {
		t.Fatalf("expected pending offer in wallet sync, got %#v", rawOffers)
	}
}

func TestEmitAssignedMinerRelaysPendingEventBackToIssuer(t *testing.T) {
	issuerCore := newTestCoreServer(t)
	targetCore := newTestCoreServer(t)
	targetCore.Address = "target-server.test"

	_, _ = issuerCore.DB.Exec(`INSERT INTO known_servers (address, added_date, last_connected, is_active) VALUES (?, 0, 0, 1)`, targetCore.Address)
	_, _ = issuerCore.DB.Exec(`INSERT INTO server_nodes (server_id, address, public_key, last_seen, is_active, reputation, sync_priority) VALUES (?, ?, ?, 0, 1, 100, 1)`,
		targetCore.ServerID, targetCore.Address, base64.StdEncoding.EncodeToString(targetCore.PublicKeyPEM))

	var relayed []emittedEvent
	issuerCore.UserEventEmitter = func(username, event string, payload map[string]any) {
		relayed = append(relayed, emittedEvent{
			event: event,
			payload: map[string]any{
				"username":       username,
				"transfer_id":    asString(payload["transfer_id"]),
				"status":         asString(payload["status"]),
				"assigned_miner": asString(payload["assigned_miner"]),
			},
		})
	}

	issuerHTTP := httptest.NewServer(httpapi.NewRouter(issuerCore))
	defer issuerHTTP.Close()
	issuerCore.Address = issuerHTTP.URL

	minerConn := &testConn{id: "miner-1"}
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  targetCore,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}
	s.clients[minerConn.id] = &ClientState{Authenticated: true, Username: "miner1", NodeType: "miner"}
	s.conns[minerConn.id] = minerConn
	interPayload := map[string]any{
		"issuer":                    issuerCore.Address,
		"origin_username":           "alice",
		"exchange_offer_voucher_id": "voucher-new",
	}
	_, _ = targetCore.DB.Exec(`INSERT INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, assigned_miner, deadline, miner_deadline, fee_amount, selector_fee_amount, fee_source, inter_server_payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tx-1", "exchange_in", issuerCore.Address, "alice", 11, float64(time.Now().Unix()), "pending_signature", "", `["voucher-new"]`, "miner1",
		float64(time.Now().Add(1*time.Minute).Unix()), float64(time.Now().Add(1*time.Minute).Unix()), 1, 0, "issuer", toJSONString(interPayload))

	s.emitAssignedMiner("tx-1", "miner1")

	if len(relayed) == 0 {
		t.Fatalf("expected relay events to issuer")
	}

	foundPending := false
	for _, evt := range relayed {
		payload, _ := evt.payload.(map[string]any)
		if evt.event == "exchange_pending" && asString(payload["username"]) == "alice" {
			foundPending = true
			if asString(payload["status"]) != "pending_signature" {
				t.Fatalf("expected pending_signature, got %q", asString(payload["status"]))
			}
			if asString(payload["assigned_miner"]) != "miner1" {
				t.Fatalf("expected miner1, got %q", asString(payload["assigned_miner"]))
			}
		}
	}
	if !foundPending {
		t.Fatalf("expected relayed exchange_pending event for issuer user")
	}
}

func TestConfirmExchangePersistsCompleteInterServerPayload(t *testing.T) {
	issuerCore := newTestCoreServer(t)
	targetCore := newTestCoreServer(t)

	reservedID := issuerCore.SaveServerContract("hps_exchange_reserved", []core.ContractDetail{
		{Key: "ISSUER", Value: "issuer-user"},
		{Key: "TOKEN_ID", Value: "token-1"},
	}, "")
	ownerKeyID := issuerCore.SaveServerContract("hps_exchange_owner_key", []core.ContractDetail{
		{Key: "ISSUER", Value: "issuer-user"},
		{Key: "OWNER", Value: "alice"},
	}, "")

	issuerHTTP := httptest.NewServer(httpapi.NewRouter(issuerCore))
	defer issuerHTTP.Close()
	issuerCore.Address = issuerHTTP.URL

	tokenPayload := map[string]any{
		"token_id":          "token-1",
		"issuer":            issuerCore.Address,
		"issuer_public_key": base64.StdEncoding.EncodeToString(issuerCore.PublicKeyPEM),
		"target_server":     "target-server.test",
		"voucher_ids":       []string{"voucher-a", "voucher-b"},
		"owner":             "alice",
		"total_value":       12,
		"session_id":        "exchange-token-1",
		"issued_at":         float64(time.Now().Unix()),
		"expires_at":        float64(time.Now().Add(5 * time.Minute).Unix()),
	}
	tokenSignature := issuerCore.SignPayload(tokenPayload)
	issuerCore.ExchangeTokens["token-1"] = map[string]any{
		"payload":     tokenPayload,
		"signature":   tokenSignature,
		"session_id":  "exchange-token-1",
		"voucher_ids": []string{"voucher-a", "voucher-b"},
		"expires_at":  float64(time.Now().Add(5 * time.Minute).Unix()),
	}

	clientContract := []byte("# HSYST P2P SERVICE\n## CONTRACT:\n# ACTION: exchange_hps\n")
	clientContractID := targetCore.SaveContract("exchange_hps", "", "", "thais", "sig", clientContract)

	conn := &testConn{id: "client-1"}
	s := &Server{
		io:             socketio.NewServer(nil),
		server:         targetCore,
		clients:        map[string]*ClientState{},
		conns:          map[string]socketio.Conn{},
		exchangeQuotes: map[string]map[string]any{},
	}
	s.clients[conn.id] = &ClientState{
		Authenticated: true,
		Username:      "thais",
		PublicKey:     "client-public-key",
	}
	s.conns[conn.id] = conn
	s.exchangeQuotes["quote-1"] = map[string]any{
		"issuer":                       "issuer-user",
		"issuer_address":               issuerCore.Address,
		"issuer_public_key":            base64.StdEncoding.EncodeToString(issuerCore.PublicKeyPEM),
		"client_username":              "thais",
		"voucher_ids":                  []string{"voucher-a", "voucher-b"},
		"rate":                         1.25,
		"fee_amount":                   1,
		"receive_amount":               10,
		"exchange_token":               tokenPayload,
		"exchange_signature":           tokenSignature,
		"issuer_reserved_contract_id":  reservedID,
		"issuer_owner_key_contract_id": ownerKeyID,
		"client_contract_id":           clientContractID,
		"expires_at":                   float64(time.Now().Add(5 * time.Minute).Unix()),
	}

	s.handleConfirmExchange(conn, map[string]any{"quote_id": "quote-1"})

	var transferID string
	if err := targetCore.DB.QueryRow(`SELECT transfer_id FROM monetary_transfers WHERE transfer_type = ? ORDER BY created_at DESC LIMIT 1`, "exchange_in").Scan(&transferID); err != nil {
		t.Fatalf("expected exchange transfer: %v", err)
	}
	transfer, ok := s.getMonetaryTransfer(transferID)
	if !ok {
		t.Fatalf("expected persisted exchange transfer")
	}
	interPayload := castMap(transfer["inter_server_payload"])
	if asString(interPayload["issuer_address"]) != issuerCore.Address {
		t.Fatalf("issuer_address mismatch: %#v", interPayload["issuer_address"])
	}
	if asString(interPayload["issuer_public_key"]) == "" {
		t.Fatalf("expected issuer_public_key in inter_server_payload")
	}
	if asString(interPayload["issuer_reserved_contract_id"]) != reservedID {
		t.Fatalf("reserved contract id mismatch: %#v", interPayload["issuer_reserved_contract_id"])
	}
	if asString(interPayload["issuer_reserved_contract"]) == "" {
		t.Fatalf("expected reserved contract content in payload")
	}
	if asString(interPayload["issuer_owner_key_contract_id"]) != ownerKeyID {
		t.Fatalf("owner key contract id mismatch: %#v", interPayload["issuer_owner_key_contract_id"])
	}
	if asString(interPayload["issuer_owner_key_contract"]) == "" {
		t.Fatalf("expected owner key contract content in payload")
	}
	if asString(interPayload["issuer_out_contract_id"]) == "" {
		t.Fatalf("expected issuer_out_contract_id in payload")
	}
	if asString(interPayload["issuer_out_contract"]) == "" {
		t.Fatalf("expected issuer_out_contract content in payload")
	}
	if asString(interPayload["exchange_contract_id"]) != clientContractID {
		t.Fatalf("exchange_contract_id mismatch: %#v", interPayload["exchange_contract_id"])
	}
	if asString(interPayload["exchange_contract_content"]) == "" {
		t.Fatalf("expected exchange_contract_content in payload")
	}
	if asString(interPayload["exchange_contract_hash"]) == "" {
		t.Fatalf("expected exchange_contract_hash in payload")
	}
}

func TestExpirePendingExchangeOffersRollsBackOrigin(t *testing.T) {
	issuerCore := newTestCoreServer(t)
	targetCore := newTestCoreServer(t)

	var rollbackCalls int
	issuerHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/exchange/rollback" {
			rollbackCalls++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer issuerHTTP.Close()
	issuerCore.Address = issuerHTTP.URL

	s := &Server{
		io:      socketio.NewServer(nil),
		server:  targetCore,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	nowTs := float64(time.Now().Unix())
	offer := targetCore.CreateVoucherOfferWithStatus("thais", "client-public-key", 9, "exchange_from:"+issuerHTTP.URL, nil, nil, "", "pending")
	_, _ = targetCore.DB.Exec(`UPDATE hps_voucher_offers SET expires_at = ? WHERE offer_id = ?`, nowTs-5, asString(offer["offer_id"]))

	interPayload := map[string]any{
		"issuer":                    issuerHTTP.URL,
		"issuer_address":            issuerHTTP.URL,
		"issuer_token_id":           "token-expired",
		"issuer_owner":              "alice",
		"issuer_total_value":        12,
		"origin_username":           "alice",
		"exchange_offer_id":         asString(offer["offer_id"]),
		"exchange_offer_voucher_id": asString(offer["voucher_id"]),
		"exchange_fee_amount":       1,
	}
	_, _ = targetCore.DB.Exec(`INSERT INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, fee_amount, selector_fee_amount, fee_source, inter_server_payload, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tx-expired-offer", "exchange_in", issuerHTTP.URL, "thais", 9, nowTs, "completed", nil,
		`["`+asString(offer["voucher_id"])+`"]`, 1, 0, "issuer", toJSONString(interPayload), nowTs+60)

	s.expirePendingExchangeOffers()

	var offerStatus string
	if err := targetCore.DB.QueryRow(`SELECT status FROM hps_voucher_offers WHERE offer_id = ?`, asString(offer["offer_id"])).Scan(&offerStatus); err != nil {
		t.Fatalf("expected offer status: %v", err)
	}
	if offerStatus != "expired" {
		t.Fatalf("expected expired offer status, got %q", offerStatus)
	}

	transfer, ok := s.getMonetaryTransfer("tx-expired-offer")
	if !ok {
		t.Fatalf("expected transfer to remain readable")
	}
	if asString(transfer["status"]) != "expired" {
		t.Fatalf("expected expired transfer, got %#v", transfer["status"])
	}
	if !waitForCondition(2*time.Second, func() bool { return rollbackCalls == 1 }) {
		t.Fatalf("expected one rollback call, got %d", rollbackCalls)
	}
}

func TestExpireWithheldExchangeOffersRollsBackOrigin(t *testing.T) {
	targetCore := newTestCoreServer(t)

	var rollbackCalls int
	issuerHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/exchange/rollback" {
			rollbackCalls++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer issuerHTTP.Close()

	s := &Server{
		io:      socketio.NewServer(nil),
		server:  targetCore,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	nowTs := float64(time.Now().Unix())
	offer := targetCore.CreateVoucherOfferWithStatus("thais", "client-public-key", 9, "exchange_from:"+issuerHTTP.URL, nil, nil, "", "withheld")
	_, _ = targetCore.DB.Exec(`UPDATE hps_voucher_offers SET expires_at = ? WHERE offer_id = ?`, nowTs-5, asString(offer["offer_id"]))

	interPayload := map[string]any{
		"issuer":                    issuerHTTP.URL,
		"issuer_address":            issuerHTTP.URL,
		"issuer_token_id":           "token-withheld-expired",
		"issuer_owner":              "alice",
		"issuer_total_value":        12,
		"origin_username":           "alice",
		"exchange_offer_id":         asString(offer["offer_id"]),
		"exchange_offer_voucher_id": asString(offer["voucher_id"]),
		"exchange_fee_amount":       1,
	}
	_, _ = targetCore.DB.Exec(`INSERT INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, fee_amount, selector_fee_amount, fee_source, inter_server_payload, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tx-withheld-expired", "exchange_in", issuerHTTP.URL, "thais", 9, nowTs, "awaiting_selector", nil,
		`["`+asString(offer["voucher_id"])+`"]`, 1, 0, "issuer", toJSONString(interPayload), nowTs+60)

	s.expireWithheldExchangeOffers()

	var offerStatus string
	if err := targetCore.DB.QueryRow(`SELECT status FROM hps_voucher_offers WHERE offer_id = ?`, asString(offer["offer_id"])).Scan(&offerStatus); err != nil {
		t.Fatalf("expected offer status: %v", err)
	}
	if offerStatus != "expired" {
		t.Fatalf("expected expired offer status, got %q", offerStatus)
	}

	transfer, ok := s.getMonetaryTransfer("tx-withheld-expired")
	if !ok {
		t.Fatalf("expected transfer to remain readable")
	}
	if asString(transfer["status"]) != "expired" {
		t.Fatalf("expected expired transfer, got %#v", transfer["status"])
	}
	if !waitForCondition(2*time.Second, func() bool { return rollbackCalls == 1 }) {
		t.Fatalf("expected one rollback call, got %d", rollbackCalls)
	}
}

func TestConfirmExchangeRollsBackIssuerWhenLocalPersistenceFails(t *testing.T) {
	issuerCore := newTestCoreServer(t)
	targetCore := newTestCoreServer(t)

	var rollbackCalls int
	issuerHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/exchange/confirm":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"payload":{"contract_id":"issuer-contract-1"}}`))
		case "/exchange/rollback":
			rollbackCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true}`))
		case "/contract/issuer-contract-1":
			_, _ = w.Write([]byte("# HSYST P2P SERVICE\n## CONTRACT:\n# ACTION: hps_exchange_out\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer issuerHTTP.Close()
	issuerCore.Address = issuerHTTP.URL

	clientContract := []byte("# HSYST P2P SERVICE\n## CONTRACT:\n# ACTION: exchange_hps\n")
	clientContractID := targetCore.SaveContract("exchange_hps", "", "", "thais", "sig", clientContract)

	conn := &testConn{id: "client-persist-fail"}
	s := &Server{
		io:             socketio.NewServer(nil),
		server:         targetCore,
		clients:        map[string]*ClientState{},
		conns:          map[string]socketio.Conn{},
		exchangeQuotes: map[string]map[string]any{},
	}
	s.clients[conn.id] = &ClientState{
		Authenticated: true,
		Username:      "thais",
		PublicKey:     "client-public-key",
	}
	s.conns[conn.id] = conn
	s.exchangeQuotes["quote-persist-fail"] = map[string]any{
		"issuer":             "issuer-user",
		"issuer_address":     issuerHTTP.URL,
		"issuer_public_key":  base64.StdEncoding.EncodeToString(issuerCore.PublicKeyPEM),
		"owner":              "alice",
		"client_username":    "thais",
		"voucher_ids":        []string{"voucher-a", "voucher-b"},
		"total_value":        12,
		"rate":               1.25,
		"fee_amount":         1,
		"receive_amount":     10,
		"exchange_token":     map[string]any{"token_id": "token-persist-fail"},
		"exchange_signature": "token-signature",
		"client_contract_id": clientContractID,
		"expires_at":         float64(time.Now().Add(5 * time.Minute).Unix()),
	}

	_ = targetCore.DB.Close()

	s.handleConfirmExchange(conn, map[string]any{"quote_id": "quote-persist-fail"})

	if !waitForCondition(2*time.Second, func() bool { return rollbackCalls == 1 }) {
		t.Fatalf("expected one rollback call, got %d", rollbackCalls)
	}
	if len(conn.emitted) == 0 {
		t.Fatalf("expected client emission")
	}
	last := conn.emitted[len(conn.emitted)-1]
	if last.event != "exchange_complete" {
		t.Fatalf("expected exchange_complete, got %q", last.event)
	}
	payload, _ := last.payload.(map[string]any)
	if payload == nil || asBool(payload["success"]) {
		t.Fatalf("expected failed exchange payload, got %#v", last.payload)
	}
}
