package socket

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hpsserver/internal/socketio"
)

func findEvent(conn *testConn, eventName string) map[string]any {
	for _, emitted := range conn.emitted {
		if emitted.event != eventName {
			continue
		}
		if payload, ok := emitted.payload.(map[string]any); ok {
			return payload
		}
	}
	return nil
}

func TestAuthenticatedClientInMinerStatsIsEligibleMiner(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	s.clients["sid-miner"] = &ClientState{
		Authenticated: true,
		Username:      "thais2",
		NodeType:      "client",
	}

	_, _ = coreServer.DB.Exec(`INSERT INTO miner_stats
		(username, pending_signatures, pending_fines, last_updated, banned_until)
		VALUES (?, 0, 0, ?, NULL)`, "thais2", float64(time.Now().Unix()))

	miners := s.listEligibleMiners("192.168.15.16:8080", "thais", false)
	if len(miners) != 1 || miners[0] != "thais2" {
		t.Fatalf("expected thais2 to be treated as eligible miner even with node_type=client, got %#v", miners)
	}
}

func TestPendingTransfersRefreshMissesMonetaryPendingSignature(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	minerConn := &testConn{id: "sid-miner"}
	s.clients[minerConn.id] = &ClientState{
		Authenticated: true,
		Username:      "thais2",
		NodeType:      "client",
	}
	s.conns[minerConn.id] = minerConn

	_, _ = coreServer.DB.Exec(`INSERT INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, assigned_miner, deadline, miner_deadline, fee_amount, selector_fee_amount, fee_source, inter_server_payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tx-pending", "exchange_in", "192.168.15.16:8080", "thais", 11,
		float64(time.Now().Unix()), "pending_signature", "", `["voucher-new"]`, "thais2",
		float64(time.Now().Add(1*time.Minute).Unix()), float64(time.Now().Add(1*time.Minute).Unix()), 1, 0, "issuer", `{}`)

	s.handleGetPendingTransfers(minerConn, map[string]any{})
	pendingTransfersPayload := findEvent(minerConn, "pending_transfers")
	if pendingTransfersPayload == nil {
		t.Fatalf("expected pending_transfers payload")
	}
	if transfers, ok := pendingTransfersPayload["transfers"].([]map[string]any); ok && len(transfers) != 0 {
		t.Fatalf("expected get_pending_transfers to miss monetary transfer, got %#v", transfers)
	}
	if transfers, ok := pendingTransfersPayload["transfers"].([]any); ok && len(transfers) != 0 {
		t.Fatalf("expected get_pending_transfers to miss monetary transfer, got %#v", transfers)
	}

	minerConn.emitted = nil
	s.handleGetMinerPendingTransfers(minerConn, map[string]any{})
	minerPendingPayload := findEvent(minerConn, "miner_pending_transfers")
	if minerPendingPayload == nil {
		t.Fatalf("expected miner_pending_transfers payload")
	}
	success, _ := minerPendingPayload["success"].(bool)
	if !success {
		t.Fatalf("expected miner_pending_transfers success, got %#v", minerPendingPayload)
	}
	transfers, ok := minerPendingPayload["transfers"].([]map[string]any)
	if ok {
		if len(transfers) != 1 {
			t.Fatalf("expected one miner pending transfer, got %#v", transfers)
		}
		return
	}
	rawTransfers, ok := minerPendingPayload["transfers"].([]any)
	if !ok || len(rawTransfers) != 1 {
		t.Fatalf("expected one miner pending transfer, got %#v", minerPendingPayload["transfers"])
	}
}

func TestExchangeInFallbackWithNullContractIDStillNotifiesMiner(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	minerConn := &testConn{id: "sid-miner"}
	s.clients[minerConn.id] = &ClientState{
		Authenticated: true,
		Username:      "thais2",
		NodeType:      "client",
	}
	s.conns[minerConn.id] = minerConn

	receiverConn := &testConn{id: "sid-receiver"}
	s.clients[receiverConn.id] = &ClientState{
		Authenticated: true,
		Username:      "thais",
		NodeType:      "client",
	}
	s.conns[receiverConn.id] = receiverConn

	_, _ = coreServer.DB.Exec(`INSERT INTO miner_stats
		(username, pending_signatures, pending_fines, last_updated, banned_until)
		VALUES (?, 0, 0, ?, NULL)`, "thais2", float64(time.Now().Unix()))

	issuerHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer issuerHTTP.Close()

	_, _ = coreServer.DB.Exec(`INSERT INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, fee_amount, selector_fee_amount, fee_source, inter_server_payload, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tx-exchange-null-contract", "exchange_in", issuerHTTP.URL, "thais", 11, float64(time.Now().Unix()),
		"awaiting_selector", nil, `["voucher-new"]`, 1, 0, "issuer",
		`{"exchange_offer_voucher_id":"voucher-new","issuer":"`+issuerHTTP.URL+`","origin_username":"thais"}`,
		float64(time.Now().Add(1*time.Minute).Unix()))

	s.requestSelectorForTransfer("tx-exchange-null-contract", issuerHTTP.URL, "thais")

	transfer, ok := s.getMonetaryTransfer("tx-exchange-null-contract")
	if !ok {
		t.Fatalf("expected transfer to remain readable after fallback assignment")
	}
	if asString(transfer["assigned_miner"]) != "thais2" {
		t.Fatalf("expected thais2 as assigned miner, got %#v", transfer["assigned_miner"])
	}
	if asString(transfer["status"]) != "pending_signature" {
		t.Fatalf("expected pending_signature status, got %#v", transfer["status"])
	}

	minerPayload := findEvent(minerConn, "miner_signature_request")
	if minerPayload == nil {
		t.Fatalf("expected miner_signature_request for assigned miner")
	}
	if asString(minerPayload["transfer_id"]) != "tx-exchange-null-contract" {
		t.Fatalf("unexpected transfer in miner payload: %#v", minerPayload)
	}

	transferDeadline := asFloat(transfer["miner_deadline"])
	createdAt := asFloat(transfer["created_at"])
	if transferDeadline-createdAt < 25 {
		t.Fatalf("expected extended miner deadline for exchange transfer, got created_at=%v miner_deadline=%v", createdAt, transferDeadline)
	}
}

func TestQueuedSpendHpsPendingActionImmediatelyRequestsMiner(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	userConn := &testConn{id: "sid-user"}
	s.clients[userConn.id] = &ClientState{
		Authenticated: true,
		Username:      "thais",
		NodeType:      "client",
	}
	s.conns[userConn.id] = userConn

	minerConn := &testConn{id: "sid-miner"}
	s.clients[minerConn.id] = &ClientState{
		Authenticated: true,
		Username:      "thais2",
		NodeType:      "client",
	}
	s.conns[minerConn.id] = minerConn

	_, _ = coreServer.DB.Exec(`INSERT INTO miner_stats
		(username, pending_signatures, pending_fines, last_updated, banned_until)
		VALUES (?, 0, 0, ?, NULL)`, "thais2", float64(time.Now().Unix()))

	nowTs := float64(time.Now().Unix())
	_, _ = coreServer.DB.Exec(`INSERT INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, fee_amount, selector_fee_amount, fee_source, inter_server_payload, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tx-spend-upload", "spend_hps:upload", "thais", "system", 7, nowTs,
		"awaiting_selector", "contract-1", `["voucher-a"]`, 1, 0, "custody", `{}`,
		nowTs+60.0)

	s.queuePendingMonetaryAction(
		userConn,
		"tx-spend-upload",
		"publish_content",
		"thais",
		"cid-user",
		map[string]any{"payment": map[string]any{"transfer_id": "tx-spend-upload"}},
		"publish_result",
	)

	transfer, ok := s.getMonetaryTransfer("tx-spend-upload")
	if !ok {
		t.Fatalf("expected queued transfer to remain readable")
	}
	if asString(transfer["assigned_miner"]) != "thais2" {
		t.Fatalf("expected thais2 as assigned miner, got %#v", transfer["assigned_miner"])
	}
	if asString(transfer["status"]) != "pending_signature" {
		t.Fatalf("expected pending_signature status, got %#v", transfer["status"])
	}

	minerPayload := findEvent(minerConn, "miner_signature_request")
	if minerPayload == nil {
		t.Fatalf("expected miner_signature_request for queued spend_hps transfer")
	}
	if asString(minerPayload["transfer_id"]) != "tx-spend-upload" {
		t.Fatalf("unexpected transfer in miner payload: %#v", minerPayload)
	}

	ackPayload := findEvent(userConn, "publish_result")
	if ackPayload == nil {
		t.Fatalf("expected publish_result pending ack")
	}
	if pending, _ := ackPayload["pending"].(bool); !pending {
		t.Fatalf("expected pending ack, got %#v", ackPayload)
	}
}

func TestSpendHpsFallbackFailureReleasesReservedVoucherAndNotifiesUser(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	userConn := &testConn{id: "sid-user"}
	s.clients[userConn.id] = &ClientState{
		Authenticated: true,
		Username:      "thais",
		NodeType:      "client",
	}
	s.conns[userConn.id] = userConn

	nowTs := float64(time.Now().Unix())
	_, _ = coreServer.DB.Exec(`INSERT INTO hps_vouchers
		(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"voucher-reserved", coreServer.Address, "thais", 7, "test", nowTs, `{}`, "issuer-sig", "owner-sig", "reserved", "pow-session-dns", 0, nowTs)
	_, _ = coreServer.DB.Exec(`INSERT INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, fee_amount, selector_fee_amount, fee_source, inter_server_payload, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tx-spend-dns", "spend_hps:dns", "thais", "system", 7, nowTs,
		"awaiting_selector", "contract-dns", `["voucher-reserved"]`, 1, 0, "custody", `{}`,
		nowTs+60.0)
	s.queuePendingMonetaryAction(
		userConn,
		"tx-spend-dns",
		"register_dns",
		"thais",
		"cid-user",
		map[string]any{
			"payment": map[string]any{
				"transfer_id": "tx-spend-dns",
				"session_id":  "pow-session-dns",
			},
		},
		"dns_result",
	)
	userConn.emitted = nil

	s.assignMinerFallback("tx-spend-dns", "thais", "system", "no_miners")

	var status string
	if err := coreServer.DB.QueryRow(`SELECT status FROM hps_vouchers WHERE voucher_id = ?`, "voucher-reserved").Scan(&status); err != nil {
		t.Fatalf("read voucher status: %v", err)
	}
	if status != "valid" {
		t.Fatalf("expected voucher to be released after fallback failure, got %q", status)
	}

	dnsPayload := findEvent(userConn, "dns_result")
	if dnsPayload == nil {
		t.Fatalf("expected dns_result failure notification")
	}
	if success, _ := dnsPayload["success"].(bool); success {
		t.Fatalf("expected dns_result failure, got %#v", dnsPayload)
	}
}

func TestHandleSignTransferQueuesSubmissionBeforeSettlement(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:               socketio.NewServer(nil),
		server:           coreServer,
		clients:          map[string]*ClientState{},
		conns:            map[string]socketio.Conn{},
		signatureWorkers: map[string]bool{},
	}

	minerConn := &testConn{id: "sid-miner"}
	s.clients[minerConn.id] = &ClientState{
		Authenticated:    true,
		Username:         "thais2",
		NodeType:         "client",
		ClientIdentifier: "cid-miner",
	}
	s.conns[minerConn.id] = minerConn

	_, _ = coreServer.DB.Exec(`INSERT INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, assigned_miner, deadline, miner_deadline, fee_amount, selector_fee_amount, fee_source, inter_server_payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"tx-sign-queue", "exchange_in", "192.168.15.16:8080", "thais", 11,
		float64(time.Now().Unix()), "pending_signature", "", `["voucher-new"]`, "thais2",
		float64(time.Now().Add(1*time.Minute).Unix()), float64(time.Now().Add(1*time.Minute).Unix()), 1, 0, "issuer", `{}`)

	s.handleSignTransfer(minerConn, map[string]any{
		"transfer_id":      "tx-sign-queue",
		"contract_content": "ZmFrZQ==",
		"report_content":   "ZmFrZQ==",
	})

	ackPayload := findEvent(minerConn, "miner_signature_ack")
	if ackPayload == nil {
		t.Fatalf("expected miner_signature_ack payload")
	}
	if success, _ := ackPayload["success"].(bool); !success {
		t.Fatalf("expected success ack, got %#v", ackPayload)
	}
	if pending, _ := ackPayload["pending"].(bool); !pending {
		t.Fatalf("expected pending ack, got %#v", ackPayload)
	}

	transfer, ok := s.getMonetaryTransfer("tx-sign-queue")
	if !ok {
		t.Fatalf("expected transfer to remain readable")
	}
	if asString(transfer["status"]) != "signature_submitted" {
		t.Fatalf("expected signature_submitted status, got %#v", transfer["status"])
	}

	action := coreServer.GetPendingMonetaryAction("tx-sign-queue")
	if action == nil {
		t.Fatalf("expected pending monetary action for queued signature")
	}
	if asString(action["action_name"]) != "settle_miner_signature" {
		t.Fatalf("unexpected action name: %#v", action)
	}
}
