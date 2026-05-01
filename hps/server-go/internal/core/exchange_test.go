package core

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	baseDir := t.TempDir()
	server, err := NewServer(Config{
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

func TestReleaseExpiredExchangeTokensReleasesReservedVouchers(t *testing.T) {
	server := newTestServer(t)

	nowTs := float64(time.Now().Unix())
	_, _ = server.DB.Exec(`INSERT INTO hps_vouchers
		(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"voucher-expired-token", server.Address, "alice", 12, "test", nowTs, `{}`, "issuer-sig", "owner-sig", "valid", nil, 0, nowTs)

	ok, _, errMsg := server.ReserveVouchersForSession("alice", "exchange-session-1", []string{"voucher-expired-token"})
	if !ok {
		t.Fatalf("reserve vouchers: %s", errMsg)
	}

	server.ExchangeTokens["token-expired"] = map[string]any{
		"session_id": "exchange-session-1",
		"expires_at": nowTs - 1,
	}

	released := server.ReleaseExpiredExchangeTokens(nowTs)
	if released != 1 {
		t.Fatalf("expected 1 released token, got %d", released)
	}
	if _, ok := server.ExchangeTokens["token-expired"]; ok {
		t.Fatalf("expected expired token to be removed")
	}

	var status string
	var sessionID sql.NullString
	if err := server.DB.QueryRow(`SELECT status, session_id FROM hps_vouchers WHERE voucher_id = ?`, "voucher-expired-token").Scan(&status, &sessionID); err != nil {
		t.Fatalf("read voucher after release: %v", err)
	}
	if status != "valid" {
		t.Fatalf("expected released voucher status valid, got %q", status)
	}
	if sessionID.Valid {
		t.Fatalf("expected released voucher session_id to be NULL, got %q", sessionID.String)
	}
}

func TestDerivedVoucherReusesLineageDkvhpsAndSupersedesParent(t *testing.T) {
	server := newTestServer(t)
	ownerKey := base64Encode(server.PublicKeyPEM)

	rootOffer := server.CreateVoucherOffer("alice", ownerKey, 30, "pow_root", nil, nil, "")
	rootPayload := castMap(rootOffer["payload"])
	rootID := asString(rootOffer["voucher_id"])
	rootOwnerSig := server.SignPayload(rootPayload)
	if _, errMsg := server.FinalizeVoucherDetailed(rootID, rootOwnerSig, ""); errMsg != "" {
		t.Fatalf("finalize root voucher: %s", errMsg)
	}

	derivedOffer := server.CreateVoucherOffer("alice", ownerKey, 20, "derived", nil, map[string]any{
		"source_voucher_id": rootID,
	}, "")
	derivedPayload := castMap(derivedOffer["payload"])
	derivedID := asString(derivedOffer["voucher_id"])
	derivedOwnerSig := server.SignPayload(derivedPayload)
	if _, errMsg := server.FinalizeVoucherDetailed(derivedID, derivedOwnerSig, ""); errMsg != "" {
		t.Fatalf("finalize derived voucher: %s", errMsg)
	}

	rootInfo := server.GetVoucherAuditInfo(rootID)
	derivedInfo := server.GetVoucherAuditInfo(derivedID)
	if rootInfo == nil || derivedInfo == nil {
		t.Fatalf("expected audit info for root and derived vouchers")
	}
	rootDkvhps := mapValue(mapValue(rootInfo["payload"])["dkvhps"])
	derivedDkvhps := mapValue(mapValue(derivedInfo["payload"])["dkvhps"])
	if asString(rootDkvhps["lineage_hash"]) == "" || asString(derivedDkvhps["lineage_hash"]) == "" {
		t.Fatalf("expected lineage dkvhps hashes in payload")
	}
	if asString(rootDkvhps["lineage_hash"]) != asString(derivedDkvhps["lineage_hash"]) {
		t.Fatalf("expected derived voucher to reuse lineage dkvhps")
	}
	if asString(rootDkvhps["voucher_hash"]) == asString(derivedDkvhps["voucher_hash"]) {
		t.Fatalf("expected derived voucher to rotate individual dkvhps")
	}
	derivedPayloadSaved := mapValue(derivedInfo["payload"])
	if asString(derivedPayloadSaved["lineage_parent_voucher_id"]) != rootID {
		t.Fatalf("expected parent voucher id %q, got %q", rootID, asString(derivedPayloadSaved["lineage_parent_voucher_id"]))
	}
	if !server.IsVoucherSuperseded(rootID, mapValue(rootInfo["payload"])) {
		t.Fatalf("expected root voucher to be superseded after derivation")
	}
}

func TestDerivedVoucherInheritsExchangeEvidenceFromParentLineage(t *testing.T) {
	server := newTestServer(t)
	ownerKey := base64Encode(server.PublicKeyPEM)

	rootOffer := server.CreateVoucherOffer("alice", ownerKey, 30, "exchange_root", nil, map[string]any{
		"type":                            "exchange",
		"lineage_origin":                  "exchange_in",
		"exchange_contract_id":            "exchange-contract-1",
		"dkvhps_disclosure_contract_id":   "disclosure-contract-1",
		"dkvhps_disclosure_contract_hash": "abc123",
		"issuer_voucher_ids":              []string{"issuer-voucher-1"},
	}, "")
	rootPayload := castMap(rootOffer["payload"])
	rootID := asString(rootOffer["voucher_id"])
	rootOwnerSig := server.SignPayload(rootPayload)
	if _, errMsg := server.FinalizeVoucherDetailed(rootID, rootOwnerSig, ""); errMsg != "" {
		t.Fatalf("finalize exchange root voucher: %s", errMsg)
	}

	derivedOffer := server.CreateVoucherOffer("alice", ownerKey, 20, "exchange_change", nil, map[string]any{
		"source_voucher_id": rootID,
	}, "")
	derivedPayload := castMap(derivedOffer["payload"])
	derivedConditions := mapValue(derivedPayload["conditions"])
	if got := asString(derivedConditions["exchange_contract_id"]); got != "exchange-contract-1" {
		t.Fatalf("expected inherited exchange_contract_id, got %q", got)
	}
	if got := asString(derivedConditions["dkvhps_disclosure_contract_id"]); got != "disclosure-contract-1" {
		t.Fatalf("expected inherited dkvhps disclosure contract id, got %q", got)
	}
	if got := asString(derivedConditions["dkvhps_disclosure_contract_hash"]); got != "abc123" {
		t.Fatalf("expected inherited dkvhps disclosure hash, got %q", got)
	}
	if got := strSliceValue(derivedConditions["issuer_voucher_ids"]); len(got) != 1 || got[0] != "issuer-voucher-1" {
		t.Fatalf("expected inherited issuer voucher ids, got %#v", got)
	}
}

func TestStoredVoucherFileUsesDkvhpsEnvelopeAndRoundTrips(t *testing.T) {
	server := newTestServer(t)
	ownerKey := base64Encode(server.PublicKeyPEM)

	offer := server.CreateVoucherOffer("alice", ownerKey, 15, "pow_root", nil, nil, "")
	payload := castMap(offer["payload"])
	voucherID := asString(offer["voucher_id"])
	ownerSig := server.SignPayload(payload)
	if _, errMsg := server.FinalizeVoucherDetailed(voucherID, ownerSig, ""); errMsg != "" {
		t.Fatalf("finalize voucher: %s", errMsg)
	}

	voucherPath := filepath.Join(server.FilesDir, "vouchers", voucherID+".hps")
	rawStored, err := server.ReadEncryptedFile(voucherPath)
	if err != nil {
		t.Fatalf("read encrypted voucher file: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(rawStored, &envelope); err != nil {
		t.Fatalf("expected dkvhps envelope json, got err=%v", err)
	}
	if asString(envelope["scheme"]) != "hps-voucher-dkvhps" {
		t.Fatalf("expected dkvhps voucher file scheme, got %#v", envelope["scheme"])
	}

	decoded, err := server.ReadVoucherFile(voucherPath)
	if err != nil {
		t.Fatalf("read voucher file with dkvhps decode: %v", err)
	}
	if !strings.HasPrefix(string(decoded), "# HSYST P2P SERVICE") {
		t.Fatalf("expected decoded voucher content, got %q", string(decoded))
	}
}
