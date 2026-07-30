package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"hpsserver/internal/core"
)

func withServerAndURLParam(req *http.Request, key, value string, server *core.Server) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, "server", server)
	return req.WithContext(ctx)
}

func TestHandleDNSIncludesReplicationMetadata(t *testing.T) {
	server := newTestCoreServer(t)
	domain := "alice.hps"
	contentHash := strings.Repeat("a", 64)
	ddnsHash := strings.Repeat("b", 64)
	issuerContractID := core.NewUUID()
	_, _ = server.DB.Exec(`INSERT INTO contracts
		(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		issuerContractID, "register_dns", nil, domain, "alice", "sig-contract", 100.0, 1, "")

	_, _ = server.DB.Exec(`INSERT INTO dns_records
		(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, contentHash, "alice", "alice", 100.0, "sig-ddns", 1, 100.0, ddnsHash,
		"http://issuer.example", "issuer-public-key", issuerContractID, 123.0)

	req := httptest.NewRequest(http.MethodGet, "/dns/"+domain, nil)
	req = withServerAndURLParam(req, "domain", domain, server)
	rec := httptest.NewRecorder()
	HandleDNS(server).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload["ddns_hash"] != ddnsHash {
		t.Fatalf("expected ddns_hash %q, got %#v", ddnsHash, payload["ddns_hash"])
	}
	if payload["issuer_server"] != "http://issuer.example" {
		t.Fatalf("expected issuer_server, got %#v", payload["issuer_server"])
	}
	if payload["issuer_public_key"] != "issuer-public-key" {
		t.Fatalf("expected issuer_public_key, got %#v", payload["issuer_public_key"])
	}
	if payload["issuer_contract_id"] != issuerContractID {
		t.Fatalf("expected issuer_contract_id %q, got %#v", issuerContractID, payload["issuer_contract_id"])
	}
}

func TestHandleDDNSReturnsDecryptedContent(t *testing.T) {
	server := newTestCoreServer(t)
	domain := "alice.hps"
	ddnsHash := strings.Repeat("c", 64)
	ddnsPath := server.DdnsPath(ddnsHash)
	ddnsContent := []byte("# HSYST P2P SERVICE\nCONTENT_HASH=hash123\n")

	if err := server.WriteEncryptedFile(ddnsPath, ddnsContent, 0o644); err != nil {
		t.Fatalf("write ddns: %v", err)
	}
	issuerContractID := core.NewUUID()
	_, _ = server.DB.Exec(`INSERT INTO contracts
		(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		issuerContractID, "register_dns", nil, domain, "alice", "sig-contract", 100.0, 1, "")
	_, _ = server.DB.Exec(`INSERT INTO dns_records
		(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, "hash123", "alice", "alice", 100.0, "sig-ddns", 1, 100.0, ddnsHash,
		"http://issuer.example", "issuer-public-key", issuerContractID, 123.0)

	req := httptest.NewRequest(http.MethodGet, "/ddns/"+domain, nil)
	req = withServerAndURLParam(req, "domain", domain, server)
	rec := httptest.NewRecorder()
	HandleDDNS(server).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.Bytes(); string(got) != string(ddnsContent) {
		t.Fatalf("expected decrypted DDNS content %q, got %q", string(ddnsContent), string(got))
	}
}
