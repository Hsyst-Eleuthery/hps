package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleSyncContentSkipsReplicatedRemoteContent(t *testing.T) {
	server := newTestCoreServer(t)

	localHash := strings.Repeat("a", 64)
	replicatedHash := strings.Repeat("b", 64)

	_, _ = server.DB.Exec(`INSERT INTO content
		(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, replication_count, last_accessed, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		localHash, "local", "", "application/octet-stream", 10, "alice", "sig-local", "pk-local", 100.0, "local.bin", 1, 1, 100.0,
		server.Address, "issuer-local", "", 100.0)
	_, _ = server.DB.Exec(`INSERT INTO content
		(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, replication_count, last_accessed, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		replicatedHash, "replicated", "", "application/octet-stream", 20, "bob", "sig-remote", "pk-remote", 101.0, "remote.bin", 1, 1, 101.0,
		"http://remote.example:8080", "issuer-remote", "", 101.0)

	req := httptest.NewRequest(http.MethodGet, "/sync/content", nil)
	req = req.WithContext(withServerAndURLParam(req, "", "", server).Context())
	rec := httptest.NewRecorder()
	HandleSyncContent(server).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload) != 1 {
		t.Fatalf("expected exactly one synced content item, got %#v", payload)
	}
	if payload[0]["content_hash"] != localHash {
		t.Fatalf("expected only local content hash %q, got %#v", localHash, payload[0]["content_hash"])
	}
}

func TestHandleSyncDNSSkipsReplicatedRemoteRecords(t *testing.T) {
	server := newTestCoreServer(t)

	_, _ = server.DB.Exec(`INSERT INTO dns_records
		(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"local.hps", strings.Repeat("c", 64), "alice", "alice", 100.0, "sig-local", 1, 100.0, "",
		server.BindAddress, "issuer-local", "", 100.0)
	_, _ = server.DB.Exec(`INSERT INTO dns_records
		(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"remote.hps", strings.Repeat("d", 64), "bob", "bob", 101.0, "sig-remote", 1, 101.0, "",
		"https://remote.example:8080", "issuer-remote", "", 101.0)

	req := httptest.NewRequest(http.MethodGet, "/sync/dns", nil)
	req = req.WithContext(withServerAndURLParam(req, "", "", server).Context())
	rec := httptest.NewRecorder()
	HandleSyncDNS(server).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload) != 1 {
		t.Fatalf("expected exactly one synced dns item, got %#v", payload)
	}
	if payload[0]["domain"] != "local.hps" {
		t.Fatalf("expected only local dns record, got %#v", payload[0]["domain"])
	}
}
