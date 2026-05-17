package core

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistEncryptedDatabaseSnapshotSurvivesRestart(t *testing.T) {
	baseDir := t.TempDir()
	cfg := Config{
		DBPath:           filepath.Join(baseDir, "test.db"),
		FilesDir:         filepath.Join(baseDir, "files"),
		Host:             "127.0.0.1",
		Port:             19080,
		MasterPassphrase: "test-passphrase",
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	contentHash := strings.Repeat("a", 64)
	domain := "restart-test.hps"
	contractID := "contract-restart-test"

	_, _ = server.DB.Exec(`INSERT INTO content
		(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, replication_count, last_accessed, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		contentHash, "local", "", "application/octet-stream", 10, "alice", "sig-local", "pk-local", 100.0, "local.bin", 1, 1, 100.0,
		server.Address, "issuer-local", "", 100.0)
	_, _ = server.DB.Exec(`INSERT INTO dns_records
		(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, contentHash, "alice", "alice", 100.0, "sig-dns", 1, 100.0, "", server.Address, "issuer-local", "", 100.0)
	_, _ = server.DB.Exec(`INSERT INTO contracts
		(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, issuer_server, contract_content)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		contractID, "register_dns", contentHash, domain, "alice", "sig-contract", 100.0, 1, server.Address, "Y29udHJhY3Q=")

	if err := server.persistEncryptedDatabaseSnapshot(); err != nil {
		t.Fatalf("persist snapshot: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close server: %v", err)
	}

	reopened, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("reopen server: %v", err)
	}

	var gotHash string
	if err := reopened.DB.QueryRow(`SELECT content_hash FROM dns_records WHERE domain = ?`, domain).Scan(&gotHash); err != nil {
		t.Fatalf("query persisted dns: %v", err)
	}
	if gotHash != contentHash {
		t.Fatalf("expected persisted content hash %q, got %q", contentHash, gotHash)
	}

	var gotIssuer string
	if err := reopened.DB.QueryRow(`SELECT issuer_server FROM contracts WHERE contract_id = ?`, contractID).Scan(&gotIssuer); err != nil {
		t.Fatalf("query persisted contract: %v", err)
	}
	if gotIssuer != reopened.Address {
		t.Fatalf("expected persisted issuer server %q, got %q", reopened.Address, gotIssuer)
	}
}
