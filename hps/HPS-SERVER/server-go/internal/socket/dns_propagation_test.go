package socket

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hpsserver/internal/core"
	"hpsserver/internal/socketio"
)

func insertTestDNS(cs *Server, domain, owner, issuerServer, issuerPublicKey, issuerContractID string) {
	now := float64(time.Now().Unix())
	_, _ = cs.server.DB.Exec(`INSERT OR REPLACE INTO dns_records
		(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, "testhash", "testuser", owner, now, "testsig", 1, now, "testddns",
		issuerServer, issuerPublicKey, issuerContractID, now)
}

// TestAddressURLFix_DNSWithAddressURL_ReturnsLocal verifies that a DNS record
// whose issuer_server matches s.server.AddressURL() ("http://127.0.0.1:PORT")
// is correctly identified as local. This is the primary AddressURL() fix.
func TestAddressURLFix_DNSWithAddressURL_ReturnsLocal(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	issuerServer := coreServer.AddressURL()
	insertTestDNS(s, "addrurl-test.hsyst", "thais", issuerServer, "pubkey", "contract-addrurl")

	result := s.ensureIssuerVerificationJob("domain", "addrurl-test.hsyst", "access", "thais", "", false)
	status := asString(result["status"])
	if status != "local" {
		t.Fatalf("expected 'local' for issuer_server=%q, got %q", issuerServer, result)
	}
}

// TestAddressURLFix_DNSWithBindAddress_ReturnsLocal verifies that a DNS record
// whose issuer_server matches s.server.BindAddress (no http:// prefix) still
// identifies as local (pre-existing behavior, tested for regression).
func TestAddressURLFix_DNSWithBindAddress_ReturnsLocal(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	issuerServer := coreServer.BindAddress
	insertTestDNS(s, "bindaddr-test.hsyst", "thais", issuerServer, "pubkey", "contract-bindaddr")

	result := s.ensureIssuerVerificationJob("domain", "bindaddr-test.hsyst", "access", "thais", "", false)
	status := asString(result["status"])
	if status != "local" {
		t.Fatalf("expected 'local' for issuer_server=%q, got %q", issuerServer, result)
	}
}

// TestAddressURLFix_DNSWithAddress_ReturnsLocal verifies that issuer_server
// matching s.server.Address (no http://) still identifies as local.
func TestAddressURLFix_DNSWithAddress_ReturnsLocal(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	issuerServer := coreServer.Address
	insertTestDNS(s, "address-test.hsyst", "thais", issuerServer, "pubkey", "contract-address")

	result := s.ensureIssuerVerificationJob("domain", "address-test.hsyst", "access", "thais", "", false)
	status := asString(result["status"])
	if status != "local" {
		t.Fatalf("expected 'local' for issuer_server=%q, got %q", issuerServer, result)
	}
}

// TestIssuerVerificationGate_AssignedJobNoMiners_ReturnsAllowed verifies that
// a verification job with status "assigned" and no online miners returns
// allowed=true with status=timeout. This is the "assigned" fallback fix.
func TestIssuerVerificationGate_AssignedJobNoMiners_ReturnsAllowed(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	insertTestDNS(s, "assigned-fallback.hsyst", "thais2", "http://remote-server:8080",
		"pubkey-remote", "contract-remote")

	_, _ = coreServer.DB.Exec(`INSERT INTO issuer_verification_jobs
		(job_id, target_type, target_id, request_kind, requester_username, original_owner,
		 issuer_server, issuer_public_key, issuer_contract_id, assigned_miner, status,
		 created_at, updated_at, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?)`,
		"job-assigned-fallback", "domain", "assigned-fallback.hsyst", "access",
		"thais2", "thais2", "http://remote-server:8080", "pubkey-remote",
		"contract-remote", "assigned", float64(time.Now().Unix()),
		float64(time.Now().Unix()), float64(time.Now().Add(60).Unix()))

	result := s.issuerVerificationGate("domain", "assigned-fallback.hsyst", "thais2")
	allowed, _ := result["allowed"].(bool)
	if !allowed {
		t.Fatalf("expected allowed=true for assigned job with no miners, got %#v", result)
	}
	status := asString(result["status"])
	if status != "timeout" {
		t.Fatalf("expected status=timeout, got %q", status)
	}
}

// TestIssuerVerificationGate_PendingJobNoMiners_ReturnsAllowed verifies that
// a pending job with no online miners also returns allowed=true (pre-existing
// behavior, tested here as regression guard for the assigned fix).
func TestIssuerVerificationGate_PendingJobNoMiners_ReturnsAllowed(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	insertTestDNS(s, "pending-fallback.hsyst", "thais", "http://remote-server:8080",
		"pubkey-remote", "contract-pending")

	// First call creates a pending job
	_ = s.ensureIssuerVerificationJob("domain", "pending-fallback.hsyst", "access", "thais", "", false)

	result := s.issuerVerificationGate("domain", "pending-fallback.hsyst", "thais")
	allowed, _ := result["allowed"].(bool)
	if !allowed {
		t.Fatalf("expected allowed=true for pending job with no miners, got %#v", result)
	}
	status := asString(result["status"])
	if status != "timeout" {
		t.Fatalf("expected status=timeout, got %q", status)
	}
}

// TestEnsureIssuerVerificationJob_RemoteIssuer_CreatesPending verifies that
// a DNS record pointing to a truly remote issuer creates a pending verification job.
func TestEnsureIssuerVerificationJob_RemoteIssuer_CreatesPending(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	insertTestDNS(s, "remote-pending.hsyst", "thais", "http://truly-remote:9999",
		"pubkey-remote", "contract-xyz")

	result := s.ensureIssuerVerificationJob("domain", "remote-pending.hsyst", "access", "thais", "", false)
	status := asString(result["status"])
	if status != "pending" {
		t.Fatalf("expected status 'pending' for remote issuer, got %q", result)
	}
	if asString(result["job_id"]) == "" {
		t.Fatal("expected non-empty job_id")
	}
}

// TestVerifyIssuerBindingWithMockRemoteServer simulates a complete DNS
// propagation scenario: a DNS record points to a remote issuer server,
// and verifyIssuerBinding contacts it and successfully confirms the binding.
func TestVerifyIssuerBindingWithMockRemoteServer(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	issuerPublicKeyB64 := base64.StdEncoding.EncodeToString(coreServer.PublicKeyPEM)

	contractDetails := []core.ContractDetail{
		{Key: "PUBLIC_KEY", Value: issuerPublicKeyB64},
		{Key: "TARGET_TYPE", Value: "domain"},
		{Key: "TARGET_ID", Value: "mock-issuer-test.hsyst"},
		{Key: "ISSUER_SERVER", Value: "http://placeholder:8080"},
		{Key: "ISSUER_CONTRACT_ID", Value: "contract-mock-dns"},
		{Key: "STATUS", Value: "confirmed"},
		{Key: "DETAIL", Value: "issuer_confirmed"},
		{Key: "ORIGINAL_OWNER", Value: "thais"},
	}
	contractText := coreServer.BuildServerContractText("dns_issuer_attest", contractDetails, core.CustodyUsername)
	signature := coreServer.SignContractText(contractText)
	signedText := strings.Replace(contractText, "# SIGNATURE: ", "# SIGNATURE: "+signature, 1)
	contractBytes := []byte(signedText)

	mux := http.NewServeMux()
	mux.HandleFunc("/server_info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"public_key": issuerPublicKeyB64})
	})
	mux.HandleFunc("/contract/contract-mock-dns", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(contractBytes)
	})
	mux.HandleFunc("/sync/dns", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") == "mock-issuer-test.hsyst" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{"domain": "mock-issuer-test.hsyst"}},
			})
			return
		}
		http.NotFound(w, r)
	})
	issuerServer := httptest.NewServer(mux)
	defer issuerServer.Close()

	insertTestDNS(s, "mock-issuer-test.hsyst", "thais", issuerServer.URL, issuerPublicKeyB64,
		"contract-mock-dns")

	result := s.verifyIssuerBinding("domain", "mock-issuer-test.hsyst", true)
	status := asString(result["status"])
	if status != "confirmed" {
		t.Fatalf("expected status 'confirmed', got %#v", result)
	}

	verification := coreServer.GetIssuerVerification("domain", "mock-issuer-test.hsyst")
	if verification == nil {
		t.Fatal("expected issuer verification record after successful verification")
	}
	if asString(verification["status"]) != "confirmed" {
		t.Fatalf("expected verification status 'confirmed', got %#v", verification)
	}
}

// TestDnsPropagationFullFlow simulates the complete DNS propagation scenario:
// 1. Register DNS on a remote server
// 2. DNS record is synced to local server
// 3. Local server resolves DNS and verifies issuer via remote
func TestDnsPropagationFullFlow(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	issuerPublicKeyB64 := base64.StdEncoding.EncodeToString(coreServer.PublicKeyPEM)

	contractDetails := []core.ContractDetail{
		{Key: "PUBLIC_KEY", Value: issuerPublicKeyB64},
		{Key: "TARGET_TYPE", Value: "domain"},
		{Key: "TARGET_ID", Value: "propagation-test.hsyst"},
		{Key: "ISSUER_SERVER", Value: "http://placeholder:8080"},
		{Key: "ISSUER_CONTRACT_ID", Value: "contract-propagation"},
		{Key: "STATUS", Value: "confirmed"},
		{Key: "DETAIL", Value: "issuer_confirmed"},
		{Key: "ORIGINAL_OWNER", Value: "thais"},
	}
	contractText := coreServer.BuildServerContractText("dns_issuer_attest", contractDetails, core.CustodyUsername)
	signature := coreServer.SignContractText(contractText)
	signedText := strings.Replace(contractText, "# SIGNATURE: ", "# SIGNATURE: "+signature, 1)
	contractBytes := []byte(signedText)

	// Mock remote issuer server serves contract, server_info, and sync/dns
	mux := http.NewServeMux()
	mux.HandleFunc("/server_info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"public_key": issuerPublicKeyB64})
	})
	mux.HandleFunc("/contract/contract-propagation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(contractBytes)
	})
	mux.HandleFunc("/sync/dns", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domain") == "propagation-test.hsyst" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{"domain": "propagation-test.hsyst"}},
			})
			return
		}
		http.NotFound(w, r)
	})
	issuerServer := httptest.NewServer(mux)
	defer issuerServer.Close()

	// Step 1: "Remote" server registers DNS with issuer = itself
	// Step 2: DNS record is synced to "local" server with issuer_server pointing to remote
	insertTestDNS(s, "propagation-test.hsyst", "thais", issuerServer.URL, issuerPublicKeyB64,
		"contract-propagation")

	// Step 3: Verify the issuer binding directly (simulates miner verification)
	verifyResult := s.verifyIssuerBinding("domain", "propagation-test.hsyst", true)
	if asString(verifyResult["status"]) != "confirmed" {
		t.Fatalf("issuer verification should succeed against mock, got %#v", verifyResult)
	}

	// Step 4: After verification is stored, the gate should return confirmed
	gateResult := s.issuerVerificationGate("domain", "propagation-test.hsyst", "thais")
	allowed, _ := gateResult["allowed"].(bool)
	status := asString(gateResult["status"])

	if !allowed {
		t.Fatalf("DNS propagation gate: expected allowed=true, got %#v", gateResult)
	}
	if status != "confirmed" {
		t.Fatalf("DNS propagation gate: expected status=confirmed after successful verification, got %q", status)
	}
}

// TestAssignPendingIssuerJobs_NoMiners_ExpiresJob verifies that when no miners
// are available, assignPendingIssuerVerificationJobs expires the job immediately
// instead of skipping it (preventing infinite hang).
func TestAssignPendingIssuerJobs_NoMiners_ExpiresJob(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	insertTestDNS(s, "expire-test.hsyst", "thais", "http://remote-server:9999",
		"pubkey", "contract-expire")

	nowTs := float64(time.Now().Unix())
	jobID := "job-expire-no-miner"
	_, _ = coreServer.DB.Exec(`INSERT INTO issuer_verification_jobs
		(job_id, target_type, target_id, request_kind, requester_username, original_owner,
		 issuer_server, issuer_public_key, issuer_contract_id, assigned_miner, status,
		 created_at, updated_at, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?)`,
		jobID, "domain", "expire-test.hsyst", "access",
		"thais", "thais", "http://remote-server:9999", "pubkey",
		"contract-expire", "pending", nowTs, nowTs, nowTs+60.0)

	// Call assignPendingIssuerVerificationJobs — should expire the job since no miners exist
	s.assignPendingIssuerVerificationJobs()

	var status, resultStatus, resultDetail string
	err := coreServer.DB.QueryRow(`SELECT status, result_status, result_detail FROM issuer_verification_jobs WHERE job_id = ?`, jobID).
		Scan(&status, &resultStatus, &resultDetail)
	if err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "completed" {
		t.Fatalf("expected status=completed (expired), got %q (result=%s detail=%s)", status, resultStatus, resultDetail)
	}
	if resultStatus != "timeout" {
		t.Fatalf("expected result_status=timeout, got %q", resultStatus)
	}
	if resultDetail != "issuer_no_miner_available" {
		t.Fatalf("expected result_detail=issuer_no_miner_available, got %q", resultDetail)
	}
}

// TestAssignPendingIssuerJobs_StaleAssigned_ExpiresJob verifies that stale
// assigned jobs (past deadline) are expired and the requester is notified.
func TestAssignPendingIssuerJobs_StaleAssigned_ExpiresJob(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	insertTestDNS(s, "stale-assigned.hsyst", "thais", "http://remote-server:9999",
		"pubkey", "contract-stale")

	nowTs := float64(time.Now().Unix())
	jobID := "job-stale-assigned"
	// Create an "assigned" job with deadline in the past
	_, _ = coreServer.DB.Exec(`INSERT INTO issuer_verification_jobs
		(job_id, target_type, target_id, request_kind, requester_username, original_owner,
		 issuer_server, issuer_public_key, issuer_contract_id, assigned_miner, status,
		 created_at, updated_at, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'somedone', ?, ?, ?, ?)`,
		jobID, "domain", "stale-assigned.hsyst", "access",
		"thais", "thais", "http://remote-server:9999", "pubkey",
		"contract-stale", "assigned", nowTs-300.0, nowTs-300.0, nowTs-10.0)

	// Call assignPendingIssuerVerificationJobs — should expire the stale assigned job
	s.assignPendingIssuerVerificationJobs()

	var status, resultStatus, resultDetail string
	err := coreServer.DB.QueryRow(`SELECT status, result_status, result_detail FROM issuer_verification_jobs WHERE job_id = ?`, jobID).
		Scan(&status, &resultStatus, &resultDetail)
	if err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "completed" {
		t.Fatalf("expected status=completed (stale expired), got %q (result=%s detail=%s)", status, resultStatus, resultDetail)
	}
	if resultStatus != "timeout" {
		t.Fatalf("expected result_status=timeout, got %q", resultStatus)
	}
	if resultDetail != "issuer_assigned_miner_timeout" {
		t.Fatalf("expected result_detail=issuer_assigned_miner_timeout, got %q", resultDetail)
	}
}
