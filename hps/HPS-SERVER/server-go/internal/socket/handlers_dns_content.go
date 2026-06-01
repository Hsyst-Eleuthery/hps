package socket

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"hpsserver/internal/core"
	"hpsserver/internal/socketio"
)

var (
	dnsCancelOps     sync.Map
	contentCancelOps sync.Map
	flowCancelOps    sync.Map
)

func isDNSOpCancelled(connID, domain string) bool {
	v, ok := dnsCancelOps.LoadAndDelete(connID + ":" + domain)
	return ok && v.(bool)
}

func isContentOpCancelled(connID, contentHash string) bool {
	v, ok := contentCancelOps.LoadAndDelete(connID + ":" + contentHash)
	return ok && v.(bool)
}

func isFlowCancelled(connID, kind, target string) bool {
	v, ok := flowCancelOps.LoadAndDelete(connID + ":" + kind + ":" + target)
	return ok && v.(bool)
}

func emitFlowProgress(conn socketio.Conn, kind, step string, stepIndex, totalSteps int, stepLabel string, timeoutMs int) {
	conn.Emit("flow_progress", map[string]any{
		"kind":         kind,
		"step":         step,
		"step_index":   stepIndex,
		"total_steps":  totalSteps,
		"step_label":   stepLabel,
		"timeout_ms":   timeoutMs,
		"started_at":   nowSec(),
	})
}

func emitDnsProgress(conn socketio.Conn, step string, stepIndex, totalSteps int, stepLabel string, timeoutMs int) {
	conn.Emit("dns_progress", map[string]any{
		"step":         step,
		"step_index":   stepIndex,
		"total_steps":  totalSteps,
		"step_label":   stepLabel,
		"timeout_ms":   timeoutMs,
		"started_at":   nowSec(),
	})
}

func emitContentProgress(conn socketio.Conn, step string, stepIndex, totalSteps int, stepLabel string, timeoutMs int) {
	conn.Emit("content_progress", map[string]any{
		"step":         step,
		"step_index":   stepIndex,
		"total_steps":  totalSteps,
		"step_label":   stepLabel,
		"timeout_ms":   timeoutMs,
		"started_at":   nowSec(),
	})
}

func (s *Server) handleResolveDNS(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("dns_resolution", map[string]any{"success": false, "error": "Not authenticated"})
		conn.Emit("dns_search_status", map[string]any{"status": "error", "error": "Not authenticated"})
		return
	}
	domain := trim(asString(data["domain"]))
	if domain == "" {
		conn.Emit("dns_resolution", map[string]any{"success": false, "error": "Missing domain"})
		conn.Emit("dns_search_status", map[string]any{"status": "error", "error": "Missing domain"})
		return
	}
	var contentHash, username, signature, ddnsHash, originalOwner, issuerServer, issuerContractID, publicKey string
	var verified int
	var reputation int
	err := s.server.DB.QueryRow(`SELECT d.content_hash, d.username, d.signature, d.verified, d.ddns_hash, d.original_owner, COALESCE(d.issuer_server, ''), COALESCE(d.issuer_contract_id, ''), COALESCE(ur.reputation, 100), COALESCE(us.public_key, '')
		FROM dns_records d LEFT JOIN user_reputations ur ON d.username = ur.username
		LEFT JOIN users us ON d.username = us.username
		WHERE d.domain = ? ORDER BY COALESCE(ur.reputation, 100) DESC, d.verified DESC LIMIT 1`, domain).
		Scan(&contentHash, &username, &signature, &verified, &ddnsHash, &originalOwner, &issuerServer, &issuerContractID, &reputation, &publicKey)
	if err == nil {
		sid := conn.ID()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("PANIC: handleResolveDNS serveDnsFromLocal goroutine domain=%s sid=%s err=%v", domain, sid, r)
				}
			}()
			s.serveDnsFromLocal(conn, domain, contentHash, username, signature, verified, ddnsHash, originalOwner, issuerServer, issuerContractID, publicKey, reputation, client.Username, false)
		}()
		return
	}
	conn.Emit("dns_search_status", map[string]any{"status": "searching_network", "domain": domain})
	sid := conn.ID()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("PANIC: handleResolveDNS goroutine domain=%s sid=%s err=%v", domain, sid, r)
			}
		}()
		// Usa contexto com timeout máximo para evitar goroutine leak
		resolveCtx, resolveCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer resolveCancel()

		emitDnsProgress(conn, "searching_network", 1, 4, "Buscando domínio na rede...", 20000)
		done := make(chan bool, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("PANIC: handleResolveDNS inner goroutine domain=%s sid=%s err=%v", domain, sid, r)
					done <- false
				}
			}()
			done <- s.resolveDNSFromNetwork(domain)
		}()
		var resolved bool
		select {
		case r := <-done:
			resolved = r
		case <-resolveCtx.Done():
			log.Printf("handleResolveDNS: deadline exceeded domain=%s sid=%s", domain, sid)
			conn.Emit("dns_resolution", map[string]any{"success": false, "error": "Timeout searching network"})
			conn.Emit("dns_search_status", map[string]any{"status": "done", "found": false, "domain": domain})
			return
		}

		if resolved {
			if isDNSOpCancelled(conn.ID(), domain) {
				conn.Emit("dns_resolution", map[string]any{"success": false, "error": "Cancelled"})
				conn.Emit("dns_search_status", map[string]any{"status": "done", "found": false, "domain": domain})
				return
			}
		} else {
			conn.Emit("dns_resolution", map[string]any{"success": false, "error": "Domain not found"})
			conn.Emit("dns_search_status", map[string]any{"status": "done", "found": false, "domain": domain})
			return
		}
		var contentHash2, username2, signature2, ddnsHash2, originalOwner2, issuerServer2, issuerContractID2, publicKey2 string
		var verified2 int
		var reputation2 int
		err2 := s.server.DB.QueryRow(`SELECT d.content_hash, d.username, d.signature, d.verified, d.ddns_hash, d.original_owner, COALESCE(d.issuer_server, ''), COALESCE(d.issuer_contract_id, ''), COALESCE(ur.reputation, 100), COALESCE(us.public_key, '')
			FROM dns_records d LEFT JOIN user_reputations ur ON d.username = ur.username
			LEFT JOIN users us ON d.username = us.username
			WHERE d.domain = ? ORDER BY COALESCE(ur.reputation, 100) DESC, d.verified DESC LIMIT 1`, domain).
			Scan(&contentHash2, &username2, &signature2, &verified2, &ddnsHash2, &originalOwner2, &issuerServer2, &issuerContractID2, &reputation2, &publicKey2)
		if err2 != nil {
			log.Printf("dns resolution: network resolve succeeded but re-query failed domain=%s sid=%s", domain, sid)
			conn.Emit("dns_resolution", map[string]any{"success": false, "error": "Domain not found"})
			conn.Emit("dns_search_status", map[string]any{"status": "done", "found": false, "domain": domain})
			return
		}
		if isDNSOpCancelled(conn.ID(), domain) {
			conn.Emit("dns_resolution", map[string]any{"success": false, "error": "Cancelled"})
			conn.Emit("dns_search_status", map[string]any{"status": "done", "found": false, "domain": domain})
			return
		}
		s.serveDnsFromLocal(conn, domain, contentHash2, username2, signature2, verified2, ddnsHash2, originalOwner2, issuerServer2, issuerContractID2, publicKey2, reputation2, client.Username, true)
	}()
}

func (s *Server) serveDnsFromLocal(conn socketio.Conn, domain, contentHash, username, signature string, verified int, ddnsHash, originalOwner, issuerServer, issuerContractID, publicKey string, reputation int, requesterUsername string, dnsResolvedFromNetwork bool) {
	ddnsPath := ""
	if ddnsHash != "" {
		ddnsPath = s.server.DdnsPath(ddnsHash)
	}
	if ddnsPath == "" || !fileExists(ddnsPath) {
		log.Printf("dns resolution: ddns file not local domain=%s hash=%s path=%s", domain, ddnsHash, ddnsPath)
		ddnsPath = ""
	}
	contentPath := s.server.ContentPath(contentHash)
	if !fileExists(contentPath) {
		log.Printf("dns resolution: content not local hash=%s domain=%s", contentHash, domain)
	}
	_, _ = s.server.DB.Exec("UPDATE dns_records SET last_resolved = ? WHERE domain = ?", nowSec(), domain)
	emitDnsProgress(conn, "issuer_verification", 2, 4, "Verificando emissor...", 3000)
	issuerGate := s.issuerVerificationGate("domain", domain, requesterUsername)
	if !asBool(issuerGate["allowed"]) {
		conn.Emit("dns_resolution", map[string]any{
			"success":        false,
			"error":          "issuer_verification_pending",
			"domain":         domain,
			"content_hash":   contentHash,
			"job_id":         asString(issuerGate["job_id"]),
			"assigned_miner": asString(issuerGate["miner"]),
		})
		conn.Emit("dns_search_status", map[string]any{"status": "pending_verification", "domain": domain})
		return
	}
	issuerVerification := castMap(issuerGate["verification"])
	contractViolation, reason := s.server.EvaluateContractViolationForDomain(domain)
	if !dnsResolvedFromNetwork && contractViolation && reason == "missing_contract" {
		emitDnsProgress(conn, "re_resolve_network", 3, 4, "Re-buscando na rede...", 20000)
		if s.resolveDNSFromNetwork(domain) {
			contractViolation, reason = s.server.EvaluateContractViolationForDomain(domain)
		}
	}
	if contractViolation && reason == "missing_contract" {
		emitDnsProgress(conn, "requesting_contracts", 4, 4, "Solicitando contratos...", 8000)
		s.requestContractsForDomainFromClients(domain)
		contractViolation, reason = s.server.EvaluateContractViolationForDomain(domain)
	}
	contracts, _ := s.server.GetContractsForDomain(domain)
	certification := s.server.GetContractCertification("domain", domain)
	certifier := ""
	certOriginalOwner := originalOwner
	if certification != nil {
		certifier = asString(certification["certifier"])
		if asString(certification["original_owner"]) != "" {
			certOriginalOwner = asString(certification["original_owner"])
		}
	}
	if contractViolation {
		conn.Emit("dns_resolution", map[string]any{
			"success":                   false,
			"error":                     "contract_violation",
			"contract_violation_reason": reason,
			"domain":                    domain,
			"content_hash":              contentHash,
			"contracts":                 contracts,
			"original_owner":            certOriginalOwner,
			"certifier":                 certifier,
			"issuer_status":             asString(issuerVerification["status"]),
			"issuer_detail":             asString(issuerVerification["detail"]),
			"issuer_server":             issuerServer,
			"issuer_contract_id":        issuerContractID,
		})
		conn.Emit("dns_search_status", map[string]any{"status": "done", "found": true, "domain": domain, "contract_violation": true})
		return
	}
	dnsPayload := map[string]any{
		"success":                   true,
		"domain":                    domain,
		"content_hash":              contentHash,
		"username":                  username,
		"verified":                  verified != 0,
		"ddns_hash":                 ddnsHash,
		"public_key":                publicKey,
		"reputation":                reputation,
		"contracts":                 contracts,
		"contract_violation":        false,
		"contract_violation_reason": "",
		"signature":                 signature,
		"original_owner":            certOriginalOwner,
		"certifier":                 certifier,
		"issuer_status":             asString(issuerVerification["status"]),
		"issuer_detail":             asString(issuerVerification["detail"]),
		"issuer_server":             issuerServer,
		"issuer_contract_id":        issuerContractID,
	}
	if ddnsPath != "" {
		if ddnsContent, err := s.server.ReadEncryptedFile(ddnsPath); err == nil && len(ddnsContent) > 0 {
			dnsPayload["ddns_content"] = base64.StdEncoding.EncodeToString(ddnsContent)
		}
	}
	conn.Emit("dns_resolution", dnsPayload)
	conn.Emit("dns_search_status", map[string]any{"status": "done", "found": true, "domain": domain, "contract_violation": false})
}

func (s *Server) handleCancelDNS(conn socketio.Conn, data map[string]any) {
	domain := asString(data["domain"])
	if domain != "" {
		dnsCancelOps.Store(conn.ID()+":"+domain, true)
	}
}

func (s *Server) handleCancelContent(conn socketio.Conn, data map[string]any) {
	contentHash := asString(data["content_hash"])
	if contentHash != "" {
		contentCancelOps.Store(conn.ID()+":"+contentHash, true)
	}
}

func (s *Server) handleCancelFlow(conn socketio.Conn, data map[string]any) {
	kind := asString(data["kind"])
	target := asString(data["target"])
	if kind != "" && target != "" {
		flowCancelOps.Store(conn.ID()+":"+kind+":"+target, true)
	}
	// Also set the specific cancel maps for backward compatibility
	if kind == "dns" && target != "" {
		dnsCancelOps.Store(conn.ID()+":"+target, true)
	}
	if kind == "content" && target != "" {
		contentCancelOps.Store(conn.ID()+":"+target, true)
	}
}

func (s *Server) handleRequestContent(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("content_response", map[string]any{"error": "Not authenticated"})
		return
	}
	contentHash := asString(data["content_hash"])
	if contentHash == "" {
		conn.Emit("content_response", map[string]any{"error": "Missing content hash"})
		return
	}
	log.Printf("content request: start hash=%s sid=%s user=%s", contentHash, conn.ID(), client.Username)

	redirectedHash := s.server.GetRedirectedHash(contentHash)
	if redirectedHash != "" {
		var appName string
		_ = s.server.DB.QueryRow(`SELECT app_name FROM api_apps WHERE content_hash = ?`, redirectedHash).Scan(&appName)
		if appName != "" {
			rows, err := s.server.DB.Query(`SELECT contract_id, action_type, content_hash, username, timestamp
				FROM contracts WHERE action_type = ? AND content_hash = ?
				ORDER BY timestamp DESC LIMIT 3`, "change_api_app", redirectedHash)
			changeContracts := []map[string]any{}
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var contractID, actionType, cHash, cUser string
					var ts float64
					if rows.Scan(&contractID, &actionType, &cHash, &cUser, &ts) == nil {
						changeContracts = append(changeContracts, map[string]any{
							"contract_id":  contractID,
							"action_type":  actionType,
							"content_hash": cHash,
							"username":     cUser,
							"timestamp":    ts,
						})
					}
				}
			}
			payload := map[string]any{
				"message":          "API App atualizado",
				"new_hash":         redirectedHash,
				"app_name":         appName,
				"change_contracts": changeContracts,
			}
			conn.Emit("content_response", map[string]any{
				"success":           true,
				"content":           base64.StdEncoding.EncodeToString([]byte(toJSONString(payload))),
				"title":             "API App Atualizado",
				"description":       "Este API App foi atualizado para o hash " + redirectedHash,
				"mime_type":         "application/json",
				"username":          "system",
				"signature":         "",
				"public_key":        "",
				"verified":          0,
				"content_hash":      contentHash,
				"reputation":        0,
				"is_api_app_update": true,
			})
			return
		}
		message := "Arquivo desatualizado, Novo Hash: " + redirectedHash
		conn.Emit("content_response", map[string]any{
			"success":      true,
			"content":      base64.StdEncoding.EncodeToString([]byte(message)),
			"title":        "Redirecionamento",
			"description":  "Este arquivo foi atualizado",
			"mime_type":    "text/plain",
			"username":     "system",
			"signature":    "",
			"public_key":   "",
			"verified":     0,
			"content_hash": contentHash,
			"reputation":   0,
		})
		return
	}

	var title, description, mimeType, username, signature, publicKey, issuerServer, issuerContractID string
	var verified int
	var size int64
	err := s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key, verified, size, COALESCE(issuer_server, ''), COALESCE(issuer_contract_id, '')
		FROM content WHERE content_hash = ?`, contentHash).Scan(&title, &description, &mimeType, &username, &signature, &publicKey, &verified, &size, &issuerServer, &issuerContractID)
	if err == nil {
		sid := conn.ID()
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("PANIC: handleRequestContent serveContentFromLocal goroutine hash=%s sid=%s err=%v", contentHash, sid, r)
				}
			}()
			s.serveContentFromLocal(conn, contentHash, title, description, mimeType, username, signature, publicKey, verified, issuerServer, issuerContractID, client.Username, false)
		}()
		return
	}

	searchHash := contentHash
	sid := conn.ID()
	log.Printf("content request: searching network hash=%s sid=%s", searchHash, sid)
	s.emitContentSearchPending(conn, contentHash)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("PANIC: handleRequestContent goroutine hash=%s sid=%s err=%v", contentHash, sid, r)
				conn.Emit("content_response", map[string]any{"success": false, "error": "Internal server error"})
			}
		}()
		emitContentProgress(conn, "searching_network", 1, 5, "Buscando conteúdo na rede...", 20000)
		_ = s.fetchContentFromNetwork(contentHash)

		if isContentOpCancelled(conn.ID(), contentHash) {
			log.Printf("content request: cancelled by user hash=%s sid=%s", contentHash, sid)
			conn.Emit("content_response", map[string]any{"success": false, "error": "Cancelled"})
			return
		}

		var title2, description2, mimeType2, username2, signature2, publicKey2, issuerServer2, issuerContractID2 string
		var verified2 int
		var size2 int64
		err2 := s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key, verified, size, COALESCE(issuer_server, ''), COALESCE(issuer_contract_id, '')
			FROM content WHERE content_hash = ?`, contentHash).Scan(&title2, &description2, &mimeType2, &username2, &signature2, &publicKey2, &verified2, &size2, &issuerServer2, &issuerContractID2)
		if err2 == nil {
			s.serveContentFromLocal(conn, contentHash, title2, description2, mimeType2, username2, signature2, publicKey2, verified2, issuerServer2, issuerContractID2, client.Username, true)
			return
		}

		if isContentOpCancelled(conn.ID(), contentHash) {
			log.Printf("content request: cancelled by user hash=%s sid=%s", contentHash, sid)
			conn.Emit("content_response", map[string]any{"success": false, "error": "Cancelled"})
			return
		}

		var redirectedContentHash string
		emitContentProgress(conn, "redirect_resolve", 2, 5, "Resolvendo redirecionamento...", 10000)
		_ = s.server.DB.QueryRow(`SELECT content_hash FROM dns_records WHERE domain = ?`, contentHash).Scan(&redirectedContentHash)
		if redirectedContentHash == "" && s.resolveDNSFromNetwork(contentHash) {
			_ = s.server.DB.QueryRow(`SELECT content_hash FROM dns_records WHERE domain = ?`, contentHash).Scan(&redirectedContentHash)
		}
		if redirectedContentHash == "" {
			if fallback := s.buildContentFallbackResponse(contentHash); fallback != nil {
				conn.Emit("content_response", fallback)
			} else {
				log.Printf("content request: metadata not found hash=%s sid=%s", searchHash, sid)
				conn.Emit("content_response", map[string]any{"success": false, "error": "Content metadata not found"})
			}
			return
		}

		if isContentOpCancelled(conn.ID(), contentHash) {
			log.Printf("content request: cancelled by user hash=%s sid=%s", contentHash, sid)
			conn.Emit("content_response", map[string]any{"success": false, "error": "Cancelled"})
			return
		}

		contentHash = redirectedContentHash
		err2 = s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key, verified, size, COALESCE(issuer_server, ''), COALESCE(issuer_contract_id, '')
			FROM content WHERE content_hash = ?`, contentHash).Scan(&title2, &description2, &mimeType2, &username2, &signature2, &publicKey2, &verified2, &size2, &issuerServer2, &issuerContractID2)
		if err2 != nil {
			s.emitContentSearchPending(conn, contentHash)
			emitContentProgress(conn, "searching_network_redirect", 3, 5, "Buscando conteúdo redirecionado na rede...", 20000)
			_ = s.fetchContentFromNetwork(contentHash)
			err2 = s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key, verified, size, COALESCE(issuer_server, ''), COALESCE(issuer_contract_id, '')
				FROM content WHERE content_hash = ?`, contentHash).Scan(&title2, &description2, &mimeType2, &username2, &signature2, &publicKey2, &verified2, &size2, &issuerServer2, &issuerContractID2)
		}
		if err2 != nil {
			if fallback := s.buildContentFallbackResponse(contentHash); fallback != nil {
				conn.Emit("content_response", fallback)
			} else {
				log.Printf("content request: metadata not found hash=%s redirected_from=%s sid=%s", contentHash, searchHash, sid)
				conn.Emit("content_response", map[string]any{"success": false, "error": "Content metadata not found"})
			}
			return
		}
		if isContentOpCancelled(conn.ID(), searchHash) {
			log.Printf("content request: cancelled by user hash=%s sid=%s", contentHash, sid)
			conn.Emit("content_response", map[string]any{"success": false, "error": "Cancelled"})
			return
		}
		s.serveContentFromLocal(conn, contentHash, title2, description2, mimeType2, username2, signature2, publicKey2, verified2, issuerServer2, issuerContractID2, client.Username, true)
	}()
}

func (s *Server) serveContentFromLocal(conn socketio.Conn, contentHash, title, description, mimeType, username, signature, publicKey string, verified int, issuerServer, issuerContractID, requesterUsername string, contentFetchedFromNetwork bool) {
	filePath := s.server.ContentPath(contentHash)
	content, err := s.server.ReadEncryptedFile(filePath)
	if err != nil {
		s.emitContentSearchPending(conn, contentHash)
		if !contentFetchedFromNetwork && s.fetchContentFromNetwork(contentHash) {
			content, err = s.server.ReadEncryptedFile(filePath)
		}
	}
	if err != nil {
		log.Printf("content request: read failed hash=%s sid=%s err=%v", contentHash, conn.ID(), err)
		conn.Emit("content_response", map[string]any{"success": false, "error": "Failed to read content: " + err.Error()})
		return
	}
	content, _ = core.ExtractContractFromContent(content)
	integrityReason := ""
	if strings.TrimSpace(signature) == "" || strings.TrimSpace(publicKey) == "" {
		integrityReason = "missing_signature"
	} else {
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != contentHash {
			integrityReason = "content_tampered"
		} else {
			if ok, _ := s.server.VerifyContentSignatureDetailed(content, signature, publicKey); !ok {
				integrityReason = "content_signature_invalid"
			}
		}
	}
	if integrityReason != "" {
		log.Printf("content request: integrity blocked hash=%s sid=%s reason=%s", contentHash, conn.ID(), integrityReason)
		s.server.RegisterContractViolation("content", "system", contentHash, "", integrityReason, false)
		s.server.EnsureContentRepairPending(contentHash)
		if strings.TrimSpace(username) != "" {
			s.emitToUser(username, "contract_violation_notice", map[string]any{
				"violation_type": "content",
				"content_hash":   contentHash,
				"reason":         integrityReason,
			})
			s.emitPendingTransferNotice(username)
		}
		conn.Emit("content_response", map[string]any{
			"success":                   false,
			"error":                     "contract_violation",
			"contract_violation_reason": integrityReason,
			"content_hash":              contentHash,
		})
		return
	}
	emitContentProgress(conn, "issuer_verification", 4, 5, "Verificando emissor...", 3000)
	issuerGate := s.issuerVerificationGateForResponse("content", contentHash, requesterUsername)
	if !asBool(issuerGate["allowed"]) {
		log.Printf("content request: issuer pending hash=%s sid=%s job=%s miner=%s", contentHash, conn.ID(), asString(issuerGate["job_id"]), asString(issuerGate["miner"]))
		conn.Emit("content_response", map[string]any{
			"success":        false,
			"error":          "issuer_verification_pending",
			"content_hash":   contentHash,
			"job_id":         asString(issuerGate["job_id"]),
			"assigned_miner": asString(issuerGate["miner"]),
		})
		return
	}
	contractViolation, reason := s.server.EvaluateContractViolationForContent(contentHash)
	if contractViolation && reason == "missing_contract" {
		emitContentProgress(conn, "requesting_contracts", 5, 5, "Solicitando contratos...", 8000)
		s.requestContractsForContentFromClients(contentHash)
		contractViolation, reason = s.server.EvaluateContractViolationForContent(contentHash)
	}
	issuerVerification := castMap(issuerGate["verification"])
	contracts, _ := s.server.GetContractsForContent(contentHash)
	certification := s.server.GetContractCertification("content", contentHash)
	certifier := ""
	originalOwner := username
	if certification != nil {
		certifier = asString(certification["certifier"])
		if asString(certification["original_owner"]) != "" {
			originalOwner = asString(certification["original_owner"])
		}
	}
	if contractViolation {
		log.Printf("content request: contract blocked hash=%s sid=%s reason=%s contracts=%d", contentHash, conn.ID(), reason, len(contracts))
		conn.Emit("content_response", map[string]any{
			"success":                   false,
			"error":                     "contract_violation",
			"contract_violation_reason": reason,
			"content_hash":              contentHash,
			"contracts":                 contracts,
			"original_owner":            originalOwner,
			"certifier":                 certifier,
			"issuer_status":             asString(issuerVerification["status"]),
			"issuer_detail":             asString(issuerVerification["detail"]),
			"issuer_server":             issuerServer,
			"issuer_contract_id":        issuerContractID,
		})
		return
	}
	if username == core.CustodyUsername || username == "system" {
		var pendingOwner string
		_ = s.server.DB.QueryRow(`SELECT original_owner FROM pending_transfers
			WHERE content_hash = ? AND status = ? ORDER BY timestamp DESC LIMIT 1`, contentHash, "pending").Scan(&pendingOwner)
		if pendingOwner != "" {
			username = pendingOwner
		}
		if originalOwner == "" {
			originalOwner = username
		}
	}
	_, _ = s.server.DB.Exec("UPDATE content SET last_accessed = ?, replication_count = replication_count + 1 WHERE content_hash = ?", nowSec(), contentHash)
	log.Printf("content request: success hash=%s sid=%s user=%s bytes=%d contracts=%d", contentHash, conn.ID(), username, len(content), len(contracts))
	conn.Emit("content_response", map[string]any{
		"success":                   true,
		"content":                   base64.StdEncoding.EncodeToString(content),
		"title":                     title,
		"description":               description,
		"mime_type":                 mimeType,
		"username":                  username,
		"signature":                 signature,
		"public_key":                publicKey,
		"verified":                  verified,
		"content_hash":              contentHash,
		"reputation":                s.getUserReputation(username),
		"contracts":                 contracts,
		"contract_violation":        false,
		"contract_violation_reason": "",
		"original_owner":            originalOwner,
		"certifier":                 certifier,
		"issuer_status":             asString(issuerVerification["status"]),
		"issuer_detail":             asString(issuerVerification["detail"]),
		"issuer_server":             issuerServer,
		"issuer_contract_id":        issuerContractID,
	})
}

func (s *Server) issuerVerificationGateForResponse(targetType, targetID, requesterUsername string) map[string]any {
	result := make(chan map[string]any, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("PANIC in issuerVerificationGate goroutine target=%s/%s err=%v", targetType, targetID, r)
				result <- map[string]any{}
			}
		}()
		result <- s.issuerVerificationGate(targetType, targetID, requesterUsername)
	}()
	select {
	case gate := <-result:
		return gate
	case <-time.After(3 * time.Second):
		log.Printf("issuer verification gate timeout target_type=%s target_id=%s requester=%s", targetType, targetID, requesterUsername)
		return map[string]any{
			"allowed":      true,
			"status":       "timeout",
			"verification": map[string]any{"status": "timeout", "detail": "issuer_gate_timeout"},
		}
	}
}

func (s *Server) emitContentSearchPending(conn socketio.Conn, contentHash string) {
	conn.Emit("content_response", map[string]any{
		"pending":      true,
		"status":       "searching_network",
		"message":      "Servidor nao tem o arquivo ou os metadados completos. Buscando em outros usuarios e servidores conhecidos.",
		"content_hash": contentHash,
	})
}

func (s *Server) buildContentFallbackResponse(contentHash string) map[string]any {
	filePath := s.server.ContentPath(contentHash)
	if _, err := os.Stat(filePath); err != nil {
		return nil
	}
	content, err := s.server.ReadEncryptedFile(filePath)
	if err != nil {
		return nil
	}
	content, _ = core.ExtractContractFromContent(content)
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != contentHash {
		return nil
	}
	return map[string]any{
		"success":                   true,
		"content_hash":              contentHash,
		"content":                   base64.StdEncoding.EncodeToString(content),
		"content_b64":               base64.StdEncoding.EncodeToString(content),
		"title":                     contentHash,
		"description":               "",
		"mime_type":                 "application/octet-stream",
		"username":                  "",
		"signature":                 "",
		"public_key":                "",
		"verified":                  false,
		"size":                      len(content),
		"reputation":                0,
		"integrity_ok":              true,
		"content_security":          "metadata_missing_local_file",
		"is_public":                 true,
		"certified":                 false,
		"contract_violation":        false,
		"contract_violation_reason": "",
		"original_owner":            "",
		"issuer_server":             "",
		"issuer_contract_id":        "",
	}
}
