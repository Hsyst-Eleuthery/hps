package socket

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"time"

	"hpsserver/internal/core"
	"hpsserver/internal/socketio"
)

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
	if err != nil {
		conn.Emit("dns_search_status", map[string]any{"status": "searching_network", "domain": domain})
		if s.resolveDNSFromNetwork(domain) {
			err = s.server.DB.QueryRow(`SELECT d.content_hash, d.username, d.signature, d.verified, d.ddns_hash, d.original_owner, COALESCE(d.issuer_server, ''), COALESCE(d.issuer_contract_id, ''), COALESCE(ur.reputation, 100), COALESCE(us.public_key, '')
				FROM dns_records d LEFT JOIN user_reputations ur ON d.username = ur.username
				LEFT JOIN users us ON d.username = us.username
				WHERE d.domain = ? ORDER BY COALESCE(ur.reputation, 100) DESC, d.verified DESC LIMIT 1`, domain).
				Scan(&contentHash, &username, &signature, &verified, &ddnsHash, &originalOwner, &issuerServer, &issuerContractID, &reputation, &publicKey)
		}
	}
	if err != nil {
		conn.Emit("dns_resolution", map[string]any{"success": false, "error": "Domain not found"})
		conn.Emit("dns_search_status", map[string]any{"status": "done", "found": false, "domain": domain})
		return
	}
	ddnsPath := ""
	if ddnsHash != "" {
		ddnsPath = s.server.DdnsPath(ddnsHash)
	}
	if ddnsPath == "" {
		conn.Emit("dns_search_status", map[string]any{"status": "searching_network", "domain": domain})
	}
	if ddnsPath == "" || !fileExists(ddnsPath) {
		if s.resolveDNSFromNetwork(domain) {
			_ = s.server.DB.QueryRow(`SELECT d.content_hash, d.username, d.signature, d.verified, d.ddns_hash, d.original_owner, COALESCE(d.issuer_server, ''), COALESCE(d.issuer_contract_id, ''), COALESCE(ur.reputation, 100), COALESCE(us.public_key, '')
				FROM dns_records d LEFT JOIN user_reputations ur ON d.username = ur.username
				LEFT JOIN users us ON d.username = us.username
				WHERE d.domain = ? ORDER BY COALESCE(ur.reputation, 100) DESC, d.verified DESC LIMIT 1`, domain).
				Scan(&contentHash, &username, &signature, &verified, &ddnsHash, &originalOwner, &issuerServer, &issuerContractID, &reputation, &publicKey)
			if ddnsHash != "" {
				ddnsPath = s.server.DdnsPath(ddnsHash)
			}
		}
	}
	if ddnsPath == "" || !fileExists(ddnsPath) {
		conn.Emit("dns_resolution", map[string]any{"success": false, "error": "DDNS file not available"})
		conn.Emit("dns_search_status", map[string]any{"status": "done", "found": false, "domain": domain})
		return
	}
	contentPath := s.server.ContentPath(contentHash)
	if !fileExists(contentPath) {
		conn.Emit("dns_search_status", map[string]any{"status": "searching_network", "domain": domain})
		if !s.fetchContentFromNetwork(contentHash) {
			conn.Emit("dns_resolution", map[string]any{"success": false, "error": "Content referenced by domain not found"})
			conn.Emit("dns_search_status", map[string]any{"status": "done", "found": false, "domain": domain})
			return
		}
	}
	_, _ = s.server.DB.Exec("UPDATE dns_records SET last_resolved = ? WHERE domain = ?", nowSec(), domain)
	issuerGate := s.issuerVerificationGate("domain", domain, client.Username)
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
	if contractViolation && reason == "missing_contract" {
		if s.resolveDNSFromNetwork(domain) {
			contractViolation, reason = s.server.EvaluateContractViolationForDomain(domain)
		}
	}
	if contractViolation && reason == "missing_contract" {
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
	filePath := s.server.ContentPath(contentHash)
	var title, description, mimeType, username, signature, publicKey, issuerServer, issuerContractID string
	var verified int
	var size int64
	err := s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key, verified, size, COALESCE(issuer_server, ''), COALESCE(issuer_contract_id, '')
		FROM content WHERE content_hash = ?`, contentHash).Scan(&title, &description, &mimeType, &username, &signature, &publicKey, &verified, &size, &issuerServer, &issuerContractID)
	if err != nil {
		s.emitContentSearchPending(conn, contentHash)
		_ = s.fetchContentFromNetwork(contentHash)
		err = s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key, verified, size, COALESCE(issuer_server, ''), COALESCE(issuer_contract_id, '')
			FROM content WHERE content_hash = ?`, contentHash).Scan(&title, &description, &mimeType, &username, &signature, &publicKey, &verified, &size, &issuerServer, &issuerContractID)
	}
	if err != nil {
		searchHash := contentHash
		var redirectedContentHash string
		_ = s.server.DB.QueryRow(`SELECT content_hash FROM dns_records WHERE domain = ?`, contentHash).Scan(&redirectedContentHash)
		if redirectedContentHash == "" && s.resolveDNSFromNetwork(contentHash) {
			_ = s.server.DB.QueryRow(`SELECT content_hash FROM dns_records WHERE domain = ?`, contentHash).Scan(&redirectedContentHash)
		}
		if redirectedContentHash == "" {
			if fallback := s.buildContentFallbackResponse(contentHash); fallback != nil {
				conn.Emit("content_response", fallback)
			} else {
				log.Printf("content request: metadata not found hash=%s sid=%s", searchHash, conn.ID())
				conn.Emit("content_response", map[string]any{"success": false, "error": "Content metadata not found"})
			}
			return
		}
		contentHash = redirectedContentHash
		filePath = s.server.ContentPath(contentHash)
		err = s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key, verified, size, COALESCE(issuer_server, ''), COALESCE(issuer_contract_id, '')
			FROM content WHERE content_hash = ?`, contentHash).Scan(&title, &description, &mimeType, &username, &signature, &publicKey, &verified, &size, &issuerServer, &issuerContractID)
		if err != nil {
			s.emitContentSearchPending(conn, contentHash)
			_ = s.fetchContentFromNetwork(contentHash)
			err = s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key, verified, size, COALESCE(issuer_server, ''), COALESCE(issuer_contract_id, '')
				FROM content WHERE content_hash = ?`, contentHash).Scan(&title, &description, &mimeType, &username, &signature, &publicKey, &verified, &size, &issuerServer, &issuerContractID)
		}
		if err != nil {
			if fallback := s.buildContentFallbackResponse(contentHash); fallback != nil {
				conn.Emit("content_response", fallback)
			} else {
				log.Printf("content request: metadata not found hash=%s redirected_from=%s sid=%s", contentHash, searchHash, conn.ID())
				conn.Emit("content_response", map[string]any{"success": false, "error": "Content metadata not found"})
			}
			return
		}
	}
	content, err := s.server.ReadEncryptedFile(filePath)
	if err != nil {
		s.emitContentSearchPending(conn, contentHash)
		if s.fetchContentFromNetwork(contentHash) {
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
	issuerGate := s.issuerVerificationGateForResponse("content", contentHash, client.Username)
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
