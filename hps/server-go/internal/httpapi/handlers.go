package httpapi

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"hpsserver/internal/core"
)

type jsonResponse map[string]any

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func notImplemented(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotImplemented, jsonResponse{"success": false, "error": "Not implemented"})
}

func HandleHealth(server *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var totalUsers, totalContent, totalDNS, totalContracts int
		_ = server.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)
		_ = server.DB.QueryRow("SELECT COUNT(*) FROM content").Scan(&totalContent)
		_ = server.DB.QueryRow("SELECT COUNT(*) FROM dns_records").Scan(&totalDNS)
		_ = server.DB.QueryRow("SELECT COUNT(*) FROM contracts").Scan(&totalContracts)

		payload := jsonResponse{
			"status":          "healthy",
			"server_id":       server.ServerID,
			"address":         server.Address,
			"online_clients":  atomic.LoadInt64(&server.ConnectedClients),
			"total_users":     totalUsers,
			"total_content":   totalContent,
			"total_dns":       totalDNS,
			"total_contracts": totalContracts,
			"uptime":          time.Since(server.StartTime).Seconds(),
			"timestamp":       float64(time.Now().UnixNano()) / 1e9,
		}
		writeJSON(w, http.StatusOK, payload)
	}
}

func HandleServerInfo(server *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload := jsonResponse{
			"server_id":  server.ServerID,
			"address":    server.Address,
			"public_key": base64.StdEncoding.EncodeToString(server.PublicKeyPEM),
			"timestamp":  float64(time.Now().UnixNano()) / 1e9,
		}
		writeJSON(w, http.StatusOK, payload)
	}
}

func HandleUpload(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		r.Body = http.MaxBytesReader(w, r.Body, core.MaxUploadSize+1024*1024)
		reader, err := r.MultipartReader()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "File missing"})
			return
		}
		part, err := reader.NextPart()
		if err != nil || part.FormName() != "file" {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "File missing"})
			return
		}
		limited := io.LimitReader(part, core.MaxUploadSize+1)
		fileData, err := io.ReadAll(limited)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "File missing"})
			return
		}
		username := strings.TrimSpace(r.Header.Get("X-Username"))
		signature := strings.TrimSpace(r.Header.Get("X-Signature"))
		publicKey := strings.TrimSpace(r.Header.Get("X-Public-Key"))
		clientID := strings.TrimSpace(r.Header.Get("X-Client-ID"))
		if username == "" || signature == "" || publicKey == "" || clientID == "" {
			writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Missing auth headers"})
			return
		}
		if len(fileData) > core.MaxUploadSize {
			writeJSON(w, http.StatusRequestEntityTooLarge, jsonResponse{"success": false, "error": "File too large"})
			return
		}
		allowed, message, remaining := server.CheckRateLimit(clientID, "upload")
		if !allowed {
			now := float64(time.Now().UnixNano()) / 1e9
			writeJSON(w, http.StatusTooManyRequests, jsonResponse{"success": false, "error": message, "blocked_until": now + float64(remaining)})
			return
		}
		var storedPublicKey, storedClientID string
		var diskQuota, usedDisk int64
		err = server.DB.QueryRow("SELECT public_key, client_identifier, disk_quota, used_disk_space FROM users WHERE username = ?", username).Scan(&storedPublicKey, &storedClientID, &diskQuota, &usedDisk)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "User not found"})
			return
		}
		if storedPublicKey == core.PendingPublicKeyLabel {
			writeJSON(w, http.StatusForbidden, jsonResponse{"success": false, "error": "Public key pending confirmation"})
			return
		}
		if storedPublicKey != "" && storedPublicKey != publicKey {
			writeJSON(w, http.StatusForbidden, jsonResponse{"success": false, "error": "Public key mismatch"})
			return
		}
		if storedClientID != "" && storedClientID != clientID {
			writeJSON(w, http.StatusForbidden, jsonResponse{"success": false, "error": "Client identifier mismatch"})
			return
		}
		if !server.VerifyContentSignature(fileData, signature, publicKey) {
			writeJSON(w, http.StatusUnauthorized, jsonResponse{"success": false, "error": "Invalid signature"})
			return
		}
		if usedDisk+int64(len(fileData)) > diskQuota {
			availableMB := float64(diskQuota-usedDisk) / (1024 * 1024)
			writeJSON(w, http.StatusRequestEntityTooLarge, jsonResponse{"success": false, "error": "Disk quota exceeded. Available space: " + fmt.Sprintf("%.2fMB", availableMB)})
			return
		}
		sum := sha256.Sum256(fileData)
		contentHash := hex.EncodeToString(sum[:])
		path := server.ContentPath(contentHash)
		if err := server.WriteEncryptedFile(path, fileData, 0o644); err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"success": false, "error": "Internal server error: " + err.Error()})
			return
		}
		server.UpdateRateLimit(clientID, "upload")
		writeJSON(w, http.StatusOK, jsonResponse{"success": true, "content_hash": contentHash, "message": "File received successfully"})
	}
}

func HandleContent(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		contentHash := chi.URLParam(r, "content_hash")

		if redirected := server.GetRedirectedHash(contentHash); redirected != "" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Arquivo desatualizado, Novo Hash: " + redirected))
			return
		}

		filePath := server.ContentPath(contentHash)
		if _, err := os.Stat(filePath); err != nil {
			var dnsHash string
			_ = server.DB.QueryRow("SELECT content_hash FROM dns_records WHERE domain = ?", contentHash).Scan(&dnsHash)
			if dnsHash != "" {
				contentHash = dnsHash
				filePath = server.ContentPath(dnsHash)
			}
		}

		if _, err := os.Stat(filePath); err != nil && server.FetchContentFromKnownServers(contentHash) {
			log.Printf("http content fetched from network hash=%s", contentHash)
			filePath = server.ContentPath(contentHash)
		}

		if _, err := os.Stat(filePath); err != nil {
			writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Content not found"})
			return
		}

		if ok, reason := server.VerifyStoredContentIntegrity(contentHash); !ok {
			server.RegisterContractViolation("content", "system", contentHash, "", reason, false)
			server.EnsureContentRepairPending(contentHash)
			writeJSON(w, http.StatusForbidden, jsonResponse{
				"success":                   false,
				"error":                     "contract_violation",
				"contract_violation_reason": reason,
				"content_hash":              contentHash,
			})
			return
		}

		violation, reason := server.EvaluateContractViolationForContent(contentHash)
		if violation {
			writeJSON(w, http.StatusForbidden, jsonResponse{"success": false, "error": "contract_violation", "contract_violation_reason": reason, "content_hash": contentHash})
			return
		}

		raw, err := server.ReadEncryptedFile(filePath)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, jsonResponse{"success": false, "error": "Failed to read content: " + err.Error()})
			return
		}
		content, _ := core.ExtractContractFromContent(raw)
		_, _ = server.DB.Exec("UPDATE content SET last_accessed = ?, replication_count = replication_count + 1 WHERE content_hash = ?", float64(time.Now().UnixNano())/1e9, contentHash)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(content)
	}
}

func HandleDNS(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		domain := chi.URLParam(r, "domain")
		var contentHash, username, signature, originalOwner, ddnsHash, issuerServer, issuerPublicKey, issuerContractID, publicKey string
		var verified int
		var issuerIssuedAt float64
		err := server.DB.QueryRow(`SELECT d.content_hash, d.username, d.signature, d.verified, d.original_owner,
			COALESCE(d.ddns_hash, ''), COALESCE(d.issuer_server, ''), COALESCE(d.issuer_public_key, ''),
			COALESCE(d.issuer_contract_id, ''), COALESCE(d.issuer_issued_at, 0), COALESCE(u.public_key, '')
			FROM dns_records d LEFT JOIN users u ON d.username = u.username
			WHERE d.domain = ? ORDER BY d.verified DESC LIMIT 1`, domain).Scan(
			&contentHash, &username, &signature, &verified, &originalOwner,
			&ddnsHash, &issuerServer, &issuerPublicKey, &issuerContractID, &issuerIssuedAt, &publicKey,
		)
		if err != nil {
			writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Domain not found"})
			return
		}
		_, _ = server.DB.Exec("UPDATE dns_records SET last_resolved = ? WHERE domain = ?", float64(time.Now().UnixNano())/1e9, domain)

		violation, reason := server.EvaluateContractViolationForDomain(domain)
		if violation {
			writeJSON(w, http.StatusForbidden, jsonResponse{
				"success": false, "error": "contract_violation", "contract_violation_reason": reason,
				"domain": domain, "content_hash": contentHash,
			})
			return
		}
		payload := jsonResponse{
			"success": true, "domain": domain, "content_hash": contentHash,
			"username": username, "signature": signature, "verified": verified != 0, "original_owner": originalOwner,
			"ddns_hash":     ddnsHash,
			"public_key":    publicKey,
			"issuer_server": issuerServer, "issuer_public_key": issuerPublicKey,
			"issuer_contract_id": issuerContractID, "issuer_issued_at": issuerIssuedAt,
			"contracts": syncContractsForDomain(server, domain),
		}
		if ddnsHash != "" {
			if ddnsBytes, err := server.ReadEncryptedFile(server.DdnsPath(ddnsHash)); err == nil && len(ddnsBytes) > 0 {
				payload["ddns_content"] = base64.StdEncoding.EncodeToString(ddnsBytes)
			}
		}
		writeJSON(w, http.StatusOK, payload)
	}
}

func HandleDDNS(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		domain := chi.URLParam(r, "domain")
		var ddnsHash string
		err := server.DB.QueryRow("SELECT ddns_hash FROM dns_records WHERE domain = ?", domain).Scan(&ddnsHash)
		if err == nil && ddnsHash != "" {
			filePath := server.DdnsPath(ddnsHash)
			if _, err := os.Stat(filePath); err == nil {
				raw, readErr := server.ReadEncryptedFile(filePath)
				if readErr == nil {
					w.Header().Set("Content-Type", "application/octet-stream")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(raw)
					return
				}
				return
			}
		}
		writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "DDNS file not found"})
	}
}

func HandleContract(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		contractID := chi.URLParam(r, "contract_id")
		if !isValidUUID(contractID) {
			writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Contract not found"})
			return
		}
		contractPath := filepath.Join(server.FilesDir, "contracts", contractID+".contract")
		if _, err := os.Stat(contractPath); err == nil {
			raw, err := server.ReadEncryptedFile(contractPath)
			if err != nil {
				writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Contract not found"})
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(raw)
			return
		}
		var contentB64 string
		err := server.DB.QueryRow("SELECT contract_content FROM contracts WHERE contract_id = ?", contractID).Scan(&contentB64)
		if err == nil && contentB64 != "" {
			data, err := base64.StdEncoding.DecodeString(contentB64)
			if err != nil {
				writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Contract not found"})
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
			return
		}
		writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Contract not found"})
	}
}

func HandleVoucher(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		voucherID := chi.URLParam(r, "voucher_id")
		if !isValidUUID(voucherID) {
			writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Voucher not found"})
			return
		}
		voucherPath := filepath.Join(server.FilesDir, "vouchers", voucherID+".hps")
		if _, err := os.Stat(voucherPath); err == nil {
			accept := r.Header.Get("Accept")
			if strings.Contains(accept, "text/html") {
				raw, err := server.ReadVoucherFile(voucherPath)
				if err != nil {
					writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Voucher not found"})
					return
				}
				var voucher map[string]any
				if err := json.Unmarshal(raw, &voucher); err != nil {
					voucher = core.ParseHpsVoucherHsyst(string(raw))
				}
				if voucher == nil {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(raw)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(core.RenderVoucherHTML(voucher)))
				return
			}
			w.Header().Set("Content-Type", "application/hps-voucher")
			raw, err := server.ReadVoucherFile(voucherPath)
			if err != nil {
				writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Voucher not found"})
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(raw)
			return
		}
		var payloadText, issuerSig, ownerSig string
		err := server.DB.QueryRow(`SELECT payload, issuer_signature, owner_signature FROM hps_vouchers
			WHERE voucher_id = ?`, voucherID).Scan(&payloadText, &issuerSig, &ownerSig)
		if err == nil {
			var payload map[string]any
			if err := json.Unmarshal([]byte(payloadText), &payload); err != nil {
				writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Voucher not found"})
				return
			}
			voucher := map[string]any{
				"voucher_type": "HPS",
				"payload":      payload,
				"signatures": map[string]any{
					"issuer": issuerSig,
					"owner":  ownerSig,
				},
			}
			core.AttachVoucherIntegrity(voucher)
			accept := r.Header.Get("Accept")
			if strings.Contains(accept, "text/html") {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(core.RenderVoucherHTML(voucher)))
				return
			}
			w.Header().Set("Content-Type", "application/hps-voucher")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(core.FormatHpsVoucherHsyst(voucher)))
			return
		}
		writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Voucher not found"})
	}
}

var uuidPattern = regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")

func isValidUUID(value string) bool {
	return uuidPattern.MatchString(strings.TrimSpace(value))
}

func HandleSyncContent(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		q := r.URL.Query()
		limit := parseInt(q.Get("limit"), 100)
		offset := parseInt(q.Get("offset"), 0)
		since := parseFloat(q.Get("since"), 0)
		contentHash := q.Get("content_hash")

		var rows *sql.Rows
		var err error
		if contentHash != "" {
			rows, err = server.DB.Query(`SELECT content_hash, title, description, mime_type, size, username,
				signature, public_key, verified, replication_count, timestamp, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at FROM content WHERE content_hash = ?`, contentHash)
		} else if since > 0 {
			rows, err = server.DB.Query(`SELECT content_hash, title, description, mime_type, size, username,
				signature, public_key, verified, replication_count, timestamp, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at FROM content
				WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`, since, limit, offset)
		} else {
			rows, err = server.DB.Query(`SELECT content_hash, title, description, mime_type, size, username,
				signature, public_key, verified, replication_count, timestamp, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at FROM content
				ORDER BY replication_count DESC, last_accessed DESC LIMIT ? OFFSET ?`, limit, offset)
		}
		if err != nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		var out []jsonResponse
		for rows.Next() {
			var contentHash, title, description, mimeType, username, signature, publicKey, issuerServer, issuerPublicKey, issuerContractID string
			var size int64
			var verified, replication int
			var timestamp, issuerIssuedAt float64
			if err := rows.Scan(&contentHash, &title, &description, &mimeType, &size, &username, &signature, &publicKey, &verified, &replication, &timestamp, &issuerServer, &issuerPublicKey, &issuerContractID, &issuerIssuedAt); err == nil {
				if !shouldExposeSyncRecord(server, issuerServer) {
					continue
				}
				out = append(out, jsonResponse{
					"content_hash":       contentHash,
					"title":              title,
					"description":        description,
					"mime_type":          mimeType,
					"size":               size,
					"username":           username,
					"signature":          signature,
					"public_key":         publicKey,
					"verified":           verified != 0,
					"replication_count":  replication,
					"timestamp":          timestamp,
					"issuer_server":      issuerServer,
					"issuer_public_key":  issuerPublicKey,
					"issuer_contract_id": issuerContractID,
					"issuer_issued_at":   issuerIssuedAt,
				})
			}
		}
		rows.Close()
		for _, item := range out {
			item["contracts"] = syncContractsForContent(server, fmt.Sprint(item["content_hash"]))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func syncContractsForContent(server *core.Server, contentHash string) []jsonResponse {
	contentHash = strings.TrimSpace(contentHash)
	if server == nil || contentHash == "" {
		return nil
	}
	rows, err := server.DB.Query(`SELECT contract_id, action_type, COALESCE(domain, ''), username, signature, timestamp, verified
		FROM contracts WHERE content_hash = ? ORDER BY timestamp DESC`, contentHash)
	if err != nil {
		return nil
	}
	type contractRow struct {
		contractID string
		actionType string
		domain     string
		username   string
		signature  string
		timestamp  float64
		verified   int
	}
	pendingRows := []contractRow{}
	for rows.Next() {
		var row contractRow
		if rows.Scan(&row.contractID, &row.actionType, &row.domain, &row.username, &row.signature, &row.timestamp, &row.verified) != nil {
			continue
		}
		pendingRows = append(pendingRows, row)
	}
	rows.Close()
	contracts := []jsonResponse{}
	for _, row := range pendingRows {
		contractText := ""
		verified := row.verified != 0
		if contractBytes := server.GetContractBytes(row.contractID); len(contractBytes) > 0 {
			contractText = string(contractBytes)
			if valid, _, info := core.ValidateContractStructure(contractBytes); valid && info != nil {
				publicKey := core.ExtractContractDetail(info, "PUBLIC_KEY")
				if publicKey == "" {
					publicKey = server.GetRegisteredPublicKey(info.User)
				}
				verified = server.VerifyContractSignature(contractBytes, info.User, info.Signature, publicKey)
			} else {
				verified = false
			}
		}
		contracts = append(contracts, jsonResponse{
			"contract_id":      row.contractID,
			"action_type":      row.actionType,
			"content_hash":     contentHash,
			"domain":           row.domain,
			"username":         row.username,
			"signature":        row.signature,
			"timestamp":        row.timestamp,
			"verified":         verified,
			"integrity_ok":     verified,
			"contract_content": contractText,
		})
	}
	return contracts
}

func syncContractsForDomain(server *core.Server, domain string) []jsonResponse {
	domain = strings.TrimSpace(domain)
	if server == nil || domain == "" {
		return nil
	}
	rows, err := server.DB.Query(`SELECT contract_id, action_type, COALESCE(content_hash, ''), username, signature, timestamp, verified
		FROM contracts WHERE domain = ? ORDER BY timestamp DESC`, domain)
	if err != nil {
		return nil
	}
	type contractRow struct {
		contractID  string
		actionType  string
		contentHash string
		username    string
		signature   string
		timestamp   float64
		verified    int
	}
	pendingRows := []contractRow{}
	for rows.Next() {
		var row contractRow
		if rows.Scan(&row.contractID, &row.actionType, &row.contentHash, &row.username, &row.signature, &row.timestamp, &row.verified) != nil {
			continue
		}
		pendingRows = append(pendingRows, row)
	}
	rows.Close()
	contracts := []jsonResponse{}
	for _, row := range pendingRows {
		contractText := ""
		verified := row.verified != 0
		if contractBytes := server.GetContractBytes(row.contractID); len(contractBytes) > 0 {
			contractText = string(contractBytes)
			if valid, _, info := core.ValidateContractStructure(contractBytes); valid && info != nil {
				publicKey := core.ExtractContractDetail(info, "PUBLIC_KEY")
				if publicKey == "" {
					publicKey = server.GetRegisteredPublicKey(info.User)
				}
				verified = server.VerifyContractSignature(contractBytes, info.User, info.Signature, publicKey)
			} else {
				verified = false
			}
		}
		contracts = append(contracts, jsonResponse{
			"contract_id":      row.contractID,
			"action_type":      row.actionType,
			"content_hash":     row.contentHash,
			"domain":           domain,
			"username":         row.username,
			"signature":        row.signature,
			"timestamp":        row.timestamp,
			"verified":         verified,
			"integrity_ok":     verified,
			"contract_content": contractText,
		})
	}
	return contracts
}

func HandleSyncDNS(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		since := parseFloat(r.URL.Query().Get("since"), 0)
		domainFilter := strings.TrimSpace(r.URL.Query().Get("domain"))
		var rows *sql.Rows
		var err error
		if domainFilter != "" {
			rows, err = server.DB.Query(`SELECT domain, content_hash, username, original_owner, signature, verified, last_resolved, timestamp, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at
				FROM dns_records WHERE domain = ? ORDER BY timestamp DESC`, domainFilter)
		} else if since > 0 {
			rows, err = server.DB.Query(`SELECT domain, content_hash, username, original_owner, signature, verified, last_resolved, timestamp, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at
				FROM dns_records WHERE timestamp > ? ORDER BY timestamp DESC`, since)
		} else {
			rows, err = server.DB.Query(`SELECT domain, content_hash, username, original_owner, signature, verified, last_resolved, timestamp, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at
				FROM dns_records ORDER BY last_resolved DESC`)
		}
		if err != nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		defer rows.Close()
		var out []jsonResponse
		for rows.Next() {
			var domain, contentHash, username, originalOwner, signature, ddnsHash, issuerServer, issuerPublicKey, issuerContractID string
			var verified int
			var lastResolved, timestamp, issuerIssuedAt float64
			if err := rows.Scan(&domain, &contentHash, &username, &originalOwner, &signature, &verified, &lastResolved, &timestamp, &ddnsHash, &issuerServer, &issuerPublicKey, &issuerContractID, &issuerIssuedAt); err == nil {
				if !shouldExposeSyncRecord(server, issuerServer) {
					continue
				}
				item := jsonResponse{
					"domain":             domain,
					"content_hash":       contentHash,
					"username":           username,
					"original_owner":     originalOwner,
					"signature":          signature,
					"verified":           verified != 0,
					"last_resolved":      lastResolved,
					"timestamp":          timestamp,
					"ddns_hash":          ddnsHash,
					"issuer_server":      issuerServer,
					"issuer_public_key":  issuerPublicKey,
					"issuer_contract_id": issuerContractID,
					"issuer_issued_at":   issuerIssuedAt,
				}
				item["contracts"] = syncContractsForDomain(server, domain)
				out = append(out, item)
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func HandleSyncUsers(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		since := parseFloat(r.URL.Query().Get("since"), 0)
		var rows *sql.Rows
		var err error
		if since > 0 {
			rows, err = server.DB.Query(`SELECT r.username, r.reputation, r.last_updated, r.client_identifier, r.violation_count, COALESCE(u.public_key, '')
				FROM user_reputations r LEFT JOIN users u ON u.username = r.username
				WHERE r.last_updated > ? ORDER BY r.reputation DESC`, since)
		} else {
			rows, err = server.DB.Query(`SELECT r.username, r.reputation, r.last_updated, r.client_identifier, r.violation_count, COALESCE(u.public_key, '')
				FROM user_reputations r LEFT JOIN users u ON u.username = r.username
				ORDER BY r.reputation DESC`)
		}
		if err != nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		defer rows.Close()
		var out []jsonResponse
		for rows.Next() {
			var username, clientID, publicKey string
			var reputation, violationCount int
			var lastUpdated float64
			if err := rows.Scan(&username, &reputation, &lastUpdated, &clientID, &violationCount, &publicKey); err == nil {
				out = append(out, jsonResponse{
					"username":          username,
					"public_key":        publicKey,
					"reputation":        reputation,
					"last_updated":      lastUpdated,
					"client_identifier": clientID,
					"violation_count":   violationCount,
				})
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func HandleSyncContracts(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		q := r.URL.Query()
		since := parseFloat(q.Get("since"), 0)
		limit := parseInt(q.Get("limit"), 100)
		offset := parseInt(q.Get("offset"), 0)
		contractType := q.Get("type")
		contractID := strings.TrimSpace(q.Get("contract_id"))

		var rows *sql.Rows
		var err error
		if contractID != "" {
			rows, err = server.DB.Query(`SELECT contract_id, action_type, content_hash, domain, username,
				signature, timestamp, verified, contract_content
				FROM contracts WHERE contract_id = ? LIMIT 1`, contractID)
		} else if contractType != "" {
			if since > 0 {
				rows, err = server.DB.Query(`SELECT contract_id, action_type, content_hash, domain, username,
					signature, timestamp, verified, contract_content
					FROM contracts WHERE action_type = ? AND timestamp > ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
					contractType, since, limit, offset)
			} else {
				rows, err = server.DB.Query(`SELECT contract_id, action_type, content_hash, domain, username,
					signature, timestamp, verified, contract_content
					FROM contracts WHERE action_type = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
					contractType, limit, offset)
			}
		} else if since > 0 {
			rows, err = server.DB.Query(`SELECT contract_id, action_type, content_hash, domain, username,
				signature, timestamp, verified, contract_content
				FROM contracts WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
				since, limit, offset)
		} else {
			rows, err = server.DB.Query(`SELECT contract_id, action_type, content_hash, domain, username,
				signature, timestamp, verified, contract_content
				FROM contracts ORDER BY timestamp DESC LIMIT ? OFFSET ?`,
				limit, offset)
		}
		if err != nil {
			writeJSON(w, http.StatusOK, []any{})
			return
		}
		defer rows.Close()
		var out []jsonResponse
		for rows.Next() {
			var contractID, actionType, contentHash, domain, username, signature, contractContent string
			var timestamp float64
			var verified int
			if err := rows.Scan(&contractID, &actionType, &contentHash, &domain, &username, &signature, &timestamp, &verified, &contractContent); err == nil {
				if core.ShouldHideReplicatedContract(username, verified != 0) {
					continue
				}
				out = append(out, jsonResponse{
					"contract_id":      contractID,
					"action_type":      actionType,
					"content_hash":     nullIfEmpty(contentHash),
					"domain":           nullIfEmpty(domain),
					"username":         username,
					"signature":        signature,
					"timestamp":        timestamp,
					"verified":         verified != 0,
					"contract_content": contractContent,
				})
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func parseInt(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func parseFloat(raw string, fallback float64) float64 {
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return v
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		if t == nil {
			return ""
		}
		return fmt.Sprint(t)
	}
}

func asInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		i, _ := strconv.Atoi(t)
		return i
	default:
		return 0
	}
}

func asFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func shouldExposeSyncRecord(server *core.Server, issuerServer string) bool {
	if server == nil {
		return false
	}
	issuerServer = strings.TrimSpace(issuerServer)
	if issuerServer == "" {
		return true
	}
	return core.MessageServerAddressesEqual(issuerServer, server.Address, server.BindAddress)
}

func HandleEconomyReport(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		writeJSON(w, http.StatusOK, server.BuildEconomyReport())
	}
}

func HandleExchangeValidate(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Invalid JSON"})
			return
		}
		voucherIDs := toStringSlice(data["voucher_ids"])
		targetServer := strings.TrimSpace(asString(data["target_server"]))
		clientSignature := asString(data["client_signature"])
		clientPublicKey := asString(data["client_public_key"])
		requestID := asString(data["request_id"])
		timestamp := asFloat(data["timestamp"])
		if len(voucherIDs) == 0 || targetServer == "" || clientSignature == "" || clientPublicKey == "" || requestID == "" {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Missing exchange fields"})
			return
		}
		if math.Abs((float64(time.Now().UnixNano())/1e9)-timestamp) > 600 {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Timestamp out of range"})
			return
		}
		type voucherRow struct {
			id         string
			payloadRaw string
			payload    map[string]any
			issuerSig  string
			ownerSig   string
		}
		var vouchers []voucherRow
		for _, voucherID := range voucherIDs {
			var payloadText, issuerSig, ownerSig, status string
			var invalidated int
			err := server.DB.QueryRow(`SELECT payload, issuer_signature, owner_signature, status, invalidated
				FROM hps_vouchers WHERE voucher_id = ?`, voucherID).Scan(&payloadText, &issuerSig, &ownerSig, &status, &invalidated)
			if err != nil {
				writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Voucher " + voucherID + " not found"})
				return
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(payloadText), &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Voucher " + voucherID + " not found"})
				return
			}
			if !server.IsLocalIssuer(asString(payload["issuer"])) {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Issuer mismatch"})
				return
			}
			if status != "valid" {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Voucher " + voucherID + " not available"})
				return
			}
			if invalidated != 0 {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Voucher " + voucherID + " invalidated"})
				return
			}
			vouchers = append(vouchers, voucherRow{voucherID, payloadText, payload, issuerSig, ownerSig})
		}
		owner := asString(vouchers[0].payload["owner"])
		ownerKey := asString(vouchers[0].payload["owner_public_key"])
		issuerForProof := asString(vouchers[0].payload["issuer"])
		if ownerKey != clientPublicKey {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Owner key mismatch"})
			return
		}
		for _, v := range vouchers {
			if asString(v.payload["owner"]) != owner {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Voucher owner mismatch"})
				return
			}
			issuerKey := asString(v.payload["issuer_public_key"])
			if !core.VerifyPayloadSignatureFlexible(v.payload, v.payloadRaw, v.issuerSig, issuerKey) {
				writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Issuer signature invalid"})
				return
			}
		}
		sortedIDs := append([]string{}, voucherIDs...)
		sort.Strings(sortedIDs)
		proofPayload := map[string]any{
			"issuer":        issuerForProof,
			"target_server": targetServer,
			"voucher_ids":   sortedIDs,
			"timestamp":     timestamp,
		}
		if !core.VerifyPayloadSignature(proofPayload, clientSignature, clientPublicKey) {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Client proof invalid"})
			return
		}
		sessionID := "exchange-" + requestID
		ok, totalValue, errMsg := server.ReserveVouchersForSession(owner, sessionID, voucherIDs)
		if !ok {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": errMsg})
			return
		}
		tokenID := core.NewUUID()
		expiresAt := float64(time.Now().UnixNano())/1e9 + float64(server.ExchangeQuoteTTL)
		tokenPayload := map[string]any{
			"token_id":          tokenID,
			"issuer":            server.Address,
			"issuer_public_key": base64.StdEncoding.EncodeToString(server.PublicKeyPEM),
			"target_server":     targetServer,
			"voucher_ids":       sortedIDs,
			"owner":             owner,
			"total_value":       totalValue,
			"session_id":        sessionID,
			"issued_at":         float64(time.Now().UnixNano()) / 1e9,
			"expires_at":        expiresAt,
		}
		tokenSignature := server.SignPayload(tokenPayload)
		server.ExchangeTokens[tokenID] = map[string]any{
			"payload":     tokenPayload,
			"signature":   tokenSignature,
			"session_id":  sessionID,
			"voucher_ids": voucherIDs,
			"expires_at":  expiresAt,
		}
		ownerKeyContractID := server.SaveServerContract("hps_exchange_owner_key", []core.ContractDetail{
			{Key: "ISSUER", Value: server.Address},
			{Key: "OWNER", Value: owner},
			{Key: "OWNER_PUBLIC_KEY", Value: ownerKey},
			{Key: "TOKEN_ID", Value: tokenID},
			{Key: "TARGET_SERVER", Value: targetServer},
			{Key: "TIMESTAMP", Value: int(time.Now().Unix())},
		}, "")
		contractID := server.SaveServerContract("hps_exchange_reserved", []core.ContractDetail{
			{Key: "ISSUER", Value: server.Address},
			{Key: "TOKEN_ID", Value: tokenID},
			{Key: "OWNER", Value: owner},
			{Key: "TARGET_SERVER", Value: targetServer},
			{Key: "TOTAL_VALUE", Value: totalValue},
			{Key: "VOUCHERS", Value: core.CanonicalJSON(sortedIDs)},
		}, "")
		economyReport := server.BuildEconomyReport()
		writeJSON(w, http.StatusOK, jsonResponse{
			"success":               true,
			"token":                 tokenPayload,
			"signature":             tokenSignature,
			"economy_report":        economyReport,
			"contract_id":           contractID,
			"owner_key_contract_id": ownerKeyContractID,
		})
	}
}

func HandleExchangeConfirm(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Invalid JSON"})
			return
		}
		tokenPayload, _ := data["token"].(map[string]any)
		tokenSignature := asString(data["signature"])
		tokenID := asString(tokenPayload["token_id"])
		if tokenID == "" || tokenSignature == "" {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Missing token"})
			return
		}
		stored := server.ExchangeTokens[tokenID]
		if stored == nil {
			writeJSON(w, http.StatusNotFound, jsonResponse{"success": false, "error": "Token not found"})
			return
		}
		if asString(stored["signature"]) != tokenSignature {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Token signature mismatch"})
			return
		}
		storedPayload, _ := stored["payload"].(map[string]any)
		if core.CanonicalJSON(tokenPayload) != core.CanonicalJSON(storedPayload) {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Token payload mismatch"})
			return
		}
		nowTs := float64(time.Now().UnixNano()) / 1e9
		if nowTs > asFloat(stored["expires_at"]) {
			if sessionID := asString(stored["session_id"]); sessionID != "" {
				server.ReleaseVouchersForSession(sessionID)
			}
			delete(server.ExchangeTokens, tokenID)
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Token expired"})
			return
		}
		stored["confirmed_at"] = nowTs
		// Keep the source vouchers reserved until the target server actually finalizes the exchange.
		stored["expires_at"] = nowTs + 3600
		contractID := server.SaveServerContract("hps_exchange_out", []core.ContractDetail{
			{Key: "ISSUER", Value: server.Address},
			{Key: "TOKEN_ID", Value: tokenID},
			{Key: "OWNER", Value: asString(tokenPayload["owner"])},
			{Key: "TARGET_SERVER", Value: asString(tokenPayload["target_server"])},
			{Key: "TOTAL_VALUE", Value: asInt(tokenPayload["total_value"])},
			{Key: "VOUCHERS", Value: core.CanonicalJSON(toStringSlice(tokenPayload["voucher_ids"]))},
		}, "")
		responsePayload := map[string]any{
			"token_id":     tokenID,
			"issuer":       server.Address,
			"contract_id":  contractID,
			"confirmed_at": nowTs,
			"voucher_ids":  tokenPayload["voucher_ids"],
			"total_value":  asInt(tokenPayload["total_value"]),
		}
		responseSignature := server.SignPayload(responsePayload)
		writeJSON(w, http.StatusOK, jsonResponse{"success": true, "payload": responsePayload, "signature": responseSignature})
	}
}

func HandleExchangeComplete(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Invalid JSON"})
			return
		}

		tokenID := strings.TrimSpace(asString(data["token_id"]))
		transferID := strings.TrimSpace(asString(data["transfer_id"]))
		stored := server.ExchangeTokens[tokenID]
		if tokenID == "" || stored == nil {
			writeJSON(w, http.StatusOK, jsonResponse{"success": true, "already_completed": true})
			return
		}

		tokenPayload, _ := stored["payload"].(map[string]any)
		sessionID := asString(stored["session_id"])
		voucherIDs := toStringSlice(tokenPayload["voucher_ids"])
		lineageRoots := []string{}
		seenRoots := map[string]bool{}
		for _, voucherID := range voucherIDs {
			info := server.GetVoucherAuditInfo(voucherID)
			if info == nil {
				continue
			}
			rootID := strings.TrimSpace(asString(info["lineage_root_voucher_id"]))
			if rootID == "" {
				rootID = voucherID
			}
			if rootID == "" || seenRoots[rootID] {
				continue
			}
			seenRoots[rootID] = true
			lineageRoots = append(lineageRoots, rootID)
		}
		if sessionID != "" {
			server.MarkVouchersSpent(sessionID)
		}
		delete(server.ExchangeTokens, tokenID)

		confirmedAt := float64(time.Now().UnixNano()) / 1e9
		owner := asString(tokenPayload["owner"])
		targetServer := asString(tokenPayload["target_server"])

		server.SaveServerContract("hps_exchange_complete", []core.ContractDetail{
			{Key: "TOKEN_ID", Value: tokenID},
			{Key: "TRANSFER_ID", Value: transferID},
			{Key: "OWNER", Value: owner},
			{Key: "TARGET_SERVER", Value: targetServer},
			{Key: "TOTAL_VALUE", Value: asInt(tokenPayload["total_value"])},
			{Key: "VOUCHERS", Value: core.CanonicalJSON(voucherIDs)},
		}, tokenID)
		server.SaveServerContract("voucher_lineage_close", []core.ContractDetail{
			{Key: "TOKEN_ID", Value: tokenID},
			{Key: "OWNER", Value: owner},
			{Key: "TARGET_SERVER", Value: targetServer},
			{Key: "SOURCE_VOUCHERS", Value: core.CanonicalJSON(voucherIDs)},
			{Key: "LINEAGE_ROOTS", Value: core.CanonicalJSON(lineageRoots)},
			{Key: "REASON", Value: "exchange_complete"},
		}, tokenID)
		lineageCloseContractID := ""
		lineageCloseContractB64 := ""
		_ = server.DB.QueryRow(`SELECT contract_id, contract_content FROM contracts
			WHERE action_type = ? AND content_hash = ?
			ORDER BY timestamp DESC LIMIT 1`, "voucher_lineage_close", tokenID).
			Scan(&lineageCloseContractID, &lineageCloseContractB64)

		if server.UserEventEmitter != nil {
			server.UserEventEmitter(owner, "hps_vouchers_ghosted", map[string]any{
				"issuer":        server.Address,
				"voucher_ids":   voucherIDs,
				"token_id":      tokenID,
				"transfer_id":   transferID,
				"target_server": targetServer,
				"reason":        "exchange_out",
				"confirmed_at":  confirmedAt,
			})
		}

		writeJSON(w, http.StatusOK, jsonResponse{
			"success":                   true,
			"confirmed_at":              confirmedAt,
			"lineage_close_contract_id": lineageCloseContractID,
			"lineage_close_contract":    lineageCloseContractB64,
		})
	}
}

func HandleExchangeRelay(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Invalid JSON"})
			return
		}
		username := strings.TrimSpace(asString(data["username"]))
		event := strings.TrimSpace(asString(data["event"]))
		payload, _ := data["payload"].(map[string]any)
		if username == "" || event == "" || payload == nil {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Missing relay fields"})
			return
		}
		if server.UserEventEmitter == nil {
			writeJSON(w, http.StatusServiceUnavailable, jsonResponse{"success": false, "error": "User event emitter unavailable"})
			return
		}
		server.UserEventEmitter(username, event, payload)
		writeJSON(w, http.StatusOK, jsonResponse{"success": true})
	}
}

func HandleExchangeRollback(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Invalid JSON"})
			return
		}

		tokenID := strings.TrimSpace(asString(data["token_id"]))
		transferID := strings.TrimSpace(asString(data["transfer_id"]))
		owner := strings.TrimSpace(asString(data["owner"]))
		reason := strings.TrimSpace(asString(data["reason"]))
		totalValue := asInt(data["total_value"])
		if tokenID == "" || owner == "" || totalValue <= 0 {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Missing rollback fields"})
			return
		}

		if stored := server.ExchangeTokens[tokenID]; stored != nil {
			if sessionID := asString(stored["session_id"]); sessionID != "" {
				server.ReleaseVouchersForSession(sessionID)
			}
			delete(server.ExchangeTokens, tokenID)
			writeJSON(w, http.StatusOK, jsonResponse{"success": true, "released_reserved": true})
			return
		}

		var existing int
		_ = server.DB.QueryRow(`SELECT COUNT(1) FROM contracts WHERE action_type = ? AND content_hash = ?`, "hps_exchange_revert", tokenID).Scan(&existing)
		if existing > 0 {
			writeJSON(w, http.StatusOK, jsonResponse{"success": true, "already_reverted": true})
			return
		}

		ownerKey := server.GetUserPublicKey(owner)
		if ownerKey == "" {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Owner public key not found"})
			return
		}

		rollbackReason := reason
		if rollbackReason == "" {
			rollbackReason = "exchange_failed"
		}
		offer := server.CreateVoucherOffer(
			owner,
			ownerKey,
			totalValue,
			"exchange_revert:"+tokenID,
			nil,
			map[string]any{
				"type":        "exchange_revert",
				"token_id":    tokenID,
				"transfer_id": transferID,
				"reason":      rollbackReason,
			},
			"",
		)

		contractID := server.SaveServerContract("hps_exchange_revert", []core.ContractDetail{
			{Key: "TOKEN_ID", Value: tokenID},
			{Key: "TRANSFER_ID", Value: transferID},
			{Key: "OWNER", Value: owner},
			{Key: "VALUE", Value: totalValue},
			{Key: "REASON", Value: rollbackReason},
			{Key: "REFUND_VOUCHER_ID", Value: asString(offer["voucher_id"])},
		}, tokenID)

		if server.UserEventEmitter != nil {
			server.UserEventEmitter(owner, "hps_voucher_offer", offer)
		}

		writeJSON(w, http.StatusOK, jsonResponse{
			"success":     true,
			"contract_id": contractID,
			"voucher_id":  asString(offer["voucher_id"]),
		})
	}
}

func HandleVoucherAudit(_ *core.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		server := r.Context().Value("server").(*core.Server)
		var data map[string]any
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Invalid JSON"})
			return
		}
		voucherIDs := toStringSlice(data["voucher_ids"])
		if len(voucherIDs) == 0 {
			writeJSON(w, http.StatusBadRequest, jsonResponse{"success": false, "error": "Missing voucher IDs"})
			return
		}
		var results []jsonResponse
		for _, voucherID := range voucherIDs {
			info := server.GetVoucherAuditInfo(voucherID)
			if info != nil {
				info["issuer_server"] = server.Address
				info["issuer_server_key"] = base64.StdEncoding.EncodeToString(server.PublicKeyPEM)
				results = append(results, info)
			}
		}
		writeJSON(w, http.StatusOK, jsonResponse{"success": true, "vouchers": results})
	}
}

func toStringSlice(value any) []string {
	var out []string
	switch v := value.(type) {
	case []string:
		return append(out, v...)
	case []any:
		for _, item := range v {
			out = append(out, asString(item))
		}
	case nil:
		return nil
	default:
		return []string{asString(v)}
	}
	return out
}
