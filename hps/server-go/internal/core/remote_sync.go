package core

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (s *Server) MakeRemoteRequestJSON(serverAddress, path, method string, data map[string]any) (bool, map[string]any, string) {
	serverAddress = strings.TrimSpace(serverAddress)
	if serverAddress == "" {
		return false, nil, "empty server address"
	}
	if !strings.HasPrefix(serverAddress, "http://") && !strings.HasPrefix(serverAddress, "https://") {
		serverAddress = "http://" + serverAddress
	}
	if method == "" {
		method = http.MethodGet
	}
	url := strings.TrimRight(serverAddress, "/") + path
	var body io.Reader
	var bodyBytes []byte
	if data != nil {
		bodyBytes, _ = json.Marshal(data)
		body = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return false, nil, err.Error()
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	s.attachInterServerAuthHeaders(req, bodyBytes)
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return false, nil, err.Error()
		}
		switch v := decoded.(type) {
		case map[string]any:
			out = v
		case []any:
			out = map[string]any{"items": v}
		default:
			out = map[string]any{}
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if msg, ok := out["error"].(string); ok && strings.TrimSpace(msg) != "" {
			return false, out, msg
		}
		return false, out, "http status " + resp.Status
	}
	s.RememberKnownServer(serverAddress)
	return true, out, ""
}

func (s *Server) MakeRemoteRequestBytes(serverAddress, path, method string) (bool, []byte, string) {
	serverAddress = strings.TrimSpace(serverAddress)
	if serverAddress == "" {
		return false, nil, "empty server address"
	}
	if !strings.HasPrefix(serverAddress, "http://") && !strings.HasPrefix(serverAddress, "https://") {
		serverAddress = "http://" + serverAddress
	}
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, strings.TrimRight(serverAddress, "/")+path, nil)
	if err != nil {
		return false, nil, err.Error()
	}
	s.attachInterServerAuthHeaders(req, nil)
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false, nil, "http status " + resp.Status
	}
	s.RememberKnownServer(serverAddress)
	return true, raw, ""
}

func (s *Server) RememberKnownServer(serverAddress string) {
	serverAddress = strings.TrimSpace(serverAddress)
	serverAddress = strings.TrimRight(serverAddress, "/")
	serverAddress = strings.TrimPrefix(serverAddress, "http://")
	serverAddress = strings.TrimPrefix(serverAddress, "https://")
	serverAddress = strings.TrimSpace(serverAddress)
	if serverAddress == "" {
		return
	}
	nowTs := float64(time.Now().UnixNano()) / 1e9
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO known_servers
		(address, added_date, last_connected, is_active)
		VALUES (?, COALESCE((SELECT added_date FROM known_servers WHERE address = ?), ?), ?, 1)`,
		serverAddress, serverAddress, nowTs, nowTs)
}

func (s *Server) attachInterServerAuthHeaders(req *http.Request, body []byte) {
	if s == nil || req == nil {
		return
	}
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])
	timestamp := float64(time.Now().UnixNano()) / 1e9
	nonce := newUUID()
	payload := map[string]any{
		"issuer":      s.Address,
		"target":      req.URL.Host,
		"method":      strings.ToUpper(req.Method),
		"path":        req.URL.Path,
		"query":       req.URL.RawQuery,
		"timestamp":   timestamp,
		"nonce":       nonce,
		"body_sha256": bodyHash,
	}
	signature := s.SignPayload(payload)
	if signature == "" {
		return
	}
	req.Header.Set("X-HPS-Server-Address", s.Address)
	req.Header.Set("X-HPS-Timestamp", strconv.FormatFloat(timestamp, 'f', -1, 64))
	req.Header.Set("X-HPS-Nonce", nonce)
	req.Header.Set("X-HPS-Signature", signature)
	req.Header.Set("X-HPS-Body-SHA256", bodyHash)
	req.Header.Set("X-HPS-Server-Public-Key", base64.StdEncoding.EncodeToString(s.PublicKeyPEM))
}

func (s *Server) VerifyEconomyReport(report map[string]any) bool {
	if report == nil {
		return false
	}
	payload, ok := report["payload"].(map[string]any)
	if !ok || payload == nil {
		return false
	}
	signature, _ := report["signature"].(string)
	issuerKey, _ := payload["issuer_public_key"].(string)
	if signature == "" || issuerKey == "" {
		return false
	}
	if VerifyPayloadSignature(payload, signature, issuerKey) {
		return true
	}
	payloadCanonical, _ := report["payload_canonical"].(string)
	return VerifyRawTextSignature(payloadCanonical, signature, issuerKey)
}

func (s *Server) SyncWithServer(serverAddress string) error {
	if strings.TrimSpace(serverAddress) == "" {
		return errors.New("empty server")
	}
	okInfo, remoteInfo, errMsg := s.MakeRemoteRequestJSON(serverAddress, "/server_info", http.MethodGet, nil)
	if !okInfo {
		_, _ = s.DB.Exec(`INSERT OR REPLACE INTO server_sync_history
			(server_address, last_sync, sync_type, items_count, success)
			VALUES (?, ?, ?, ?, 0)`, serverAddress, now(), "full", 0)
		return errors.New(errMsg)
	}
	remoteServerID := asString(remoteInfo["server_id"])
	remotePublicKey := asString(remoteInfo["public_key"])
	nowTs := now()
	if remoteServerID != "" {
		_, _ = s.DB.Exec(`INSERT OR REPLACE INTO server_nodes
			(server_id, address, public_key, last_seen, is_active, reputation, sync_priority)
			VALUES (?, ?, ?, ?, 1, COALESCE((SELECT reputation FROM server_nodes WHERE address = ?), 100), 1)`,
			remoteServerID, serverAddress, remotePublicKey, nowTs, serverAddress)
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO known_servers (address, added_date, last_connected, is_active)
		VALUES (?, COALESCE((SELECT added_date FROM known_servers WHERE address = ?), ?), ?, 1)`,
		serverAddress, serverAddress, nowTs, nowTs)

	total := 0
	if c, err := s.SyncContentWithServer(serverAddress); err == nil {
		total += c
	}
	if c, err := s.SyncDNSWithServer(serverAddress); err == nil {
		total += c
	}
	if c, err := s.SyncUsersWithServer(serverAddress); err == nil {
		total += c
	}
	if c, err := s.SyncContractsWithServer(serverAddress); err == nil {
		total += c
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO server_sync_history
		(server_address, last_sync, sync_type, items_count, success)
		VALUES (?, ?, ?, ?, 1)`, serverAddress, now(), "full", total)
	return nil
}

func (s *Server) SyncContentWithServer(serverAddress string) (int, error) {
	since := s.getLastSyncFor(serverAddress, "content")
	path := "/sync/content?limit=1000"
	if since > 0 {
		path += "&since=" + strconv.FormatFloat(since, 'f', -1, 64)
	}
	ok, payload, errMsg := s.MakeRemoteRequestJSON(serverAddress, path, http.MethodGet, nil)
	if !ok {
		return 0, errors.New(errMsg)
	}
	items := castSlice(payload["items"])
	count := 0
	for _, item := range items {
		row := castMap(item)
		contentHash := asString(row["content_hash"])
		if contentHash == "" {
			continue
		}
		title := asString(row["title"])
		remoteUsername := asString(row["username"])
		if strings.HasPrefix(title, "(HPS!api)") {
			s.syncRemoteAPIAppUpdate(title, remoteUsername, contentHash)
		}
		filePath := s.ContentPath(contentHash)
		downloadedSize := 0
		if _, statErr := os.Stat(filePath); statErr != nil {
			okRaw, contentBytes, _ := s.MakeRemoteRequestBytes(serverAddress, "/content/"+url.PathEscape(contentHash), http.MethodGet)
			if !okRaw || len(contentBytes) == 0 {
				continue
			}
			if writeErr := s.WriteEncryptedFile(filePath, contentBytes); writeErr != nil {
				continue
			}
			downloadedSize = len(contentBytes)
		}
		size := asInt(row["size"])
		if size <= 0 {
			size = downloadedSize
		}
		_, _ = s.DB.Exec(`INSERT OR REPLACE INTO content
			(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, replication_count, last_accessed, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			contentHash, title, asString(row["description"]), asString(row["mime_type"]), size,
			remoteUsername, asString(row["signature"]), asString(row["public_key"]), asFloat(row["timestamp"]),
			filePath, boolToInt(asBool(row["verified"])), asInt(row["replication_count"]), now(),
			asString(row["issuer_server"]), asString(row["issuer_public_key"]), asString(row["issuer_contract_id"]), asFloat(row["issuer_issued_at"]))
		if contracts := castSlice(row["contracts"]); len(contracts) > 0 {
			s.UpsertContractsFromSyncPayload(serverAddress, map[string]any{"items": contracts})
		}
		count++
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO server_sync_history
		(server_address, last_sync, sync_type, items_count, success)
		VALUES (?, ?, ?, ?, 1)`, serverAddress, now(), "content", count)
	return count, nil
}

func (s *Server) SyncDNSWithServer(serverAddress string) (int, error) {
	since := s.getLastSyncFor(serverAddress, "dns")
	path := "/sync/dns"
	if since > 0 {
		path += "?since=" + strconv.FormatFloat(since, 'f', -1, 64)
	}
	ok, payload, errMsg := s.MakeRemoteRequestJSON(serverAddress, path, http.MethodGet, nil)
	if !ok {
		return 0, errors.New(errMsg)
	}
	items := castSlice(payload["items"])
	count := 0
	for _, item := range items {
		row := castMap(item)
		domain := asString(row["domain"])
		if domain == "" {
			continue
		}
		ddnsHash := asString(row["ddns_hash"])
		if ddnsHash != "" {
			ddnsPath := s.DdnsPath(ddnsHash)
			if _, statErr := os.Stat(ddnsPath); statErr != nil {
				if okRaw, ddnsBytes, _ := s.MakeRemoteRequestBytes(serverAddress, "/ddns/"+url.PathEscape(domain), http.MethodGet); okRaw && len(ddnsBytes) > 0 {
					_ = s.WriteEncryptedFile(ddnsPath, ddnsBytes)
				}
			}
		}
		_, _ = s.DB.Exec(`INSERT OR REPLACE INTO dns_records
			(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			domain, asString(row["content_hash"]), asString(row["username"]), asString(row["original_owner"]),
			asFloat(row["timestamp"]), asString(row["signature"]), boolToInt(asBool(row["verified"])), now(), ddnsHash,
			asString(row["issuer_server"]), asString(row["issuer_public_key"]), asString(row["issuer_contract_id"]), asFloat(row["issuer_issued_at"]))
		if contracts := castSlice(row["contracts"]); len(contracts) > 0 {
			s.UpsertContractsFromSyncPayload(serverAddress, map[string]any{"items": contracts})
		}
		count++
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO server_sync_history
		(server_address, last_sync, sync_type, items_count, success)
		VALUES (?, ?, ?, ?, 1)`, serverAddress, now(), "dns", count)
	return count, nil
}

func (s *Server) SyncUsersWithServer(serverAddress string) (int, error) {
	since := s.getLastSyncFor(serverAddress, "users")
	path := "/sync/users"
	if since > 0 {
		path += "?since=" + strconv.FormatFloat(since, 'f', -1, 64)
	}
	ok, payload, errMsg := s.MakeRemoteRequestJSON(serverAddress, path, http.MethodGet, nil)
	if !ok {
		return 0, errors.New(errMsg)
	}
	items := castSlice(payload["items"])
	count := 0
	for _, item := range items {
		row := castMap(item)
		username := asString(row["username"])
		if username == "" {
			continue
		}
		reputation := asInt(row["reputation"])
		lastUpdated := asFloat(row["last_updated"])
		if lastUpdated <= 0 {
			lastUpdated = now()
		}
		clientID := asString(row["client_identifier"])
		publicKey := asString(row["public_key"])
		violationCount := asInt(row["violation_count"])
		_, _ = s.DB.Exec(`INSERT OR REPLACE INTO user_reputations
			(username, reputation, last_updated, client_identifier, violation_count)
			VALUES (?, ?, ?, ?, ?)`,
			username, reputation, lastUpdated, clientID, violationCount)
		_, _ = s.DB.Exec(`INSERT OR IGNORE INTO users
			(username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity)
			VALUES (?, '', '', ?, ?, ?, ?, ?)`,
			username, now(), now(), reputation, clientID, now())
		if strings.TrimSpace(publicKey) != "" {
			_, _ = s.DB.Exec(`UPDATE users SET reputation = ?, client_identifier = COALESCE(NULLIF(?, ''), client_identifier),
				public_key = CASE WHEN public_key = '' OR public_key = ? THEN ? ELSE public_key END
				WHERE username = ?`, reputation, clientID, PendingPublicKeyLabel, publicKey, username)
		} else {
			_, _ = s.DB.Exec(`UPDATE users SET reputation = ?, client_identifier = COALESCE(NULLIF(?, ''), client_identifier)
				WHERE username = ?`, reputation, clientID, username)
		}
		count++
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO server_sync_history
		(server_address, last_sync, sync_type, items_count, success)
		VALUES (?, ?, ?, ?, 1)`, serverAddress, now(), "users", count)
	return count, nil
}

func (s *Server) SyncContractsWithServer(serverAddress string) (int, error) {
	since := s.getLastSyncFor(serverAddress, "contracts")
	path := "/sync/contracts?limit=1000"
	if since > 0 {
		path += "&since=" + strconv.FormatFloat(since, 'f', -1, 64)
	}
	ok, payload, errMsg := s.MakeRemoteRequestJSON(serverAddress, path, http.MethodGet, nil)
	if !ok {
		return 0, errors.New(errMsg)
	}
	return s.UpsertContractsFromSyncPayload(serverAddress, payload), nil
}

func (s *Server) SyncContractWithServer(serverAddress, contractID string) (int, error) {
	path := "/sync/contracts?limit=1000"
	if strings.TrimSpace(contractID) != "" {
		path = "/sync/contracts?contract_id=" + contractID
	}
	ok, payload, errMsg := s.MakeRemoteRequestJSON(serverAddress, path, http.MethodGet, nil)
	if !ok {
		return 0, errors.New(errMsg)
	}
	return s.UpsertContractsFromSyncPayload(serverAddress, payload), nil
}

func (s *Server) listRemoteServersByPriority() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	appendAddress := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" || MessageServerAddressesEqual(addr, s.Address, s.BindAddress) {
			return
		}
		normalized := NormalizeMessageServerAddress(addr)
		if normalized == "" {
			return
		}
		if _, exists := seen[normalized]; exists {
			return
		}
		seen[normalized] = struct{}{}
		out = append(out, addr)
	}

	rows, err := s.DB.Query(`SELECT address FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC`, s.Address)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var addr string
			if rows.Scan(&addr) != nil {
				continue
			}
			appendAddress(addr)
		}
	}

	knownRows, err := s.DB.Query(`SELECT address FROM known_servers WHERE is_active = 1 ORDER BY last_connected DESC`)
	if err == nil {
		defer knownRows.Close()
		for knownRows.Next() {
			var addr string
			if knownRows.Scan(&addr) != nil {
				continue
			}
			appendAddress(addr)
		}
	}

	return out
}

func (s *Server) FetchContentFromKnownServers(contentHash string) bool {
	contentHash = strings.TrimSpace(contentHash)
	if contentHash == "" {
		return false
	}

	for _, serverAddr := range s.listRemoteServersByPriority() {
		okRaw, raw, _ := s.MakeRemoteRequestBytes(serverAddr, "/content/"+url.PathEscape(contentHash), http.MethodGet)
		if !okRaw || len(raw) == 0 {
			continue
		}
		filePath := s.ContentPath(contentHash)
		if err := s.WriteEncryptedFile(filePath, raw, 0o644); err != nil {
			continue
		}
		okMeta, payload, _ := s.MakeRemoteRequestJSON(serverAddr, "/sync/content?content_hash="+url.QueryEscape(contentHash), http.MethodGet, nil)
		items := []any{}
		if okMeta {
			items = castSlice(payload["items"])
			if len(items) > 0 {
				meta := castMap(items[0])
				_, _ = s.DB.Exec(`INSERT OR REPLACE INTO content
					(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, replication_count, last_accessed, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					contentHash,
					asString(meta["title"]),
					asString(meta["description"]),
					asString(meta["mime_type"]),
					asInt(meta["size"]),
					asString(meta["username"]),
					asString(meta["signature"]),
					asString(meta["public_key"]),
					asFloat(meta["timestamp"]),
					filePath,
					boolToInt(asBool(meta["verified"])),
					asInt(meta["replication_count"]),
					now(),
					asString(meta["issuer_server"]),
					asString(meta["issuer_public_key"]),
					asString(meta["issuer_contract_id"]),
					asFloat(meta["issuer_issued_at"]),
				)
				for _, contractItem := range castSlice(meta["contracts"]) {
					contractMeta := castMap(contractItem)
					contractID := asString(contractMeta["contract_id"])
					contractText := asString(contractMeta["contract_content"])
					if contractID == "" || contractText == "" {
						continue
					}
					contractBytes := []byte(contractText)
					valid, _, info := ValidateContractStructure(contractBytes)
					if !valid || info == nil {
						continue
					}
					publicKey := ExtractContractDetail(info, "PUBLIC_KEY")
					if publicKey == "" {
						publicKey = s.GetRegisteredPublicKey(info.User)
					}
					if !s.VerifyContractSignature(contractBytes, info.User, info.Signature, publicKey) {
						continue
					}
					domain := ExtractContractDetail(info, "DOMAIN")
					if domain == "" {
						domain = ExtractContractDetail(info, "DNAME")
					}
					if domain == "" {
						domain = asString(contractMeta["domain"])
					}
					contractPath := filepath.Join(s.FilesDir, "contracts", contractID+".contract")
					_ = s.WriteEncryptedFile(contractPath, contractBytes, 0o644)
					_, _ = s.DB.Exec(`INSERT OR REPLACE INTO contracts
						(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
						VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
						contractID,
						info.Action,
						contentHash,
						nullIfEmptyString(domain),
						info.User,
						info.Signature,
						asFloat(contractMeta["timestamp"]),
						1,
						base64.StdEncoding.EncodeToString(contractBytes),
					)
					_ = s.SaveContractArchiveByContract(contractID, contractBytes)
				}
				return true
			}
		}
		_ = os.Remove(filePath)
		if len(items) == 0 {
			continue
		}
	}

	return false
}

func (s *Server) UpsertContractsFromSyncPayload(serverAddress string, payload map[string]any) int {
	items := castSlice(payload["items"])
	count := 0
	for _, item := range items {
		row := castMap(item)
		contractID := asString(row["contract_id"])
		if contractID == "" {
			continue
		}
		actionType := asString(row["action_type"])
		contentHash := asString(row["content_hash"])
		domain := asString(row["domain"])
		username := asString(row["username"])
		contractContent := asString(row["contract_content"])
		verified := boolToInt(asBool(row["verified"]))
		var contractBytes []byte
		if contractContent != "" {
			raw, encoded := decodeReplicatedContractContent(contractContent)
			if len(raw) > 0 {
				contractBytes = raw
				if ok, _, info := ValidateContractStructure(raw); ok && info != nil {
					if info.Action != "" {
						actionType = info.Action
					}
					if info.User != "" {
						username = info.User
					}
					if info.Signature != "" {
						row["signature"] = info.Signature
					}
					if extractedHash := ExtractContractDetail(info, "FILE_HASH"); extractedHash != "" {
						contentHash = extractedHash
					} else if extractedHash := ExtractContractDetail(info, "CONTENT_HASH"); extractedHash != "" {
						contentHash = extractedHash
					}
					if extractedDomain := ExtractContractDetail(info, "DOMAIN"); extractedDomain != "" {
						domain = extractedDomain
					} else if extractedDomain := ExtractContractDetail(info, "DNAME"); extractedDomain != "" {
						domain = extractedDomain
					}
					publicKey := ExtractContractDetail(info, "PUBLIC_KEY")
					if publicKey == "" {
						publicKey = s.GetRegisteredPublicKey(username)
					}
					verified = boolToInt(s.VerifyContractSignature(raw, username, asString(row["signature"]), publicKey))
					if !encoded {
						contractContent = base64.StdEncoding.EncodeToString(raw)
					}
				} else {
					verified = 0
				}
			} else {
				verified = 0
			}
		}
		if IsForbiddenReplicatedContractUser(username) || !s.HasContractReplicationTarget(contractID, contentHash, domain) {
			continue
		}
		if contractContent == "" || verified == 0 {
			continue
		}
		_, _ = s.DB.Exec(`INSERT OR REPLACE INTO contracts
			(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			contractID, actionType, nullIfEmptyString(contentHash),
			nullIfEmptyString(domain), username, asString(row["signature"]),
			asFloat(row["timestamp"]), verified, contractContent)
		if len(contractBytes) > 0 {
			_ = s.SaveContractArchiveByContract(contractID, contractBytes)
		}
		count++
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO server_sync_history
		(server_address, last_sync, sync_type, items_count, success)
		VALUES (?, ?, ?, ?, 1)`, serverAddress, now(), "contracts", count)
	return count
}

func decodeReplicatedContractContent(raw string) ([]byte, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, false
	}
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw)); err == nil && len(decoded) > 0 {
		return decoded, true
	}
	return []byte(raw), false
}

func castSlice(v any) []any {
	if v == nil {
		return []any{}
	}
	if out, ok := v.([]any); ok {
		return out
	}
	return []any{}
}

func (s *Server) getLastSyncFor(serverAddress, syncType string) float64 {
	if strings.TrimSpace(serverAddress) == "" || strings.TrimSpace(syncType) == "" {
		return 0
	}
	var ts float64
	_ = s.DB.QueryRow(`SELECT COALESCE(last_sync, 0) FROM server_sync_history
		WHERE server_address = ? AND sync_type = ? LIMIT 1`, serverAddress, syncType).Scan(&ts)
	return ts
}

func (s *Server) syncRemoteAPIAppUpdate(title, username, contentHash string) {
	appName := extractAppNameFromTitle(title)
	if appName == "" || username == "" || contentHash == "" {
		return
	}
	var currentHash, currentOwner string
	err := s.DB.QueryRow(`SELECT content_hash, username FROM api_apps WHERE app_name = ?`, appName).Scan(&currentHash, &currentOwner)
	if err == sql.ErrNoRows {
		_, _ = s.DB.Exec(`INSERT INTO api_apps (app_name, username, content_hash, timestamp, last_updated)
			VALUES (?, ?, ?, ?, ?)`, appName, username, contentHash, now(), now())
		_, _ = s.DB.Exec(`INSERT INTO api_app_versions (version_id, app_name, content_hash, username, timestamp, version_number)
			VALUES (?, ?, ?, ?, ?, 1)`, NewUUID(), appName, contentHash, username, now())
		return
	}
	if err != nil || currentOwner != username || currentHash == contentHash {
		return
	}
	_, _ = s.DB.Exec(`UPDATE dns_records SET content_hash = ? WHERE content_hash = ?`, contentHash, currentHash)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO content_redirects
		(old_hash, new_hash, username, redirect_type, timestamp)
		VALUES (?, ?, ?, ?, ?)`, currentHash, contentHash, username, "app_update", now())
	_, _ = s.DB.Exec(`UPDATE api_apps SET content_hash = ?, last_updated = ? WHERE app_name = ?`,
		contentHash, now(), appName)
	nextVersion := 1
	_ = s.DB.QueryRow(`SELECT COALESCE(MAX(version_number), 0) + 1 FROM api_app_versions WHERE app_name = ?`, appName).Scan(&nextVersion)
	_, _ = s.DB.Exec(`INSERT INTO api_app_versions (version_id, app_name, content_hash, username, timestamp, version_number)
		VALUES (?, ?, ?, ?, ?, ?)`, NewUUID(), appName, contentHash, username, now(), nextVersion)
}

func extractAppNameFromTitle(title string) string {
	title = strings.TrimSpace(title)
	if !strings.HasPrefix(title, "(HPS!api)") {
		return ""
	}
	parts := strings.Split(title, "{")
	if len(parts) < 2 {
		return ""
	}
	body := strings.TrimSuffix(parts[1], "}")
	for _, kv := range strings.Split(body, ",") {
		seg := strings.TrimSpace(kv)
		if strings.HasPrefix(seg, "name=") {
			return strings.TrimSpace(strings.TrimPrefix(seg, "name="))
		}
		if strings.HasPrefix(seg, "app=") {
			return strings.TrimSpace(strings.TrimPrefix(seg, "app="))
		}
	}
	return ""
}
