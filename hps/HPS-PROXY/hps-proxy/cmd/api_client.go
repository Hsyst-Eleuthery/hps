package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type APIClient struct {
	baseURL   string
	http      *http.Client
	authToken string
	cryptoDir string
	serverAddr string

	dnsMu    sync.RWMutex
	dnsCache map[string]string

	contentMu    sync.RWMutex
	contentCache map[string]CachedContent
}

func (c *APIClient) SetAuthToken(token string) {
	c.authToken = token
}

func (c *APIClient) AuthToken() string {
	return c.authToken
}

func generateAuthToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func pinnedKeysPath(cryptoDir string) string {
	return filepath.Join(cryptoDir, "pinned_keys.json")
}

type pinnedKeys struct {
	Keys map[string]string `json:"keys"`
}

func pinServerKey(cryptoDir, serverAddr, publicKey string) error {
	path := pinnedKeysPath(cryptoDir)
	pk := pinnedKeys{Keys: map[string]string{}}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &pk)
	}
	if pk.Keys == nil {
		pk.Keys = map[string]string{}
	}
	pk.Keys[serverAddr] = publicKey
	raw, err := json.MarshalIndent(pk, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func getPinnedServerKey(cryptoDir, serverAddr string) (string, error) {
	path := pinnedKeysPath(cryptoDir)
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var pk pinnedKeys
	if err := json.Unmarshal(raw, &pk); err != nil {
		return "", err
	}
	key, ok := pk.Keys[serverAddr]
	if !ok {
		return "", errors.New("nenhuma chave fixada para este servidor")
	}
	return key, nil
}

type CachedContent struct {
	Body    []byte
	Mime    string
	Headers map[string][]string
	Exp     time.Time
}

type ContentResponse struct {
	Body    []byte
	Mime    string
	Headers map[string][]string
}

func NewAPIClient(cfg Config) *APIClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil

	serverAddr := buildAPIBaseURL(cfg.Server, cfg.TLS)
	parsed, _ := url.Parse(serverAddr)
	host := ""
	if parsed != nil {
		host = parsed.Hostname()
	}

	if cfg.TLS {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // TOFU: verify via VerifyConnection
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("nenhum certificado apresentado pelo servidor")
				}
				leaf := cs.PeerCertificates[0]
				peerPubKey := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				peerPubHex := hex.EncodeToString(peerPubKey[:])

				// SECURITY FIX: Require cryptoDir for pinning - reject if empty
				if cfg.CryptoDir == "" {
					log.Printf("[tofu] SECURITY: cryptoDir vazio, rejeitando conexao sem pinning")
					return errors.New("cryptoDir obrigatorio para verificacao de pinning")
				}

				pinned, err := getPinnedServerKey(cfg.CryptoDir, host)
				if err != nil {
					log.Printf("[tofu] primeira conexao com %s, fixando chave: %s", host, peerPubHex[:16])
					if pinErr := pinServerKey(cfg.CryptoDir, host, peerPubHex); pinErr != nil {
						log.Printf("[tofu] erro ao fixar chave: %v", pinErr)
					}
					return nil
				}
				if pinned != peerPubHex {
					return fmt.Errorf("TOFU: chave do servidor mudou! anterior=%s atual=%s", pinned[:16], peerPubHex[:16])
				}
				return nil
			},
		}
	}

	return &APIClient{
		baseURL:      serverAddr,
		http:         &http.Client{Timeout: 60 * time.Second, Transport: transport},
		cryptoDir:    cfg.CryptoDir,
		serverAddr:   host,
		dnsCache:     map[string]string{},
		contentCache: map[string]CachedContent{},
	}
}

func buildAPIBaseURL(server string, useTLS bool) string {
	defaultScheme := "http"
	if useTLS {
		defaultScheme = "https"
	}

	trimmed := strings.TrimSpace(server)
	if trimmed == "" {
		return fmt.Sprintf("%s://", defaultScheme)
	}

	if strings.HasPrefix(strings.ToLower(trimmed), "ws://") {
		trimmed = "http://" + trimmed[len("ws://"):]
	} else if strings.HasPrefix(strings.ToLower(trimmed), "wss://") {
		trimmed = "https://" + trimmed[len("wss://"):]
	} else if !strings.HasPrefix(strings.ToLower(trimmed), "http://") && !strings.HasPrefix(strings.ToLower(trimmed), "https://") {
		trimmed = defaultScheme + "://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return strings.TrimRight(trimmed, "/")
	}

	if strings.EqualFold(parsed.Hostname(), "localhost") {
		if port := parsed.Port(); port != "" {
			parsed.Host = "127.0.0.1:" + port
		} else {
			parsed.Host = "127.0.0.1"
		}
	}

	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/")
}

func (c *APIClient) ResolveDomain(ctx context.Context, domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "", errors.New("dominio ausente")
	}

	c.dnsMu.RLock()
	cached := c.dnsCache[domain]
	c.dnsMu.RUnlock()
	if cached != "" {
		return cached, nil
	}

	paths := []string{
		fmt.Sprintf("%s/dns/%s", c.baseURL, url.PathEscape(domain)),
		fmt.Sprintf("%s/api/dns/%s", c.baseURL, url.PathEscape(domain)),
	}

	var out DNSResponse
	var raw []byte
	var statusCode int
	var err error
	parsed := false
	for _, endpoint := range paths {
		raw, statusCode, err = c.doGet(ctx, endpoint, 4*1024*1024)
		if err != nil {
			continue
		}
		if json.Unmarshal(raw, &out) == nil {
			parsed = true
			break
		}
	}

	if err != nil {
		return "", err
	}
	if !parsed {
		return "", errors.New("resposta DNS invalida: " + trimBodyMessage(raw, statusCode))
	}
	if statusCode >= 400 {
		return "", errors.New(trimBodyMessage(raw, statusCode))
	}
	if !out.Success {
		if out.Error == "" {
			out.Error = trimBodyMessage(raw, statusCode)
		}
		return "", errors.New(out.Error)
	}
	if strings.TrimSpace(out.ContentHash) == "" {
		return "", errors.New("dns sem content_hash (resposta invalida do servidor)")
	}

	hash := strings.TrimSpace(out.ContentHash)
	c.dnsMu.Lock()
	c.dnsCache[domain] = hash
	c.dnsMu.Unlock()
	return hash, nil
}

func (c *APIClient) FetchContent(ctx context.Context, hash string) ([]byte, string, error) {
	res, err := c.FetchContentWithMeta(ctx, hash)
	if err != nil {
		return nil, "", err
	}
	return res.Body, res.Mime, nil
}

func (c *APIClient) FetchContentWithMeta(ctx context.Context, hash string) (ContentResponse, error) {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return ContentResponse{}, errors.New("hash ausente")
	}

	c.contentMu.RLock()
	cached, ok := c.contentCache[hash]
	c.contentMu.RUnlock()
	if ok && time.Now().Before(cached.Exp) {
		return ContentResponse{
			Body:    cached.Body,
			Mime:    cached.Mime,
			Headers: cloneHeaders(cached.Headers),
		}, nil
	}

	paths := []string{
		fmt.Sprintf("%s/content/%s", c.baseURL, url.PathEscape(hash)),
		fmt.Sprintf("%s/api/content/%s", c.baseURL, url.PathEscape(hash)),
	}

	var body []byte
	var mime string
	var headers http.Header
	var statusCode int
	var err error
	for _, endpoint := range paths {
		body, statusCode, mime, headers, err = c.doGetWithMime(ctx, endpoint, 200*1024*1024)
		if err == nil {
			break
		}
	}
	if err != nil {
		return ContentResponse{}, err
	}
	if statusCode >= 400 {
		return ContentResponse{}, errors.New(trimBodyMessage(body, statusCode))
	}
	mime = normalizeMime(body, mime)

	headerMap := cloneHeaders(headers)
	c.contentMu.Lock()
	c.contentCache[hash] = CachedContent{
		Body:    append([]byte(nil), body...),
		Mime:    mime,
		Headers: cloneHeaders(headerMap),
		Exp:     nowPlus(2 * time.Minute),
	}
	c.contentMu.Unlock()
	return ContentResponse{
		Body:    body,
		Mime:    mime,
		Headers: headerMap,
	}, nil
}

func (c *APIClient) doGet(ctx context.Context, endpoint string, maxBytes int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	if c.authToken != "" {
		req.Header.Set("X-HPS-Auth-Token", c.authToken)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBytes))
	io.Copy(io.Discard, res.Body) // drain to allow connection reuse
	if err != nil {
		return nil, res.StatusCode, err
	}
	return raw, res.StatusCode, nil
}

func (c *APIClient) doGetWithMime(ctx context.Context, endpoint string, maxBytes int64) ([]byte, int, string, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, "", nil, err
	}
	if c.authToken != "" {
		req.Header.Set("X-HPS-Auth-Token", c.authToken)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, 0, "", nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBytes))
	io.Copy(io.Discard, res.Body) // drain to allow connection reuse
	if err != nil {
		return nil, res.StatusCode, "", nil, err
	}
	return raw, res.StatusCode, strings.TrimSpace(res.Header.Get("Content-Type")), cloneHeaders(res.Header), nil
}

func (c *APIClient) SyncSnapshot(ctx context.Context, limit int) (SyncSnapshot, error) {
	if limit <= 0 {
		limit = 200
	}
	content, err := c.fetchList(ctx, fmt.Sprintf("%s/sync/content?limit=%d", c.baseURL, limit))
	if err != nil {
		return SyncSnapshot{}, err
	}
	dns, err := c.fetchList(ctx, fmt.Sprintf("%s/sync/dns", c.baseURL))
	if err != nil {
		return SyncSnapshot{}, err
	}
	contracts, err := c.fetchList(ctx, fmt.Sprintf("%s/sync/contracts?limit=%d", c.baseURL, limit))
	if err != nil {
		return SyncSnapshot{}, err
	}
	users, err := c.fetchList(ctx, fmt.Sprintf("%s/sync/users", c.baseURL))
	if err != nil {
		return SyncSnapshot{}, err
	}
	return SyncSnapshot{
		Content:   content,
		DNS:       dns,
		Contracts: contracts,
		Users:     users,
	}, nil
}

func (c *APIClient) AuditVouchers(ctx context.Context, voucherIDs []string) (map[string]map[string]any, error) {
	ids := uniqueSorted(voucherIDs)
	if len(ids) == 0 {
		return map[string]map[string]any{}, nil
	}
	endpoint := c.baseURL + "/voucher/audit"
	payload := map[string]any{"voucher_ids": ids}
	raw, statusCode, err := c.doPostJSON(ctx, endpoint, payload, 8*1024*1024)
	if err != nil {
		return nil, err
	}
	if statusCode >= 400 {
		return nil, errors.New(trimBodyMessage(raw, statusCode))
	}

	var out struct {
		Success  bool             `json:"success"`
		Vouchers []map[string]any `json:"vouchers"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	result := map[string]map[string]any{}
	for _, row := range out.Vouchers {
		id := strings.TrimSpace(asString(row["voucher_id"]))
		if id != "" {
			result[id] = row
		}
	}
	return result, nil
}

func (c *APIClient) fetchList(ctx context.Context, endpoint string) ([]map[string]any, error) {
	raw, statusCode, err := c.doGet(ctx, endpoint, 16*1024*1024)
	if err != nil {
		return nil, err
	}
	if statusCode >= 400 {
		return nil, errors.New(trimBodyMessage(raw, statusCode))
	}
	if len(raw) == 0 {
		return []map[string]any{}, nil
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (c *APIClient) doPostJSON(ctx context.Context, endpoint string, payload any, maxBytes int64) ([]byte, int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("X-HPS-Auth-Token", c.authToken)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBytes))
	io.Copy(io.Discard, res.Body) // drain to allow connection reuse
	if err != nil {
		return nil, res.StatusCode, err
	}
	return raw, res.StatusCode, nil
}

func cloneHeaders(h http.Header) map[string][]string {
	if len(h) == 0 {
		return map[string][]string{}
	}
	out := map[string][]string{}
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func normalizeMime(body []byte, headerMime string) string {
	m := strings.ToLower(strings.TrimSpace(headerMime))
	if m != "" {
		m = strings.TrimSpace(strings.Split(m, ";")[0])
	}
	if m != "" && m != "application/octet-stream" {
		return m
	}

	sniff := "application/octet-stream"
	if len(body) > 0 {
		sample := body
		if len(sample) > 512 {
			sample = sample[:512]
		}
		sniff = strings.ToLower(strings.TrimSpace(http.DetectContentType(sample)))
		sniff = strings.TrimSpace(strings.Split(sniff, ";")[0])
	}

	if sniff != "" && sniff != "application/octet-stream" {
		return sniff
	}
	if m != "" {
		return m
	}
	return "application/octet-stream"
}

func trimBodyMessage(body []byte, statusCode int) string {
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = "status " + strconv.Itoa(statusCode)
	}
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	return msg
}
