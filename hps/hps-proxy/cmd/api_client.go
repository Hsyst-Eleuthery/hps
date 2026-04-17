package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type APIClient struct {
	baseURL string
	http    *http.Client

	dnsMu    sync.RWMutex
	dnsCache map[string]string

	contentMu    sync.RWMutex
	contentCache map[string]CachedContent
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
	scheme := "http"
	if cfg.TLS {
		scheme = "https"
	}
	return &APIClient{
		baseURL:      fmt.Sprintf("%s://%s", scheme, strings.TrimSpace(cfg.Server)),
		http:         &http.Client{Timeout: 60 * time.Second},
		dnsCache:     map[string]string{},
		contentCache: map[string]CachedContent{},
	}
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBytes))
	if err != nil {
		return nil, res.StatusCode, err
	}
	return raw, res.StatusCode, nil
}

func (c *APIClient) doGetWithMime(ctx context.Context, endpoint string, maxBytes int64) ([]byte, int, string, http.Header, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, 0, "", nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBytes))
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
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *APIClient) doPostJSON(ctx context.Context, endpoint string, payload any, maxBytes int64) ([]byte, int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBytes))
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
	if len(msg) > 500 {
		msg = msg[:500] + "..."
	}
	return msg
}
