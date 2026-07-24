package main

import (
	"context"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProxyHandler struct {
	api        *APIClient
	store      *LocalStore
	serverAddr string
	authToken  string
	rateMu     sync.Mutex
	rateBuckets map[string]*rateBucket
}

type rateBucket struct {
	tokens    float64
	lastCheck time.Time
}

func NewProxyHandler(api *APIClient, store *LocalStore, serverAddr, authToken string) *ProxyHandler {
	return &ProxyHandler{
		api:         api,
		store:       store,
		serverAddr:  strings.TrimSpace(serverAddr),
		authToken:   authToken,
		rateBuckets: make(map[string]*rateBucket),
	}
}

func (p *ProxyHandler) allowRate(ip string, rate float64, burst int) bool {
	p.rateMu.Lock()
	defer p.rateMu.Unlock()
	b, ok := p.rateBuckets[ip]
	if !ok {
		b = &rateBucket{tokens: float64(burst), lastCheck: time.Now()}
		p.rateBuckets[ip] = b
	}
	now := time.Now()
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * rate
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.lastCheck = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// M-06 FIX: Always check localhost first
	if !isLocalhost(r.RemoteAddr) {
		writeBrowserErrorPage(w, http.StatusForbidden, "Acesso negado", "O proxy HPS aceita apenas conexoes locais.", "")
		return
	}

	// Rate limiting: 10 req/s with burst of 20
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !p.allowRate(clientIP, 10, 20) {
		writeBrowserErrorPage(w, http.StatusTooManyRequests, "Muitas requisicoes", "Limite de taxa excedido. Tente novamente.", "")
		return
	}

	// M-06 FIX: Always require authentication if token is configured
	if p.authToken != "" {
		auth := strings.TrimSpace(r.Header.Get("Proxy-Authorization"))
		expected := "Bearer " + p.authToken
		if !strings.EqualFold(auth, expected) {
			w.Header().Set("Proxy-Authenticate", "Bearer")
			writeBrowserErrorPage(w, http.StatusProxyAuthRequired, "Autenticacao necessaria", "Proxy-Authorization header obrigatorio.", "")
			return
		}
	}

	if strings.EqualFold(r.Method, http.MethodConnect) {
		p.handleConnect(w, r)
		return
	}

	input := extractInputTarget(r)
	if input == "" {
		writeBrowserErrorPage(w, http.StatusBadRequest, "Destino ausente", "Nao foi possivel identificar dominio/hash da requisicao.", "")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()

	domain := ""
	hash := ""
	resolvedBy := "hash_direct"
	if looksLikeContentHash(input) {
		hash = strings.TrimSpace(input)
	} else {
		domain = strings.ToLower(strings.TrimSpace(input))
		resolvedBy = "dns"
		var err error
		hash, err = p.api.ResolveDomain(ctx, domain)
		if err != nil {
			p.recordVisit(VisitRecord{
				Input:      input,
				Domain:     domain,
				Server:     p.serverAddr,
				HTTPStatus: http.StatusNotFound,
				Failure:    err.Error(),
				ResolvedBy: "dns",
			})
			p.recordServer(false)
			status := http.StatusBadGateway
			title := "Falha DNS HPS"
			sanitizedErr := sanitizeErrorMessage(err.Error())
			if looksLikeNotFound(sanitizedErr) {
				status = http.StatusNotFound
				title = "Dominio nao encontrado na rede HPS"
			}
			writeBrowserErrorPage(w, status, title, sanitizedErr, domain)
			return
		}
		if p.store != nil {
			p.store.SaveDNS(domain, hash)
		}
	}

	res, err := p.api.FetchContentWithMeta(ctx, hash)
	if err != nil {
		p.recordVisit(VisitRecord{
			Input:       input,
			Domain:      domain,
			ContentHash: hash,
			Server:      p.serverAddr,
			HTTPStatus:  http.StatusNotFound,
			Failure:     err.Error(),
			ResolvedBy:  resolvedBy,
		})
		p.recordServer(false)
		status := http.StatusBadGateway
		title := "Falha ao carregar conteudo HPS"
		sanitizedErr := sanitizeErrorMessage(err.Error())
		if looksLikeNotFound(sanitizedErr) {
			status = http.StatusNotFound
			title = "Conteudo nao encontrado"
		}
		writeBrowserErrorPage(w, status, title, sanitizedErr, domain)
		return
	}
	p.recordServer(true)

	integrity := IntegrityResult{}
	if p.store != nil {
		integrity = p.store.StoreContent(hash, domain, res.Mime, res.Body)
		p.recordVisit(VisitRecord{
			Input:        input,
			Domain:       domain,
			ContentHash:  hash,
			ResolvedBy:   resolvedBy,
			Server:       p.serverAddr,
			Mime:         res.Mime,
			Bytes:        len(res.Body),
			HTTPStatus:   http.StatusOK,
			Integrity:    integrity.Status,
			IntegrityMsg: integrity.Reason,
		})
	}

	contractIDs := extractHeaderIDs(res.Headers, "X-HPS-Contract-ID", "X-HPS-Contract-Id", "X-HPS-Contracts")
	if p.store != nil && len(contractIDs) > 0 {
		p.store.LinkContractRefs(hash, domain, contractIDs)
	}

	voucherIDs := extractHeaderIDs(res.Headers, "X-HPS-Voucher-ID", "X-HPS-Voucher-Id", "X-HPS-Vouchers")
	if p.store != nil && len(voucherIDs) > 0 {
		p.auditAndStoreVouchers(ctx, domain, hash, voucherIDs)
	}

	w.Header().Set("Content-Type", res.Mime)
	w.Header().Set("X-HPS-Domain", domain)
	w.Header().Set("X-HPS-Content-Hash", hash)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.Body)
	log.Printf("[proxy] input=%s domain=%s hash=%s bytes=%d mime=%s integrity=%s", input, domain, hash, len(res.Body), res.Mime, integrity.Status)
}

func extractInputTarget(r *http.Request) string {
	h := strings.TrimSpace(r.URL.Hostname())
	if h == "" {
		h = strings.TrimSpace(r.Host)
	}
	h = strings.TrimSpace(strings.Split(h, ":")[0])
	if h != "" {
		return strings.TrimSpace(h)
	}
	rawPath := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/"))
	if rawPath != "" {
		return strings.TrimSpace(strings.Split(rawPath, "/")[0])
	}
	return ""
}

func (p *ProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" {
		writeBrowserErrorPage(w, http.StatusBadRequest, "CONNECT sem destino", "Host ausente no CONNECT.", "")
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeBrowserErrorPage(w, http.StatusInternalServerError, "Erro interno", "Proxy nao suporta hijacking.", "")
		return
	}

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[connect] falha ao conectar em %s: %v", target, err)
		writeBrowserErrorPage(w, http.StatusBadGateway, "Falha CONNECT", "Nao foi possivel conectar ao destino.", "")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		log.Printf("[connect] hijack falhou: %v", err)
		writeBrowserErrorPage(w, http.StatusInternalServerError, "Erro interno", "Falha ao hijackar conexao.", "")
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Limit tunnel data transfer to 100MB to prevent resource exhaustion
	const maxTunnelBytes = 100 * 1024 * 1024
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		done := make(chan struct{}, 2)
		go func() {
			io.Copy(targetConn, io.LimitReader(clientConn, maxTunnelBytes))
			done <- struct{}{}
		}()
		go func() {
			io.Copy(clientConn, io.LimitReader(targetConn, maxTunnelBytes))
			done <- struct{}{}
		}()
		<-done
	}()
}

func writeBrowserErrorPage(w http.ResponseWriter, status int, title, details, domain string) {
	title = strings.TrimSpace(title)
	if title == "" {
		title = "Erro no HPS Proxy"
	}
	details = strings.TrimSpace(details)
	if details == "" {
		details = "Falha desconhecida."
	}
	domain = strings.TrimSpace(domain)

	body := "<!doctype html><html lang=\"pt-br\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
		"<title>HPS Proxy - Erro</title>" +
		"<style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px;background:#0f172a;color:#e2e8f0}" +
		".card{max-width:880px;margin:0 auto;background:#111827;border:1px solid #334155;border-radius:12px;padding:20px}" +
		"h1{font-size:22px;margin:0 0 10px;color:#f8fafc}.meta{font-size:13px;color:#94a3b8;margin-bottom:12px}" +
		"code{background:#0b1220;padding:2px 6px;border-radius:6px;color:#f8fafc}" +
		".err{white-space:pre-wrap;background:#0b1220;border:1px solid #334155;padding:12px;border-radius:8px}</style></head><body>" +
		"<div class=\"card\"><h1>" + html.EscapeString(title) + "</h1>" +
		"<div class=\"meta\">HTTP " + html.EscapeString(http.StatusText(status)) + " (" + html.EscapeString(strings.TrimSpace(strconv.Itoa(status))) + ")</div>"
	if domain != "" {
		body += "<div class=\"meta\">Dominio: <code>" + html.EscapeString(domain) + "</code></div>"
	}
	body += "<div class=\"err\">" + html.EscapeString(details) + "</div>" +
		"</div></body></html>"

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func looksLikeNotFound(message string) bool {
	msg := strings.ToLower(strings.TrimSpace(message))
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "nao encontrado") ||
		strings.Contains(msg, "domain not found") ||
		strings.Contains(msg, "content not found")
}

var base58HashPattern = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{44,90}$`)
var b64HashPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)

func looksLikeContentHash(value string) bool {
	v := strings.TrimSpace(value)
	v = strings.TrimPrefix(v, "hps://")
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimSpace(strings.Split(v, "/")[0])
	if v == "" {
		return false
	}
	lv := strings.ToLower(v)
	if isHexLen(lv, 64) {
		return true
	}
	if strings.HasPrefix(v, "Qm") && base58HashPattern.MatchString(v) {
		return true
	}
	if strings.Contains(v, ".") {
		return false
	}
	return b64HashPattern.MatchString(v)
}

func extractHeaderIDs(headers map[string][]string, keys ...string) []string {
	var out []string
	for hdrKey, values := range headers {
		matched := false
		for _, key := range keys {
			if strings.EqualFold(hdrKey, key) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, raw := range values {
			parts := strings.Split(raw, ",")
			for _, part := range parts {
				id := strings.TrimSpace(part)
				if id != "" {
					out = append(out, id)
				}
			}
		}
	}
	return uniqueSorted(out)
}

func (p *ProxyHandler) auditAndStoreVouchers(ctx context.Context, domain, hash string, voucherIDs []string) {
	if p.store == nil || p.api == nil || len(voucherIDs) == 0 {
		return
	}
	results, err := p.api.AuditVouchers(ctx, voucherIDs)
	if err != nil {
		for _, id := range voucherIDs {
			p.store.UpsertVoucher(VoucherRecord{
				VoucherID:         id,
				Domain:            domain,
				ContentHash:       hash,
				VerificationState: "audit_error",
				VerificationError: err.Error(),
			})
		}
		return
	}
	for _, id := range voucherIDs {
		row := results[id]
		state := "audited"
		errText := ""
		if row == nil {
			state = "not_found"
			errText = "voucher nao retornado pelo servidor"
		} else if asBool(row["invalidated"]) {
			state = "invalidated"
			errText = "voucher invalidado"
		}
		p.store.UpsertVoucher(VoucherRecord{
			VoucherID:         id,
			Domain:            domain,
			ContentHash:       hash,
			VerificationState: state,
			VerificationError: errText,
			Raw:               row,
		})
	}
}

func (p *ProxyHandler) recordVisit(v VisitRecord) {
	if p.store == nil {
		return
	}
	p.store.RecordVisit(v)
}

func (p *ProxyHandler) recordServer(success bool) {
	if p.store == nil {
		return
	}
	p.store.RecordServerAccess(p.serverAddr, success)
}

func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.ToLower(strings.TrimSpace(host))
	// Direct matches
	if host == "127.0.0.1" || host == "localhost" {
		return true
	}
	// IPv6 loopback - various representations
	if host == "::1" || host == "0:0:0:0:0:0:0:1" || host == "[::1]" || host == "[0:0:0:0:0:0:0:1]" {
		return true
	}
	// Normalize and strip brackets for expanded check
	normalized := strings.Trim(host, "[]")
	if normalized == "::1" || normalized == "0:0:0:0:0:0:0:1" {
		return true
	}
	return false
}

func sanitizeErrorMessage(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "erro desconhecido"
	}
	// Remove potential path information that could leak filesystem structure
	if idx := strings.Index(msg, "open "); idx != -1 {
		msg = "erro interno"
	}
	if idx := strings.Index(msg, "permission denied"); idx != -1 {
		msg = "acesso negado"
	}
	// Limit length
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	return msg
}
