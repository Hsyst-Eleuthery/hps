package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxVisitHistory = 2000
)

type LocalStore struct {
	root       string
	filesDir   string
	statePath  string
	storageKey []byte

	mu    sync.Mutex
	state ProxyLocalState
}

type ProxyLocalState struct {
	UpdatedAt      string                    `json:"updated_at"`
	Servers        map[string]ServerAccess   `json:"servers"`
	DNS            map[string]string         `json:"dns"`
	Files          map[string]FileRecord     `json:"files"`
	Contracts      map[string]ContractRecord `json:"contracts"`
	Vouchers       map[string]VoucherRecord  `json:"vouchers"`
	Visits         []VisitRecord             `json:"visits"`
	Sync           SyncState                 `json:"sync"`
	HashContracts  map[string][]string       `json:"hash_contracts"`
	DomainContract map[string][]string       `json:"domain_contracts"`
	HashVouchers   map[string][]string       `json:"hash_vouchers"`
	DomainVouchers map[string][]string       `json:"domain_vouchers"`
}

type ServerAccess struct {
	Address    string `json:"address"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	Accesses   int    `json:"accesses"`
	Successful int    `json:"successful"`
	Failed     int    `json:"failed"`
}

type FileRecord struct {
	Hash            string `json:"hash"`
	Path            string `json:"path"`
	Mime            string `json:"mime"`
	Size            int    `json:"size"`
	LocalSHA256     string `json:"local_sha256"`
	IntegrityStatus string `json:"integrity_status"`
	IntegrityReason string `json:"integrity_reason"`
	Domain          string `json:"domain"`
	FirstSeen       string `json:"first_seen"`
	LastSeen        string `json:"last_seen"`
}

type ContractRecord struct {
	ContractID  string `json:"contract_id"`
	ActionType  string `json:"action_type"`
	ContentHash string `json:"content_hash"`
	Domain      string `json:"domain"`
	Username    string `json:"username"`
	Verified    bool   `json:"verified"`
	Timestamp   string `json:"timestamp"`
}

type VoucherRecord struct {
	VoucherID         string         `json:"voucher_id"`
	Domain            string         `json:"domain"`
	ContentHash       string         `json:"content_hash"`
	VerificationState string         `json:"verification_state"`
	VerificationError string         `json:"verification_error"`
	UpdatedAt         string         `json:"updated_at"`
	Raw               map[string]any `json:"raw"`
}

type VisitRecord struct {
	When         string `json:"when"`
	Input        string `json:"input"`
	Domain       string `json:"domain"`
	ContentHash  string `json:"content_hash"`
	ResolvedBy   string `json:"resolved_by"`
	Server       string `json:"server"`
	Mime         string `json:"mime"`
	Bytes        int    `json:"bytes"`
	HTTPStatus   int    `json:"http_status"`
	Failure      string `json:"failure"`
	Integrity    string `json:"integrity"`
	IntegrityMsg string `json:"integrity_reason"`
}

type SyncState struct {
	LastFullSync  string `json:"last_full_sync"`
	ContentItems  int    `json:"content_items"`
	DNSItems      int    `json:"dns_items"`
	ContractItems int    `json:"contract_items"`
	UserItems     int    `json:"user_items"`
}

type SyncSnapshot struct {
	Content   []map[string]any
	DNS       []map[string]any
	Contracts []map[string]any
	Users     []map[string]any
}

type IntegrityResult struct {
	SHA256 string
	Status string
	Reason string
}

type encryptedContentEnvelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag"`
	Ciphertext string `json:"ciphertext"`
}

func NewLocalStore(root string, storageKey []byte) (*LocalStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("diretorio de dados invalido")
	}
	if len(storageKey) != keySizeBytes {
		return nil, errors.New("chave de armazenamento invalida")
	}
	filesDir := filepath.Join(root, "files")
	statePath := filepath.Join(root, "state.json")
	if err := os.MkdirAll(filesDir, 0o700); err != nil {
		return nil, err
	}
	s := &LocalStore{
		root:       root,
		filesDir:   filesDir,
		statePath:  statePath,
		storageKey: append([]byte(nil), storageKey...),
		state: ProxyLocalState{
			Servers:        map[string]ServerAccess{},
			DNS:            map[string]string{},
			Files:          map[string]FileRecord{},
			Contracts:      map[string]ContractRecord{},
			Vouchers:       map[string]VoucherRecord{},
			Visits:         []VisitRecord{},
			HashContracts:  map[string][]string{},
			DomainContract: map[string][]string{},
			HashVouchers:   map[string][]string{},
			DomainVouchers: map[string][]string{},
		},
	}
	_ = s.load()
	return s, nil
}

func (s *LocalStore) DataDir() string {
	return s.root
}

func (s *LocalStore) RecordServerAccess(address string, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	addr := strings.ToLower(strings.TrimSpace(address))
	if addr == "" {
		return
	}
	rec := s.state.Servers[addr]
	if rec.Address == "" {
		rec.Address = addr
		rec.FirstSeen = now
	}
	rec.Accesses++
	if success {
		rec.Successful++
	} else {
		rec.Failed++
	}
	rec.LastSeen = now
	s.state.Servers[addr] = rec
	s.state.UpdatedAt = now
	_ = s.saveLocked()
}

func (s *LocalStore) SaveDNS(domain, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain = strings.ToLower(strings.TrimSpace(domain))
	hash = strings.TrimSpace(hash)
	if domain == "" || hash == "" {
		return
	}
	s.state.DNS[domain] = hash
	s.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = s.saveLocked()
}

func (s *LocalStore) StoreContent(hash, domain, mime string, body []byte) IntegrityResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	hash = strings.TrimSpace(hash)
	domain = strings.ToLower(strings.TrimSpace(domain))
	mime = strings.TrimSpace(mime)
	sum := sha256.Sum256(body)
	localSHA := hex.EncodeToString(sum[:])
	integrity := evaluateIntegrity(hash, localSHA)

	name := sanitizeForFilename(hash)
	if name == "" {
		name = localSHA
	}
	filePath := ""
	blob, encErr := s.encryptBlob(body)
	if encErr == nil {
		filePath = filepath.Join(s.filesDir, name+".hpsbin")
		_ = os.WriteFile(filePath, blob, 0o600)
	} else {
		integrity.Status = "local_encrypt_error"
		integrity.Reason = encErr.Error()
	}

	rec := s.state.Files[hash]
	if rec.Hash == "" {
		rec.Hash = hash
		rec.FirstSeen = now
	}
	rec.Path = filePath
	rec.Mime = mime
	rec.Size = len(body)
	rec.LocalSHA256 = localSHA
	rec.IntegrityStatus = integrity.Status
	rec.IntegrityReason = integrity.Reason
	rec.Domain = domain
	rec.LastSeen = now
	s.state.Files[hash] = rec
	s.state.UpdatedAt = now
	_ = s.saveLocked()
	return integrity
}

func (s *LocalStore) encryptBlob(plain []byte) ([]byte, error) {
	nonce := randomBytes(nonceSizeBytes)
	defer zero(nonce)
	ciphertext, tag, err := encryptGCM(s.storageKey, nonce, plain)
	if err != nil {
		return nil, err
	}
	defer zero(ciphertext)
	defer zero(tag)
	env := encryptedContentEnvelope{
		Version:    1,
		Algorithm:  "AES-256-GCM",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Tag:        base64.StdEncoding.EncodeToString(tag),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.Marshal(env)
}

func (s *LocalStore) RecordVisit(v VisitRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(v.When) == "" {
		v.When = time.Now().UTC().Format(time.RFC3339)
	}
	s.state.Visits = append([]VisitRecord{v}, s.state.Visits...)
	if len(s.state.Visits) > maxVisitHistory {
		s.state.Visits = s.state.Visits[:maxVisitHistory]
	}
	s.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = s.saveLocked()
}

func (s *LocalStore) UpsertContracts(items []ContractRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, item := range items {
		id := strings.TrimSpace(item.ContractID)
		if id == "" {
			continue
		}
		s.state.Contracts[id] = item
		if h := strings.TrimSpace(item.ContentHash); h != "" {
			s.state.HashContracts[h] = appendUnique(s.state.HashContracts[h], id)
		}
		if d := strings.ToLower(strings.TrimSpace(item.Domain)); d != "" {
			s.state.DomainContract[d] = appendUnique(s.state.DomainContract[d], id)
		}
	}
	s.state.UpdatedAt = now
	_ = s.saveLocked()
}

func (s *LocalStore) LinkContractRefs(hash, domain string, contractIDs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash = strings.TrimSpace(hash)
	domain = strings.ToLower(strings.TrimSpace(domain))
	if hash != "" {
		for _, id := range contractIDs {
			s.state.HashContracts[hash] = appendUnique(s.state.HashContracts[hash], id)
		}
	}
	if domain != "" {
		for _, id := range contractIDs {
			s.state.DomainContract[domain] = appendUnique(s.state.DomainContract[domain], id)
		}
	}
	s.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = s.saveLocked()
}

func (s *LocalStore) UpsertVoucher(v VoucherRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := strings.TrimSpace(v.VoucherID)
	if id == "" {
		return
	}
	if strings.TrimSpace(v.UpdatedAt) == "" {
		v.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.state.Vouchers[id] = v
	if h := strings.TrimSpace(v.ContentHash); h != "" {
		s.state.HashVouchers[h] = appendUnique(s.state.HashVouchers[h], id)
	}
	if d := strings.ToLower(strings.TrimSpace(v.Domain)); d != "" {
		s.state.DomainVouchers[d] = appendUnique(s.state.DomainVouchers[d], id)
	}
	s.state.UpdatedAt = v.UpdatedAt
	_ = s.saveLocked()
}

func (s *LocalStore) ApplySyncSnapshot(ss SyncSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Format(time.RFC3339)

	for _, row := range ss.DNS {
		domain := strings.ToLower(strings.TrimSpace(asString(row["domain"])))
		hash := strings.TrimSpace(asString(row["content_hash"]))
		if domain != "" && hash != "" {
			s.state.DNS[domain] = hash
		}
	}

	for _, row := range ss.Contracts {
		id := strings.TrimSpace(asString(row["contract_id"]))
		if id == "" {
			continue
		}
		rec := ContractRecord{
			ContractID:  id,
			ActionType:  strings.TrimSpace(asString(row["action_type"])),
			ContentHash: strings.TrimSpace(asString(row["content_hash"])),
			Domain:      strings.ToLower(strings.TrimSpace(asString(row["domain"]))),
			Username:    strings.TrimSpace(asString(row["username"])),
			Verified:    asBool(row["verified"]),
			Timestamp:   toRFC3339(asString(row["timestamp"])),
		}
		s.state.Contracts[id] = rec
		if rec.ContentHash != "" {
			s.state.HashContracts[rec.ContentHash] = appendUnique(s.state.HashContracts[rec.ContentHash], id)
		}
		if rec.Domain != "" {
			s.state.DomainContract[rec.Domain] = appendUnique(s.state.DomainContract[rec.Domain], id)
		}
	}

	s.state.Sync = SyncState{
		LastFullSync:  now,
		ContentItems:  len(ss.Content),
		DNSItems:      len(ss.DNS),
		ContractItems: len(ss.Contracts),
		UserItems:     len(ss.Users),
	}
	s.state.UpdatedAt = now
	_ = s.saveLocked()
}

func (s *LocalStore) KnownContractIDs(hash, domain string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	if h := strings.TrimSpace(hash); h != "" {
		out = append(out, s.state.HashContracts[h]...)
	}
	if d := strings.ToLower(strings.TrimSpace(domain)); d != "" {
		out = append(out, s.state.DomainContract[d]...)
	}
	return uniqueSorted(out)
}

func (s *LocalStore) load() error {
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		return err
	}
	var st ProxyLocalState
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	if st.Servers == nil {
		st.Servers = map[string]ServerAccess{}
	}
	if st.DNS == nil {
		st.DNS = map[string]string{}
	}
	if st.Files == nil {
		st.Files = map[string]FileRecord{}
	}
	if st.Contracts == nil {
		st.Contracts = map[string]ContractRecord{}
	}
	if st.Vouchers == nil {
		st.Vouchers = map[string]VoucherRecord{}
	}
	if st.Visits == nil {
		st.Visits = []VisitRecord{}
	}
	if st.HashContracts == nil {
		st.HashContracts = map[string][]string{}
	}
	if st.DomainContract == nil {
		st.DomainContract = map[string][]string{}
	}
	if st.HashVouchers == nil {
		st.HashVouchers = map[string][]string{}
	}
	if st.DomainVouchers == nil {
		st.DomainVouchers = map[string][]string{}
	}
	s.state = st
	return nil
}

func (s *LocalStore) saveLocked() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.statePath, raw, 0o600)
}

func sanitizeForFilename(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var out []rune
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			out = append(out, r)
		}
	}
	return strings.TrimSpace(string(out))
}

func appendUnique(in []string, item string) []string {
	item = strings.TrimSpace(item)
	if item == "" {
		return in
	}
	for _, v := range in {
		if strings.EqualFold(v, item) {
			return in
		}
	}
	return append(in, item)
}

func uniqueSorted(in []string) []string {
	set := map[string]struct{}{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		set[v] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func evaluateIntegrity(expectedHash, localSHA256 string) IntegrityResult {
	h := strings.ToLower(strings.TrimSpace(expectedHash))
	s := strings.ToLower(strings.TrimSpace(localSHA256))
	if h == "" || s == "" {
		return IntegrityResult{SHA256: s, Status: "unknown", Reason: "missing_hash"}
	}
	if isHexLen(h, 64) {
		if h == s {
			return IntegrityResult{SHA256: s, Status: "verified", Reason: "sha256_match"}
		}
		return IntegrityResult{SHA256: s, Status: "failed", Reason: "sha256_mismatch"}
	}
	return IntegrityResult{SHA256: s, Status: "unverified", Reason: "hash_format_not_sha256_hex"}
}

func isHexLen(v string, size int) bool {
	if len(v) != size {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		return s == "1" || s == "true" || s == "yes"
	default:
		return false
	}
}

func toRFC3339(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Now().UTC().Format(time.RFC3339)
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return raw
}
