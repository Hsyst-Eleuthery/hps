package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sqlite3 "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

var dbLock sync.Mutex

// Config mirrors CLI arguments in the Python server.
type Config struct {
	DBPath           string
	FilesDir         string
	Host             string
	AdvertiseHost    string
	Port             int
	SSLCert          string
	SSLKey           string
	OwnerEnabled     bool
	OwnerUsername    string
	ExchangeFeeRate  float64
	ExchangeFeeMin   int
	ExchangeQuoteTTL int
	MasterPassphrase string
}

type Server struct {
	cfg               Config
	DB                *sql.DB
	PrivateKey        *rsa.PrivateKey
	PublicKeyPEM      []byte
	storageKey        []byte
	OwnerPassword     string
	OwnerPasswordHash string

	ExchangeFeeRate  float64
	ExchangeFeeMin   int
	ExchangeQuoteTTL int

	FilesDir string
	Host     string
	Port     int

	ServerID    string
	BindAddress string
	Address     string
	StartTime   time.Time

	ConnectedClients int64

	BannedClients     map[string]float64
	mu                sync.Mutex
	powMu             sync.RWMutex
	lastNetworkSyncAt time.Time

	HpsPowCosts map[string]int

	ExchangeTokens map[string]map[string]any

	PowChallenges   map[string]PowChallenge
	LoginAttempts   map[string][]float64
	ClientHashrates map[string]float64

	HpsVoucherUnitBits int
	HpsVoucherMaxValue int

	UserEventEmitter func(username, event string, payload map[string]any)
}

func (s *Server) OwnerEnabled() bool {
	return s.cfg.OwnerEnabled
}

func (s *Server) OwnerUsername() string {
	return s.cfg.OwnerUsername
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.OwnerUsername == "" {
		cfg.OwnerUsername = OwnerUsernameDefault
	}
	if cfg.ExchangeFeeRate == 0 {
		cfg.ExchangeFeeRate = 0.02
	}
	if cfg.ExchangeFeeMin == 0 {
		cfg.ExchangeFeeMin = 1
	}

	if cfg.FilesDir == "" {
		cfg.FilesDir = "hps_files"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "hps_server.db"
	}
	cfg.FilesDir = normalizePath(cfg.FilesDir)
	cfg.DBPath = normalizePath(cfg.DBPath)

	s := &Server{
		cfg:              cfg,
		FilesDir:         cfg.FilesDir,
		Host:             cfg.Host,
		Port:             cfg.Port,
		ExchangeFeeRate:  cfg.ExchangeFeeRate,
		ExchangeFeeMin:   cfg.ExchangeFeeMin,
		ServerID:         newUUID(),
		StartTime:        time.Now(),
		BannedClients:    map[string]float64{},
		ExchangeQuoteTTL: 600,
		HpsPowCosts: map[string]int{
			"upload":             4,
			"dns":                4,
			"report":             4,
			"contract_transfer":  4,
			"contract_reset":     4,
			"contract_certify":   4,
			"usage_contract":     4,
			"hps_transfer":       4,
			"inventory_transfer": 1,
			"issuer_recheck":     2,
		},
		ExchangeTokens:     map[string]map[string]any{},
		PowChallenges:      map[string]PowChallenge{},
		LoginAttempts:      map[string][]float64{},
		ClientHashrates:    map[string]float64{},
		HpsVoucherUnitBits: 8,
		HpsVoucherMaxValue: 50,
	}

	s.BindAddress = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	advertiseHost := strings.TrimSpace(cfg.AdvertiseHost)
	if advertiseHost == "" {
		advertiseHost = detectAdvertiseHost(cfg.Host)
	}
	s.Address = fmt.Sprintf("%s:%d", advertiseHost, cfg.Port)

	if err := s.ensureDirs(); err != nil {
		return nil, err
	}
	if err := s.initStorageCrypto(); err != nil {
		return nil, err
	}
	if err := s.openDB(); err != nil {
		return nil, err
	}
	if err := s.loadEncryptedDatabaseSnapshot(); err != nil {
		return nil, err
	}
	if err := s.generateKeys(); err != nil {
		return nil, err
	}
	if err := s.initDatabase(); err != nil {
		return nil, err
	}
	s.LoadConfiguredPrices()
	if err := s.persistEncryptedDatabaseSnapshot(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Server) ListenAddr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *Server) Close() error {
	var firstErr error
	if err := s.persistEncryptedDatabaseSnapshot(); err != nil && firstErr == nil {
		firstErr = err
	}
	if s.DB != nil {
		if err := s.DB.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if len(s.storageKey) > 0 {
		zeroBytes(s.storageKey)
		s.storageKey = nil
	}
	return firstErr
}

func normalizePath(path string) string {
	if path == "" {
		return path
	}
	if strings.HasPrefix(path, "~") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if path == "~" {
				path = home
			} else if strings.HasPrefix(path, "~/") {
				path = filepath.Join(home, path[2:])
			}
		}
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	return path
}

func (s *Server) ensureDirs() error {
	if err := os.MkdirAll(s.FilesDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.FilesDir, "contracts"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.FilesDir, "vouchers"), 0o755); err != nil {
		return err
	}
	return nil
}

func (s *Server) generateKeys() error {
	keyPath := filepath.Join(s.FilesDir, "server_key.pem")
	if key, err := loadPrivateKeyFromFile(keyPath); err == nil && key != nil {
		s.PrivateKey = key
		s.PublicKeyPEM = pemEncodePublicKey(key)
		return nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	s.PrivateKey = key
	s.PublicKeyPEM = pemEncodePublicKey(key)
	return savePrivateKeyToFile(keyPath, key)
}

func (s *Server) openDB() error {
	memName := fmt.Sprintf("file:hpsserver-%d-%d?mode=memory&cache=shared", s.cfg.Port, time.Now().UnixNano())
	db, err := sql.Open("sqlite", memName)
	if err != nil {
		return err
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		db.Close()
		return err
	}
	if _, err := db.Exec("PRAGMA busy_timeout=30000"); err != nil {
		db.Close()
		return err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	s.DB = db
	return nil
}

func (s *Server) serializeMemoryDatabase() ([]byte, error) {
	if s.DB == nil {
		return nil, nil
	}
	conn, err := s.DB.Conn(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var out []byte
	err = conn.Raw(func(driverConn any) error {
		serializer, ok := driverConn.(interface {
			Serialize() ([]byte, error)
		})
		if !ok {
			return errors.New("sqlite driver does not support serialization")
		}
		var innerErr error
		out, innerErr = serializer.Serialize()
		return innerErr
	})
	return out, err
}

func (s *Server) deserializeMemoryDatabase(buf []byte) error {
	if s.DB == nil || len(buf) == 0 {
		return nil
	}
	conn, err := s.DB.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Raw(func(driverConn any) error {
		serializer, ok := driverConn.(interface {
			Deserialize([]byte) error
		})
		if !ok {
			return errors.New("sqlite driver does not support deserialization")
		}
		return serializer.Deserialize(buf)
	})
}

var _ = sqlite3.Driver{}

func (s *Server) initDatabase() error {
	dbLock.Lock()
	defer dbLock.Unlock()

	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		return err
	}
	if _, err := s.DB.Exec(string(schema)); err != nil {
		return err
	}

	if err := s.ensureColumn("user_reputations", "contract_penalty_base", "ALTER TABLE user_reputations ADD COLUMN contract_penalty_base INTEGER"); err != nil {
		return err
	}
	if err := s.ensureColumn("user_reputations", "reputation_credit", "ALTER TABLE user_reputations ADD COLUMN reputation_credit INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("users", "reputation_credit", "ALTER TABLE users ADD COLUMN reputation_credit INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("miner_stats", "pending_fines", "ALTER TABLE miner_stats ADD COLUMN pending_fines INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("miner_stats", "fine_promise_amount", "ALTER TABLE miner_stats ADD COLUMN fine_promise_amount REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("miner_stats", "fine_promise_active", "ALTER TABLE miner_stats ADD COLUMN fine_promise_active INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("pending_transfers", "hps_amount", "ALTER TABLE pending_transfers ADD COLUMN hps_amount INTEGER"); err != nil {
		return err
	}
	if err := s.ensureColumn("pending_transfers", "hps_total_value", "ALTER TABLE pending_transfers ADD COLUMN hps_total_value INTEGER"); err != nil {
		return err
	}
	if err := s.ensureColumn("pending_transfers", "hps_voucher_ids", "ALTER TABLE pending_transfers ADD COLUMN hps_voucher_ids TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("pending_transfers", "hps_session_id", "ALTER TABLE pending_transfers ADD COLUMN hps_session_id TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("pending_transfers", "requester_user", "ALTER TABLE pending_transfers ADD COLUMN requester_user TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("pending_transfers", "request_payload", "ALTER TABLE pending_transfers ADD COLUMN request_payload TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "inter_server_payload", "ALTER TABLE monetary_transfers ADD COLUMN inter_server_payload TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_username", "ALTER TABLE monetary_transfers ADD COLUMN selector_username TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_status", "ALTER TABLE monetary_transfers ADD COLUMN selector_status TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_deadline", "ALTER TABLE monetary_transfers ADD COLUMN selector_deadline REAL"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_commit", "ALTER TABLE monetary_transfers ADD COLUMN selector_commit TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_nonce", "ALTER TABLE monetary_transfers ADD COLUMN selector_nonce TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_client_nonce", "ALTER TABLE monetary_transfers ADD COLUMN selector_client_nonce TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_seed", "ALTER TABLE monetary_transfers ADD COLUMN selector_seed TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_list_json", "ALTER TABLE monetary_transfers ADD COLUMN selector_list_json TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "miner_list_json", "ALTER TABLE monetary_transfers ADD COLUMN miner_list_json TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_fee_amount", "ALTER TABLE monetary_transfers ADD COLUMN selector_fee_amount INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_rewarded", "ALTER TABLE monetary_transfers ADD COLUMN selector_rewarded INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("monetary_transfers", "selector_attempts", "ALTER TABLE monetary_transfers ADD COLUMN selector_attempts INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("hps_vouchers", "lineage_root_voucher_id", "ALTER TABLE hps_vouchers ADD COLUMN lineage_root_voucher_id TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("hps_vouchers", "lineage_parent_voucher_id", "ALTER TABLE hps_vouchers ADD COLUMN lineage_parent_voucher_id TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("hps_vouchers", "lineage_parent_hash", "ALTER TABLE hps_vouchers ADD COLUMN lineage_parent_hash TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("hps_vouchers", "lineage_depth", "ALTER TABLE hps_vouchers ADD COLUMN lineage_depth INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("hps_vouchers", "lineage_origin", "ALTER TABLE hps_vouchers ADD COLUMN lineage_origin TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("client_files", "published", "ALTER TABLE client_files ADD COLUMN published INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("client_contracts", "content_hash", "ALTER TABLE client_contracts ADD COLUMN content_hash TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("client_contracts", "domain", "ALTER TABLE client_contracts ADD COLUMN domain TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("content", "issuer_server", "ALTER TABLE content ADD COLUMN issuer_server TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("content", "issuer_public_key", "ALTER TABLE content ADD COLUMN issuer_public_key TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("content", "issuer_contract_id", "ALTER TABLE content ADD COLUMN issuer_contract_id TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("content", "issuer_issued_at", "ALTER TABLE content ADD COLUMN issuer_issued_at REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("dns_records", "issuer_server", "ALTER TABLE dns_records ADD COLUMN issuer_server TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("dns_records", "issuer_public_key", "ALTER TABLE dns_records ADD COLUMN issuer_public_key TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("dns_records", "issuer_contract_id", "ALTER TABLE dns_records ADD COLUMN issuer_contract_id TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("dns_records", "issuer_issued_at", "ALTER TABLE dns_records ADD COLUMN issuer_issued_at REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureEconomyStatsDefaults(); err != nil {
		return err
	}
	if err := s.ensureCustodyUser(); err != nil {
		return err
	}
	if err := s.ensureOwnerUser(); err != nil {
		return err
	}

	return nil
}

func (s *Server) ensureColumn(table, column, alter string) error {
	rows, err := s.DB.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	_, err = s.DB.Exec(alter)
	return err
}

func (s *Server) ensureEconomyStatsDefaults() error {
	defaults := map[string]any{
		"total_minted":              0.0,
		"custody_balance":           0.0,
		"owner_balance":             0.0,
		"rebate_balance":            0.0,
		"last_economy_hash":         "",
		"last_economy_contract_id":  "",
		"last_economy_update_ts":    0.0,
		"last_economy_event_ts":     0.0,
		"last_economy_event_reason": "",
	}
	for key, value := range defaults {
		var existing any
		err := s.DB.QueryRow("SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?", key).Scan(&existing)
		if errors.Is(err, sql.ErrNoRows) {
			_, err = s.DB.Exec("INSERT INTO hps_economy_stats (stat_key, stat_value) VALUES (?, ?)", key, value)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	return nil
}

func (s *Server) ensureCustodyUser() error {
	serverKeyB64 := base64.StdEncoding.EncodeToString(s.PublicKeyPEM)
	var existing string
	err := s.DB.QueryRow("SELECT public_key FROM users WHERE username = ?", CustodyUsername).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		passwordHash := sha256Hex(CustodyUsername)
		_, err = s.DB.Exec(`INSERT OR IGNORE INTO users
			(username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			CustodyUsername, passwordHash, serverKeyB64, now(), now(), 100, "system", now())
		return err
	}
	if err != nil {
		return err
	}
	if existing != serverKeyB64 {
		_, err = s.DB.Exec("UPDATE users SET public_key = ? WHERE username = ?", serverKeyB64, CustodyUsername)
		return err
	}
	return nil
}

func (s *Server) ensureOwnerUser() error {
	if !s.cfg.OwnerEnabled {
		return nil
	}
	password, err := s.loadOrCreateOwnerPassword()
	if err != nil || password == "" {
		return err
	}
	s.OwnerPassword = password
	s.OwnerPasswordHash = sha256Hex(password)

	var storedHash, storedKey string
	err = s.DB.QueryRow("SELECT password_hash, public_key FROM users WHERE username = ?", s.cfg.OwnerUsername).Scan(&storedHash, &storedKey)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = s.DB.Exec(`INSERT OR IGNORE INTO users
			(username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			s.cfg.OwnerUsername, s.OwnerPasswordHash, PendingPublicKeyLabel, now(), 0.0, 100, "system", now())
		if err != nil {
			return err
		}
		_, err = s.DB.Exec(`INSERT OR REPLACE INTO user_reputations
			(username, reputation, last_updated, client_identifier) VALUES (?, ?, ?, ?)`,
			s.cfg.OwnerUsername, 100, now(), "system")
		return err
	}
	if err != nil {
		return err
	}
	if storedHash != s.OwnerPasswordHash {
		_, err = s.DB.Exec("UPDATE users SET password_hash = ? WHERE username = ?", s.OwnerPasswordHash, s.cfg.OwnerUsername)
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(storedKey) == "" {
		_, err = s.DB.Exec("UPDATE users SET public_key = ? WHERE username = ?", PendingPublicKeyLabel, s.cfg.OwnerUsername)
		return err
	}
	return nil
}

func (s *Server) loadOrCreateOwnerPassword() (string, error) {
	path := filepath.Join(s.FilesDir, "owner_credentials.txt")
	if b, err := os.ReadFile(path); err == nil {
		value := strings.TrimSpace(string(b))
		if value == "" {
			return "", nil
		}
		if strings.Contains(value, ":") {
			parts := strings.SplitN(value, ":", 2)
			return strings.TrimSpace(parts[1]), nil
		}
		return value, nil
	}
	password := randomToken(12)
	content := fmt.Sprintf("%s:%s\n", s.cfg.OwnerUsername, password)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return password, nil
}

func now() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

func sha256Hex(value string) string {
	h := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", h)
}

func randomToken(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Printf("random token fallback: %v", err)
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func detectAdvertiseHost(bindHost string) string {
	if bindHost != "" && bindHost != "0.0.0.0" {
		return bindHost
	}
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr.IP == nil {
		return "127.0.0.1"
	}
	return localAddr.IP.String()
}

func pemEncodePublicKey(key *rsa.PrivateKey) []byte {
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return append([]byte("-----BEGIN PUBLIC KEY-----\n"), append(chunkBase64(pub), []byte("-----END PUBLIC KEY-----\n")...)...)
}

func loadPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("not RSA private key")
	default:
		return nil, errors.New("unsupported private key type")
	}
}

func savePrivateKeyToFile(path string, key *rsa.PrivateKey) error {
	if key == nil {
		return errors.New("missing private key")
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

func chunkBase64(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	for len(enc) > 0 {
		line := enc
		if len(line) > 64 {
			line = enc[:64]
		}
		out.WriteString(line)
		out.WriteString("\n")
		if len(enc) > 64 {
			enc = enc[64:]
		} else {
			break
		}
	}
	return []byte(out.String())
}
