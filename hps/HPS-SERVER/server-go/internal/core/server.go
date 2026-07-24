package core

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// M8 FIX: Atomic counter for UUID fallback
var uuidCounter int64

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

	MaxTxTimeSeconds float64
	MinTxTimeSeconds float64
	VolatileFees     bool
	NetworkMode      string
}

type Server struct {
	cfg               Config
	DB                *sql.DB
	PrivateKey        crypto.PrivateKey   // Server identity key (Ed25519 for signing)
	PublicKeyPEM      []byte
	CustodyKey        crypto.PrivateKey   // Economic operations (custody signing)
	CustodyKeyPEM     []byte
	IssuerKey         crypto.PrivateKey   // Voucher issuance
	IssuerKeyPEM      []byte
	StorageKey        crypto.PrivateKey   // Storage encryption (separate from server key)
	StorageKeyPEM     []byte
	EncryptionKey     *ecdh.PrivateKey    // X25519 key for DKVHPS encryption (replaces RSA-OAEP)
	EncryptionKeyPEM  []byte              // PEM-encoded X25519 public key
	storageKey        []byte              // AES storage key (derived from master pass)
	OwnerPasswordHash string

	ExchangeFeeRate  float64
	ExchangeFeeMin   int
	ExchangeQuoteTTL int

	FilesDir string
	Host     string
	Port     int
	HasTLS   bool

	ServerID    string
	BindAddress string
	Address     string
	StartTime   time.Time

	ConnectedClients int64

	BannedClients     map[string]float64
	mu                sync.Mutex
	powMu             sync.RWMutex
	stateMu           sync.RWMutex
	economyMu         sync.Mutex // Protects economy stat reads/writes
	dbMu              sync.RWMutex // Serializes SQLite operations (Lock for writes, RLock for reads)
	txMu              sync.Mutex   // Protects currentTx/txNesting/txMustRollback (allows reentrant BeginTx)
	txNesting         int32        // Nested BeginTx depth (>=1 when in a transaction)
	txMustRollback    bool         // Inner RollbackTx signals outer CommitTx to roll back instead
	lastNetworkSyncAt time.Time

	HpsPowCosts map[string]int

	ExchangeTokens map[string]map[string]any

	PowChallenges   map[string]PowChallenge
	LoginAttempts   map[string][]float64
	ClientHashrates map[string]float64

	HpsVoucherUnitBits int
	HpsVoucherMaxValue int

	ConfigData *ServerConfigData

	UserEventEmitter func(username, event string, payload map[string]any)
	done             chan struct{}

	currentTx *sql.Tx // Active transaction for TxExec/TxQuery/TxQueryRow
}

func (s *Server) OwnerEnabled() bool {
	return s.cfg.OwnerEnabled
}

func (s *Server) OwnerUsername() string {
	return s.cfg.OwnerUsername
}

func (s *Server) BeginTx() error {
	s.txMu.Lock()
	if s.currentTx != nil {
		s.txNesting++
		s.txMu.Unlock()
		return nil
	}
	s.dbMu.Lock()
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		s.dbMu.Unlock()
		s.txMu.Unlock()
		return err
	}
	s.currentTx = tx
	s.txNesting = 1
	s.txMustRollback = false
	s.txMu.Unlock()
	return nil
}

func (s *Server) CommitTx() {
	s.txMu.Lock()
	if s.currentTx == nil {
		s.txMu.Unlock()
		return
	}
	s.txNesting--
	if s.txNesting > 0 {
		s.txMu.Unlock()
		return
	}
	tx := s.currentTx
	s.currentTx = nil
	mustRollback := s.txMustRollback
	s.txMu.Unlock()
	if mustRollback {
		tx.Rollback()
	} else {
		tx.Commit()
	}
	s.dbMu.Unlock()
}

func (s *Server) RollbackTx() {
	s.txMu.Lock()
	if s.currentTx == nil {
		s.txMu.Unlock()
		return
	}
	s.txNesting--
	if s.txNesting > 0 {
		s.txMustRollback = true
		s.txMu.Unlock()
		return
	}
	tx := s.currentTx
	s.currentTx = nil
	s.txMustRollback = false
	s.txMu.Unlock()
	tx.Rollback()
	s.dbMu.Unlock()
}

func (s *Server) RLockDB() {
	s.txMu.Lock()
	inTx := s.currentTx != nil
	s.txMu.Unlock()
	if inTx {
		return
	}
	s.dbMu.RLock()
}

func (s *Server) RUnlockDB() {
	s.txMu.Lock()
	inTx := s.currentTx != nil
	s.txMu.Unlock()
	if inTx {
		return
	}
	s.dbMu.RUnlock()
}

func (s *Server) TxExec(query string, args ...any) (sql.Result, error) {
	if s.currentTx != nil {
		return s.currentTx.Exec(query, args...)
	}
	return s.DB.Exec(query, args...)
}

func (s *Server) TxQuery(query string, args ...any) (*sql.Rows, error) {
	if s.currentTx != nil {
		return s.currentTx.Query(query, args...)
	}
	return s.DB.Query(query, args...)
}

func (s *Server) TxQueryRow(query string, args ...any) *sql.Row {
	if s.currentTx != nil {
		return s.currentTx.QueryRow(query, args...)
	}
	return s.DB.QueryRow(query, args...)
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
		HasTLS:           cfg.SSLCert != "" || cfg.SSLKey != "",
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
			"issuer_recheck":     2,
		},
		ExchangeTokens:     map[string]map[string]any{},
		PowChallenges:      map[string]PowChallenge{},
		LoginAttempts:      map[string][]float64{},
		ClientHashrates:    map[string]float64{},
		HpsVoucherUnitBits: 8,
		HpsVoucherMaxValue: 50,
		done:               make(chan struct{}),
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
	if err := s.generateKeys(); err != nil {
		return nil, err
	}
	if err := s.openDB(); err != nil {
		return nil, err
	}

	s.LoadConfiguredPrices()

	if err := s.BootstrapConfig(); err != nil {
		log.Printf("WARN: config bootstrap: %v", err)
	}

	if s.cfg.MaxTxTimeSeconds <= 0 {
		s.cfg.MaxTxTimeSeconds = 120.0
	}
	if s.cfg.MinTxTimeSeconds <= 0 {
		s.cfg.MinTxTimeSeconds = 60.0
	}
	if s.cfg.MaxTxTimeSeconds < s.cfg.MinTxTimeSeconds {
		s.cfg.MaxTxTimeSeconds = s.cfg.MinTxTimeSeconds
	}

	log.Printf("INFO: server initialization complete")

	return s, nil
}

func (s *Server) ListenAddr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *Server) AddressURL() string {
	if s.HasTLS {
		return "https://" + s.Address
	}
	return "http://" + s.Address
}

func (s *Server) Close() error {
	log.Printf("INFO: server shutdown initiated")
	var firstErr error
	close(s.done)
	if s.DB != nil {
		if _, err := s.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			log.Printf("WARN: failed to checkpoint WAL: %v", err)
		}
	}
	if err := s.persistEncryptedDatabaseSnapshot(); err != nil {
		log.Printf("WARN: final seal failed: %v", err)
	}
	if s.DB != nil {
		if err := s.DB.Close(); err != nil {
			log.Printf("ERROR: failed to close database connection: %v", err)
			firstErr = err
		} else {
			log.Printf("INFO: database connection closed and synced")
		}
	}
	if len(s.storageKey) > 0 {
		s.cleanupPlaintextDatabaseArtifacts()
		zeroBytes(s.storageKey)
		s.storageKey = nil
		log.Printf("INFO: storage key cleared from memory")
	}
	log.Printf("INFO: server shutdown complete")
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
	type keyTask struct {
		name   string
		loadFn func() (crypto.PrivateKey, error)
		saveFn func(crypto.PrivateKey) error
		keyPtr *crypto.PrivateKey
		pemPtr *[]byte
	}
	tasks := []keyTask{
		{"server_key", func() (crypto.PrivateKey, error) { return s.loadServerPrivateKey() }, func(k crypto.PrivateKey) error { return s.saveServerPrivateKey(k) }, &s.PrivateKey, &s.PublicKeyPEM},
		{"custody_key", func() (crypto.PrivateKey, error) { return s.loadSubKey("custody_key") }, func(k crypto.PrivateKey) error { return s.saveSubKey("custody_key", k) }, &s.CustodyKey, &s.CustodyKeyPEM},
		{"issuer_key", func() (crypto.PrivateKey, error) { return s.loadSubKey("issuer_key") }, func(k crypto.PrivateKey) error { return s.saveSubKey("issuer_key", k) }, &s.IssuerKey, &s.IssuerKeyPEM},
		{"storage_key", func() (crypto.PrivateKey, error) { return s.loadSubKey("storage_key") }, func(k crypto.PrivateKey) error { return s.saveSubKey("storage_key", k) }, &s.StorageKey, &s.StorageKeyPEM},
	}

	type result struct {
		idx int
		key crypto.PrivateKey
		pem []byte
		err error
	}
	results := make(chan result, len(tasks))

	for i, t := range tasks {
		i, t := i, t
		go func() {
			log.Printf("INFO: %s: checking for existing key...", t.name)
			loaded, loadErr := t.loadFn()
			if loadErr == nil && loaded != nil {
				results <- result{i, loaded, pemEncodePublicKey(loaded), nil}
				return
			}
			log.Printf("INFO: %s: generating new ECDSA P-256 key...", t.name)
			priv, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if genErr != nil {
				results <- result{idx: i, err: fmt.Errorf("%s generate: %w", t.name, genErr)}
				return
			}
			if saveErr := t.saveFn(priv); saveErr != nil {
				log.Printf("WARN: %s: failed to save key: %v", t.name, saveErr)
			}
			results <- result{i, priv, pemEncodePublicKey(priv), nil}
		}()
	}

	var firstErr error
	for range tasks {
		r := <-results
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		if r.key != nil {
			*tasks[r.idx].keyPtr = r.key
			*tasks[r.idx].pemPtr = r.pem
		}
	}
	if firstErr != nil {
		return firstErr
	}

	// Generate X25519 encryption key for DKVHPS (ECDH-based encryption)
	log.Printf("INFO: loading or generating X25519 encryption key...")
	encKey, err := s.loadEncryptionKey()
	if err == nil && encKey != nil {
		s.EncryptionKey = encKey
	} else {
		log.Printf("INFO: generating X25519 encryption key...")
		encKey, genErr := ecdh.X25519().GenerateKey(rand.Reader)
		if genErr != nil {
			return fmt.Errorf("x25519 generate: %w", genErr)
		}
		if saveErr := s.saveEncryptionKey(encKey); saveErr != nil {
			log.Printf("WARN: failed to save encryption key: %v", saveErr)
		}
		s.EncryptionKey = encKey
	}
	if s.EncryptionKey != nil {
		pubKey := s.EncryptionKey.PublicKey()
		pubDER, _ := x509.MarshalPKIXPublicKey(pubKey)
		s.EncryptionKeyPEM = append([]byte("-----BEGIN PUBLIC KEY-----\n"), append(chunkBase64(pubDER), []byte("-----END PUBLIC KEY-----\n")...)...)
	}

	log.Printf("INFO: key separation active: server_key + custody_key + issuer_key + storage_key")
	return nil
}

func (s *Server) loadSubKey(name string) (crypto.PrivateKey, error) {
	if len(s.storageKey) > 0 {
		encPath := filepath.Join(s.FilesDir, name+".enc")
		if pathExists(encPath) {
			data, err := os.ReadFile(encPath)
			if err != nil {
				return nil, err
			}
			var env encryptedKeyEnvelope
			if err := json.Unmarshal(data, &env); err != nil {
				return nil, err
			}
			nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
			if err != nil {
				return nil, err
			}
			ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
			if err != nil {
				return nil, err
			}
			block, err := aes.NewCipher(s.storageKey)
			if err != nil {
				return nil, err
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}
			plain, err := gcm.Open(nil, nonce, ct, nil)
			if err != nil {
				return nil, err
			}
			return loadPrivateKeyFromBytes(plain)
		}
	}
	pemPath := filepath.Join(s.FilesDir, name+".pem")
	return loadPrivateKeyFromFile(pemPath)
}

func (s *Server) saveSubKey(name string, key crypto.PrivateKey) error {
	if len(s.storageKey) > 0 {
		encPath := filepath.Join(s.FilesDir, name+".enc")
		block, err := aes.NewCipher(s.storageKey)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
		defer zeroBytes(keyBytes)
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		ct := gcm.Seal(nil, nonce, keyBytes, nil)
		env := encryptedKeyEnvelope{
			Version:    1,
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ct),
		}
		data, err := json.Marshal(env)
		if err != nil {
			return err
		}
		if err := os.WriteFile(encPath, data, 0o600); err != nil {
			return err
		}
		pemPath := filepath.Join(s.FilesDir, name+".pem")
		if pathExists(pemPath) {
			_ = os.Remove(pemPath)
		}
		return nil
	}
	keyPath := filepath.Join(s.FilesDir, name+".pem")
	return savePrivateKeyToFile(keyPath, key)
}

func (s *Server) loadServerPrivateKey() (crypto.PrivateKey, error) {
	if len(s.storageKey) > 0 {
		encPath := filepath.Join(s.FilesDir, "server_key.enc")
		if pathExists(encPath) {
			data, err := os.ReadFile(encPath)
			if err != nil {
				return nil, err
			}
			var env encryptedKeyEnvelope
			if err := json.Unmarshal(data, &env); err != nil {
				return nil, err
			}
			nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
			if err != nil {
				return nil, err
			}
			ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
			if err != nil {
				return nil, err
			}
			block, err := aes.NewCipher(s.storageKey)
			if err != nil {
				return nil, err
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}
			plain, err := gcm.Open(nil, nonce, ct, nil)
			if err != nil {
				return nil, err
			}
			return loadPrivateKeyFromBytes(plain)
		}
	}
	keyPath := filepath.Join(s.FilesDir, "server_key.pem")
	return loadPrivateKeyFromFile(keyPath)
}

func (s *Server) saveServerPrivateKey(key crypto.PrivateKey) error {
	if len(s.storageKey) > 0 {
		encPath := filepath.Join(s.FilesDir, "server_key.enc")
		block, err := aes.NewCipher(s.storageKey)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
		defer zeroBytes(keyBytes)
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		ct := gcm.Seal(nil, nonce, keyBytes, nil)
		env := encryptedKeyEnvelope{
			Version:    1,
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ct),
		}
		data, err := json.Marshal(env)
		if err != nil {
			return err
		}
		if err := os.WriteFile(encPath, data, 0o600); err != nil {
			return err
		}
		plainPath := filepath.Join(s.FilesDir, "server_key.pem")
		if pathExists(plainPath) {
			_ = os.Remove(plainPath)
		}
		return nil
	}
	keyPath := filepath.Join(s.FilesDir, "server_key.pem")
	return savePrivateKeyToFile(keyPath, key)
}

func (s *Server) loadEncryptionKey() (*ecdh.PrivateKey, error) {
	name := "encryption_key"
	if len(s.storageKey) > 0 {
		encPath := filepath.Join(s.FilesDir, name+".enc")
		if pathExists(encPath) {
			data, err := os.ReadFile(encPath)
			if err != nil {
				return nil, err
			}
			var env encryptedKeyEnvelope
			if err := json.Unmarshal(data, &env); err != nil {
				return nil, err
			}
			nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
			if err != nil {
				return nil, err
			}
			ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
			if err != nil {
				return nil, err
			}
			block, err := aes.NewCipher(s.storageKey)
			if err != nil {
				return nil, err
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}
			plain, err := gcm.Open(nil, nonce, ct, nil)
			if err != nil {
				return nil, err
			}
			return ecdh.X25519().NewPrivateKey(plain)
		}
	}
	pemPath := filepath.Join(s.FilesDir, name+".pem")
	key, err := loadPrivateKeyFromFile(pemPath)
	if err != nil {
		return nil, err
	}
	if k, ok := key.(*ecdh.PrivateKey); ok {
		return k, nil
	}
	// Try to convert from PKCS8 to ecdh
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	if k, ok := parsed.(*ecdh.PrivateKey); ok {
		return k, nil
	}
	return nil, errors.New("loaded key is not X25519")
}

func (s *Server) saveEncryptionKey(key *ecdh.PrivateKey) error {
	name := "encryption_key"
	keyBytes := key.Bytes()
	if len(s.storageKey) > 0 {
		encPath := filepath.Join(s.FilesDir, name+".enc")
		block, err := aes.NewCipher(s.storageKey)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		defer zeroBytes(keyBytes)
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		ct := gcm.Seal(nil, nonce, keyBytes, nil)
		env := encryptedKeyEnvelope{
			Version:    1,
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ct),
		}
		data, err := json.Marshal(env)
		if err != nil {
			return err
		}
		if err := os.WriteFile(encPath, data, 0o600); err != nil {
			return err
		}
		pemPath := filepath.Join(s.FilesDir, name+".pem")
		if pathExists(pemPath) {
			_ = os.Remove(pemPath)
		}
		return nil
	}
	keyPath := filepath.Join(s.FilesDir, name+".pem")
	keyBytesPKCS8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytesPKCS8}
	return os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600)
}

func (s *Server) openDB() error {
	dbPath := strings.TrimSpace(s.cfg.DBPath)
	if dbPath == "" {
		return errors.New("database path is required")
	}
	dbPathAbs, err := filepath.Abs(s.cfg.DBPath)
	if err != nil {
		return fmt.Errorf("invalid database path: %w", err)
	}
	dir := filepath.Dir(dbPathAbs)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	if len(s.storageKey) > 0 {
		dsn := "file::memory:?cache=shared"
		db, err := sql.Open("sqlite3", dsn)
		if err != nil {
			return fmt.Errorf("failed to open in-memory database: %w", err)
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return fmt.Errorf("in-memory db ping failed: %w", err)
		}
		if _, err := db.Exec("PRAGMA journal_mode=OFF"); err != nil {
			db.Close()
			return fmt.Errorf("failed to set journal mode: %w", err)
		}
		db.SetMaxOpenConns(4)
		db.SetMaxIdleConns(2)
		s.DB = db
		// Apply schema first so tables exist before loading snapshot data
		if err := s.initDatabase(); err != nil {
			log.Printf("WARN: failed to initialize schema before snapshot load: %v", err)
		}
		if err := s.loadEncryptedSnapshotToMemory(); err != nil {
			log.Printf("WARN: failed to load encrypted snapshot into memory: %v", err)
		}
		log.Printf("INFO: in-memory database initialized with encrypted disk storage")
		return nil
	}

	connStr := fmt.Sprintf("file:%s?_journal=WAL&_busy_timeout=30000&_synchronous=NORMAL&_mmap_size=268435456", dbPathAbs)
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return fmt.Errorf("failed to set journal mode: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	s.DB = db
	if err := s.initDatabase(); err != nil {
		return nil
	}
	log.Printf("INFO: database opened at %s (go-sqlite3)", dbPathAbs)
	return nil
}

func (s *Server) cleanupPlaintextDatabaseArtifacts() {
	dbPath := strings.TrimSpace(s.cfg.DBPath)
	if dbPath == "" {
		return
	}
	// With encrypted storage, we use in-memory DB, so nothing to clean
	if len(s.storageKey) > 0 {
		return
	}
	base := dbPath
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := base + suffix
		if !pathExists(path) {
			continue
		}
		if err := SecureDeleteFile(path); err != nil {
			log.Printf("WARN: failed to securely remove plaintext database artifact %s: %v", path, err)
		}
	}
}
func (s *Server) serializeMemoryDatabase() ([]byte, error) {
	if s.DB == nil {
		return nil, nil
	}
	// Use a timeout to avoid blocking forever if all connections are busy
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var out []byte
	err = conn.Raw(func(driverConn any) error {
		sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("expected *sqlite3.SQLiteConn")
		}
		// Ensure no transaction is active before VACUUM (VACUUM requires no transaction)
		_, _ = sqliteConn.Exec("ROLLBACK", nil)
		var innerErr error
		out, innerErr = sqliteSerialize(sqliteConn, "")
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
		sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("expected *sqlite3.SQLiteConn")
		}
		return sqliteDeserialize(sqliteConn, buf, "")
	})
}

func (s *Server) deserializeMemoryDatabaseFromBytes(db *sql.DB, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Raw(func(driverConn any) error {
		sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("expected *sqlite3.SQLiteConn")
		}
		return sqliteDeserialize(sqliteConn, buf, "")
	})
}

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
	if err := s.ensureColumn("known_servers", "server_id", "ALTER TABLE known_servers ADD COLUMN server_id TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("known_servers", "latency", "ALTER TABLE known_servers ADD COLUMN latency REAL DEFAULT 0"); err != nil {
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
	if err := s.ensureColumn("monetary_transfers", "retry_count", "ALTER TABLE monetary_transfers ADD COLUMN retry_count INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("hps_voucher_offers", "voucher_id", "ALTER TABLE hps_voucher_offers ADD COLUMN voucher_id TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("hps_voucher_offers", "value", "ALTER TABLE hps_voucher_offers ADD COLUMN value INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := s.ensureColumn("hps_voucher_offers", "reason", "ALTER TABLE hps_voucher_offers ADD COLUMN reason TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("hps_voucher_offers", "status", "ALTER TABLE hps_voucher_offers ADD COLUMN status TEXT DEFAULT 'pending'"); err != nil {
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
	if err := s.ensureColumn("contracts", "issuer_server", "ALTER TABLE contracts ADD COLUMN issuer_server TEXT DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureEconomyStatsDefaults(); err != nil {
		return err
	}
	if err := s.ensureSecurityStatsDefaults(); err != nil {
		return err
	}
	if err := s.ensureCustodyUser(); err != nil {
		return err
	}
	if err := s.ensureOwnerUser(); err != nil {
		return err
	}
	if err := s.hardenDatabaseSchema(); err != nil {
		return err
	}

	return nil
}

func (s *Server) hardenDatabaseSchema() error {
	if _, err := s.DB.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return err
	}
	if _, err := s.DB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return err
	}
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS db_audit_triggers (
		trigger_name TEXT PRIMARY KEY,
		table_name TEXT NOT NULL,
		created_at REAL NOT NULL
	)`); err != nil {
		return err
	}
	// Create audit triggers for critical tables
	triggerDefs := []string{
		`CREATE TRIGGER IF NOT EXISTS trg_hps_vouchers_insert
		 AFTER INSERT ON hps_vouchers
		 BEGIN
			 INSERT OR IGNORE INTO db_audit_triggers (trigger_name, table_name, created_at)
			 VALUES ('trg_hps_vouchers_insert', 'hps_vouchers', ` + fmt.Sprintf("%.0f", now()) + `);
		 END`,
		`CREATE TRIGGER IF NOT EXISTS trg_hps_vouchers_update
		 AFTER UPDATE ON hps_vouchers
		 BEGIN
			 INSERT OR IGNORE INTO db_audit_triggers (trigger_name, table_name, created_at)
			 VALUES ('trg_hps_vouchers_update', 'hps_vouchers', ` + fmt.Sprintf("%.0f", now()) + `);
		 END`,
		`CREATE TRIGGER IF NOT EXISTS trg_monetary_transfers_insert
		 AFTER INSERT ON monetary_transfers
		 BEGIN
			 INSERT OR IGNORE INTO db_audit_triggers (trigger_name, table_name, created_at)
			 VALUES ('trg_monetary_transfers_insert', 'monetary_transfers', ` + fmt.Sprintf("%.0f", now()) + `);
		 END`,
		`CREATE TRIGGER IF NOT EXISTS trg_contracts_insert
		 AFTER INSERT ON contracts
		 BEGIN
			 INSERT OR IGNORE INTO db_audit_triggers (trigger_name, table_name, created_at)
			 VALUES ('trg_contracts_insert', 'contracts', ` + fmt.Sprintf("%.0f", now()) + `);
		 END`,
	}
	for _, trig := range triggerDefs {
		if _, err := s.DB.Exec(trig); err != nil {
			log.Printf("WARN: failed to create audit trigger: %v", err)
		}
	}
	log.Printf("INFO: database schema hardened with integrity checks and audit triggers")
	return nil
}

var validTableName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func (s *Server) ensureColumn(table, column, alter string) error {
	if !validTableName.MatchString(table) {
		return fmt.Errorf("invalid table name: %q", table)
	}
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
		"total_burned":              0.0,
		"custody_balance":           0.0,
		"owner_balance":             0.0,
		"rebate_balance":            0.0,
		"custody_subsidy_share":     0.5,
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
		passwordHash, hashErr := bcrypt.GenerateFromPassword([]byte(CustodyUsername), bcrypt.DefaultCost)
		if hashErr != nil {
			return hashErr
		}
		_, err = s.DB.Exec(`INSERT OR IGNORE INTO users
			(username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			CustodyUsername, string(passwordHash), serverKeyB64, now(), now(), 100, "system", now())
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

func (s *Server) ensureSecurityStatsDefaults() error {
	defaults := map[string]any{
		"supply_chain_hash":    "",
		"supply_chain_index":   0.0,
		"content_receipt_hash": "",
		"content_receipt_index": 0.0,
		"global_tx_counter":    0.0,
		"market_pending_transfers": 0.0,
		"market_available_miners":  0.0,
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

func (s *Server) ensureOwnerUser() error {
	if !s.cfg.OwnerEnabled {
		return nil
	}
	password, err := s.loadOrCreateOwnerPassword()
	if err != nil {
		return err
	}
	// If password is empty but hash was already loaded from file, use it directly.
	if password == "" && s.OwnerPasswordHash == "" {
		return fmt.Errorf("owner password hash unavailable")
	}
	if password != "" && s.OwnerPasswordHash == "" {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if hashErr != nil {
			return hashErr
		}
		s.OwnerPasswordHash = string(hash)
	}

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
	if bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)) != nil {
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
		parts := strings.SplitN(value, ":", 2)
		if len(parts) >= 2 {
			storedHash := strings.TrimSpace(parts[1])
			// If the stored value is a bcrypt hash, return it directly (migration from plaintext)
			if strings.HasPrefix(storedHash, "$2a$") || strings.HasPrefix(storedHash, "$2b$") || strings.HasPrefix(storedHash, "$2y$") {
				s.OwnerPasswordHash = storedHash
				return "", nil
			}
			return storedHash, nil
		}
		return value, nil
	}
	password := randomToken(12)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	content := fmt.Sprintf("%s:%s\n", s.cfg.OwnerUsername, string(hash))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	s.OwnerPasswordHash = string(hash)
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
	// M-02 FIX: Enforce minimum token size of 32 bytes
	if n < 32 {
		n = 32
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Printf("CRITICAL: crypto/rand.Read failed: %v", err)
		return ""
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// M8 FIX: Fallback with atomic counter + PID + timestamp for maximum entropy
		// Use multiple sources of entropy to make prediction harder
		nano := time.Now().UnixNano()
		pid := int64(os.Getpid())
		counter := atomic.AddInt64(&uuidCounter, 1)
		
		// Combine multiple entropy sources
		val := nano ^ pid ^ counter
		val = val & 0xFFFFFFFFFFFF // 48 bits
		
		b[0] = byte(val >> 40)
		b[1] = byte(val >> 32)
		b[2] = byte(val >> 24)
		b[3] = byte(val >> 16)
		b[4] = byte(val >> 8)
		b[5] = byte(val)
		
		// Use SHA-256 of all sources for remaining bytes
		h := sha256.Sum256([]byte(fmt.Sprintf("%d-%d-%d", nano, pid, counter)))
		copy(b[6:], h[:10])
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func detectAdvertiseHost(bindHost string) string {
	if bindHost != "" && bindHost != "0.0.0.0" {
		if net.ParseIP(bindHost) == nil {
			// Not a valid IP, try resolving as hostname
			ips, err := net.LookupIP(bindHost)
			if err != nil || len(ips) == 0 {
				return "127.0.0.1"
			}
			return ips[0].String()
		}
		return bindHost
	}
	dnsServer := os.Getenv("HPS_DNS_SERVER")
	if dnsServer == "" {
		dnsServer = "8.8.8.8:80"
	}
	conn, err := net.Dial("udp", dnsServer)
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

func pemEncodePublicKey(key crypto.PrivateKey) []byte {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(ecKey.Public())
	return append([]byte("-----BEGIN PUBLIC KEY-----\n"), append(chunkBase64(pubDER), []byte("-----END PUBLIC KEY-----\n")...)...)
}

func loadPrivateKeyFromFile(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func loadPrivateKeyFromBytes(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func savePrivateKeyToFile(path string, key crypto.PrivateKey) error {
	if key == nil {
		return errors.New("missing private key")
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}
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

func (s *Server) runDatabaseSealLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.persistEncryptedDatabaseSnapshot(); err != nil {
				log.Printf("ERROR: periodic seal failed: %v", err)
			}
		}
	}
}
