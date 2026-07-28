package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha256"
)

const configFileMagic = "HPSCFG1"
const configNonceSize = 12

type ServerConfigData struct {
	ServerName       string  `json:"server_name"`
	OwnerName        string  `json:"owner_name"`
	CustodyName      string  `json:"custody_name"`
	CustodyKey       string  `json:"custody_key"`
	MaxTxTimeSeconds float64 `json:"max_tx_time_seconds"`
	MinTxTimeSeconds float64 `json:"min_tx_time_seconds"`
	DefaultMinerFee  int     `json:"default_miner_fee"`
	VolatileFees     bool    `json:"volatile_fees"`
	ConfigVersion    int     `json:"config_version"`
	GeneratedAt      float64 `json:"generated_at"`
}

func DefaultServerConfig() *ServerConfigData {
	return &ServerConfigData{
		ServerName:       "HPS Server",
		OwnerName:        OwnerUsernameDefault,
		CustodyName:      CustodyUsername,
		MaxTxTimeSeconds: 120.0,
		MinTxTimeSeconds: 60.0,
		DefaultMinerFee:  5,
		VolatileFees:     true,
		ConfigVersion:    1,
		GeneratedAt:      now(),
	}
}

func (s *Server) ConfigFilePath() string {
	return filepath.Join(s.FilesDir, "server_config.json")
}

func (s *Server) ConfigEncryptedPath() string {
	return filepath.Join(s.FilesDir, "server_config.json.enc")
}

func (s *Server) GenerateConfigFile() error {
	cfg := DefaultServerConfig()
	cfg.ServerName = s.Address
	cfg.CustodyName = CustodyUsername
	cfg.OwnerName = s.cfg.OwnerUsername

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	path := s.ConfigFilePath()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	log.Printf("CONFIG: config file generated at %s", path)
	log.Printf("CONFIG: EDIT the file with your settings, then the server will encrypt it on next start")
	return nil
}

func (s *Server) LoadEncryptedConfig() (*ServerConfigData, error) {
	encPath := s.ConfigEncryptedPath()
	plainPath := s.ConfigFilePath()

	if pathExists(encPath) {
		raw, err := os.ReadFile(encPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read encrypted config: %w", err)
		}
		plain, err := decryptConfigBlob(s.storageKey, raw)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt config: %w", err)
		}
		var cfg ServerConfigData
		if err := json.Unmarshal(plain, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
		return &cfg, nil
	}

	if pathExists(plainPath) {
		raw, err := os.ReadFile(plainPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read plain config: %w", err)
		}
		var cfg ServerConfigData
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse plain config: %w", err)
		}
		if err := s.EncryptConfigFile(); err != nil {
			return nil, fmt.Errorf("failed to encrypt config after reading: %w", err)
		}
		log.Printf("CONFIG: config file encrypted after reading plaintext")
		return &cfg, nil
	}

	return nil, nil
}

func (s *Server) EncryptConfigFile() error {
	plainPath := s.ConfigFilePath()
	if !pathExists(plainPath) {
		return errors.New("config file not found")
	}
	raw, err := os.ReadFile(plainPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	blob, err := encryptConfigBlob(s.storageKey, raw)
	if err != nil {
		return fmt.Errorf("failed to encrypt config: %w", err)
	}
	encPath := s.ConfigEncryptedPath()
	tmpPath := encPath + ".new"
	if err := os.WriteFile(tmpPath, blob, 0o600); err != nil {
		return fmt.Errorf("failed to write encrypted config: %w", err)
	}
	if pathExists(encPath) {
		os.Remove(encPath)
	}
	if err := os.Rename(tmpPath, encPath); err != nil {
		return fmt.Errorf("failed to rename encrypted config: %w", err)
	}
	if err := os.Remove(plainPath); err != nil {
		log.Printf("CONFIG: failed to remove plain config file: %v", err)
	}
	log.Printf("CONFIG: config file encrypted at %s", encPath)
	return nil
}

func (s *Server) DecryptConfigToTemp() (string, error) {
	encPath := s.ConfigEncryptedPath()
	if !pathExists(encPath) {
		return "", errors.New("no encrypted config file found")
	}
	raw, err := os.ReadFile(encPath)
	if err != nil {
		return "", fmt.Errorf("failed to read encrypted config: %w", err)
	}
	plain, err := decryptConfigBlob(s.storageKey, raw)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt config: %w", err)
	}
	plainPath := s.ConfigFilePath()
	if err := os.WriteFile(plainPath, plain, 0o600); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}
	return plainPath, nil
}

func (s *Server) ApplyEncryptedConfigAndRestart() error {
	plainPath := s.ConfigFilePath()
	if !pathExists(plainPath) {
		return errors.New("plain config file not found for apply")
	}
	if err := s.EncryptConfigFile(); err != nil {
		return fmt.Errorf("failed to encrypt config: %w", err)
	}
	log.Printf("CONFIG: config applied, shutting down for restart")
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
	return nil
}

func encryptConfigBlob(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	out := make([]byte, len(configFileMagic)+len(nonce)+len(ciphertext))
	copy(out, []byte(configFileMagic))
	copy(out[len(configFileMagic):], nonce)
	copy(out[len(configFileMagic)+len(nonce):], ciphertext)
	return out, nil
}

func decryptConfigBlob(key, blob []byte) ([]byte, error) {
	if len(blob) < len(configFileMagic)+configNonceSize+16 {
		return nil, errors.New("invalid encrypted config blob")
	}
	if string(blob[:len(configFileMagic)]) != configFileMagic {
		return nil, errors.New("invalid config file magic")
	}
	nonce := blob[len(configFileMagic) : len(configFileMagic)+configNonceSize]
	ciphertext := blob[len(configFileMagic)+configNonceSize:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("config decryption failed (wrong key or corrupted file): %w", err)
	}
	return plain, nil
}

func (s *Server) generateConfigKey() []byte {
	info := s.ServerID + s.Address + CustodyUsername
	mac := hmac.New(sha256.New, []byte(info))
	mac.Write([]byte("hps-server-config-v1"))
	return mac.Sum(nil)[:32]
}

func (s *Server) BootstrapConfig() error {
	if len(s.storageKey) == 0 {
		return nil
	}

	encPath := s.ConfigEncryptedPath()
	plainPath := s.ConfigFilePath()

	if pathExists(encPath) {
		cfg, err := s.LoadEncryptedConfig()
		if err != nil {
			return fmt.Errorf("failed to load encrypted config: %w", err)
		}
		if cfg != nil {
			s.ConfigData = cfg
			s.applyConfigData(cfg)
		}
		return nil
	}

	if pathExists(plainPath) {
		cfg, err := s.LoadEncryptedConfig()
		if err != nil {
			return fmt.Errorf("failed to load plain config: %w", err)
		}
		if cfg != nil {
			s.ConfigData = cfg
			s.applyConfigData(cfg)
		}
		return nil
	}

	if err := s.GenerateConfigFile(); err != nil {
		return fmt.Errorf("failed to generate config: %w", err)
	}
	log.Printf("CONFIG: first run - config file generated. Edit %s and restart the server", plainPath)
	return nil
}

func (s *Server) MaxTxTimeSeconds() float64 {
	return s.cfg.MaxTxTimeSeconds
}

func (s *Server) MinTxTimeSeconds() float64 {
	return s.cfg.MinTxTimeSeconds
}

func (s *Server) IsVolatileFees() bool {
	return s.cfg.VolatileFees
}

func (s *Server) applyConfigData(cfg *ServerConfigData) {
	if cfg == nil {
		return
	}
	if cfg.MaxTxTimeSeconds <= 0 {
		cfg.MaxTxTimeSeconds = 120.0
	}
	if cfg.MinTxTimeSeconds <= 0 {
		cfg.MinTxTimeSeconds = 60.0
	}
	if cfg.MaxTxTimeSeconds < cfg.MinTxTimeSeconds {
		cfg.MaxTxTimeSeconds = cfg.MinTxTimeSeconds
	}
	if strings.TrimSpace(cfg.OwnerName) != "" && s.cfg.OwnerUsername == OwnerUsernameDefault {
		s.cfg.OwnerUsername = cfg.OwnerName
	}
	s.cfg.MaxTxTimeSeconds = cfg.MaxTxTimeSeconds
	s.cfg.MinTxTimeSeconds = cfg.MinTxTimeSeconds
	s.cfg.VolatileFees = cfg.VolatileFees
	log.Printf("CONFIG: applied config: max_tx=%.0fs min_tx=%.0fs volatile_fees=%t",
		cfg.MaxTxTimeSeconds, cfg.MinTxTimeSeconds, cfg.VolatileFees)
}
