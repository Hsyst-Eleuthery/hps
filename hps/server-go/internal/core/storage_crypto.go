package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	storageKeySize       = 32
	storageNonceSize     = 12
	storageKeyIterations = 210000
	storageFileMagic     = "HPSENC1"
	storageDbFileMagic   = "HPSDBENC1"
)

type encryptedKeyEnvelope struct {
	Version    int    `json:"version"`
	Kdf        string `json:"kdf,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
	Salt       string `json:"salt,omitempty"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func (s *Server) initStorageCrypto() error {
	passphrase := strings.TrimSpace(s.cfg.MasterPassphrase)
	if passphrase == "" {
		return errors.New("missing server master passphrase")
	}

	masterPath := filepath.Join(s.FilesDir, "server.masterkey.hps")
	storagePath := filepath.Join(s.FilesDir, "server.storage.hps.key")

	if pathExists(masterPath) && pathExists(storagePath) {
		masterKey, err := decryptMasterKeyFile(masterPath, passphrase)
		if err != nil {
			return err
		}
		defer zeroBytes(masterKey)
		storageKey, err := decryptKeyFile(storagePath, masterKey)
		if err != nil {
			return err
		}
		s.storageKey = storageKey
		return nil
	}

	masterKey := randomSecureBytes(storageKeySize)
	storageKey := randomSecureBytes(storageKeySize)
	defer zeroBytes(masterKey)

	if err := encryptMasterKeyFile(masterPath, passphrase, masterKey); err != nil {
		zeroBytes(storageKey)
		return err
	}
	if err := encryptKeyFile(storagePath, masterKey, storageKey); err != nil {
		zeroBytes(storageKey)
		return err
	}
	s.storageKey = storageKey
	return nil
}

func (s *Server) WriteEncryptedFile(path string, data []byte, perm ...os.FileMode) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("empty file path")
	}
	mode := os.FileMode(0o644)
	if len(perm) > 0 {
		mode = perm[0]
	}
	if len(s.storageKey) == 0 {
		return os.WriteFile(path, data, mode)
	}
	blob, err := encryptBlob(s.storageKey, data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, blob, mode)
}

func (s *Server) ReadEncryptedFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(s.storageKey) == 0 {
		return raw, nil
	}
	plain, err := decryptBlob(s.storageKey, raw)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func encryptMasterKeyFile(path, passphrase string, masterKey []byte) error {
	salt := randomSecureBytes(16)
	derived := derivePassphraseKey(passphrase, salt, storageKeyIterations)
	defer zeroBytes(derived)
	defer zeroBytes(salt)
	return encryptKeyFileWithKdf(path, masterKey, derived, derived, salt)
}

func decryptMasterKeyFile(path, passphrase string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env, err := parseEncryptedKeyEnvelope(raw)
	if err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(salt)
	iter := env.Iterations
	if iter <= 0 {
		iter = storageKeyIterations
	}
	derived := derivePassphraseKey(passphrase, salt, iter)
	defer zeroBytes(derived)
	key, err := decryptEnvelope(&env, derived)
	if err != nil {
		return nil, fmt.Errorf("invalid server master passphrase or key file")
	}
	return key, nil
}

func encryptKeyFile(path string, encryptKey, plainKey []byte) error {
	return encryptKeyFileWithKdf(path, plainKey, encryptKey, nil, nil)
}

func encryptKeyFileWithKdf(path string, plainKey, encryptKey, derived, salt []byte) error {
	env, err := encryptEnvelope(plainKey, encryptKey)
	if err != nil {
		return err
	}
	if len(derived) > 0 {
		env.Kdf = "KDF-SHA256"
		env.Iterations = storageKeyIterations
		env.Salt = base64.StdEncoding.EncodeToString(salt)
	}
	payload := formatEncryptedKeyEnvelope(path, env)
	return os.WriteFile(path, payload, 0o600)
}

func decryptKeyFile(path string, key []byte) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env, err := parseEncryptedKeyEnvelope(raw)
	if err != nil {
		return nil, err
	}
	return decryptEnvelope(&env, key)
}

func encryptEnvelope(plain, key []byte) (*encryptedKeyEnvelope, error) {
	ciphertext, nonce, err := encryptAesGcm(key, plain)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(nonce)
	env := &encryptedKeyEnvelope{
		Version:    1,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return env, nil
}

func decryptEnvelope(env *encryptedKeyEnvelope, key []byte) ([]byte, error) {
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		zeroBytes(nonce)
		return nil, err
	}
	defer zeroBytes(nonce)
	plain, err := decryptAesGcm(key, nonce, ciphertext)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func encryptBlob(key, plain []byte) ([]byte, error) {
	ciphertext, nonce, err := encryptAesGcm(key, plain)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(nonce)
	out := make([]byte, len(storageFileMagic)+len(nonce)+len(ciphertext))
	copy(out, []byte(storageFileMagic))
	copy(out[len(storageFileMagic):], nonce)
	copy(out[len(storageFileMagic)+len(nonce):], ciphertext)
	return out, nil
}

func decryptBlob(key, blob []byte) ([]byte, error) {
	if len(blob) < len(storageFileMagic)+storageNonceSize {
		return blob, nil
	}
	if string(blob[:len(storageFileMagic)]) != storageFileMagic {
		return blob, nil
	}
	nonce := blob[len(storageFileMagic) : len(storageFileMagic)+storageNonceSize]
	ciphertext := blob[len(storageFileMagic)+storageNonceSize:]
	return decryptAesGcm(key, nonce, ciphertext)
}

func encryptAesGcm(key, plain []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := randomSecureBytes(gcm.NonceSize())
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	return ciphertext, nonce, nil
}

func decryptAesGcm(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func derivePassphraseKey(passphrase string, salt []byte, iterations int) []byte {
	if iterations < 1 {
		iterations = 1
	}
	state := sha256.Sum256(append([]byte(passphrase), salt...))
	for i := 1; i < iterations; i++ {
		next := sha256.Sum256(append(state[:], []byte(passphrase)...))
		state = next
	}
	out := make([]byte, storageKeySize)
	copy(out, state[:])
	return out
}

func randomSecureBytes(size int) []byte {
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return buf
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func parseEncryptedKeyEnvelope(raw []byte) (encryptedKeyEnvelope, error) {
	var env encryptedKeyEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && env.Nonce != "" && env.Ciphertext != "" {
		return env, nil
	}
	fields, ok := parseHPSEnvelopeFields(string(raw))
	if !ok {
		return encryptedKeyEnvelope{}, errors.New("invalid encrypted key envelope")
	}
	env = encryptedKeyEnvelope{
		Version:    parseIntField(fields["VERSION"]),
		Kdf:        fields["KDF"],
		Iterations: parseIntField(fields["ITERATIONS"]),
		Salt:       fields["SALT"],
		Nonce:      fields["NONCE"],
		Ciphertext: fields["CIPHERTEXT"],
	}
	if env.Nonce == "" || env.Ciphertext == "" {
		return encryptedKeyEnvelope{}, errors.New("invalid encrypted key envelope")
	}
	return env, nil
}

func formatEncryptedKeyEnvelope(path string, env *encryptedKeyEnvelope) []byte {
	kind := "ENCRYPTED KEY"
	lower := strings.ToLower(filepath.Base(path))
	if strings.Contains(lower, "masterkey") {
		kind = "MASTER KEY"
	}
	fields := map[string]string{
		"VERSION":    fmt.Sprint(env.Version),
		"KDF":        env.Kdf,
		"ITERATIONS": fmt.Sprint(env.Iterations),
		"SALT":       env.Salt,
		"NONCE":      env.Nonce,
		"CIPHERTEXT": env.Ciphertext,
	}
	lines := []string{
		"# HPS P2P SERVICE",
		"# " + kind + ":",
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		if strings.TrimSpace(fields[key]) == "" || fields[key] == "0" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, "## "+key+" = "+fields[key])
	}
	lines = append(lines, "# :END "+kind)
	return []byte(strings.Join(lines, "\n") + "\n")
}

func parseHPSEnvelopeFields(raw string) (map[string]string, bool) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	fields := map[string]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "## ") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(line, "## "))
		parts := strings.SplitN(body, "=", 2)
		if len(parts) != 2 {
			continue
		}
		fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return fields, len(fields) > 0
}

func parseIntField(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	var out int
	_, _ = fmt.Sscanf(raw, "%d", &out)
	return out
}

func (s *Server) loadEncryptedSnapshotToFile(tmpPath string) error {
	dbPath := strings.TrimSpace(s.cfg.DBPath)
	if dbPath == "" || len(s.storageKey) == 0 {
		return nil
	}
	encPath := dbPath + ".enc"
	var plain []byte
	var err error
	switch {
	case pathExists(encPath):
		raw, readErr := os.ReadFile(encPath)
		if readErr != nil {
			return fmt.Errorf("failed to read encrypted db snapshot at %s: %w", encPath, readErr)
		}
		log.Printf("INFO: loading encrypted database snapshot from %s (%d bytes)", encPath, len(raw))
		plain, err = decryptDbBlobWithKey(s.storageKey, raw)
		if err != nil {
			return fmt.Errorf("failed to decrypt database snapshot: %w", err)
		}
		log.Printf("INFO: decrypted database snapshot (%d bytes)", len(plain))
	case pathExists(dbPath):
		log.Printf("INFO: loading unencrypted database file from %s", dbPath)
		plain, err = os.ReadFile(dbPath)
		if err != nil {
			return fmt.Errorf("failed to read database file: %w", err)
		}
		_ = os.Remove(dbPath)
		_ = os.Remove(dbPath + "-wal")
		_ = os.Remove(dbPath + "-shm")
	default:
		log.Printf("INFO: no existing database snapshot found, creating empty at %s", tmpPath)
		return nil
	}
	defer zeroBytes(plain)
	if len(plain) == 0 {
		log.Printf("WARN: database snapshot is empty")
		return nil
	}
	return os.WriteFile(tmpPath, plain, 0o600)
}

func (s *Server) loadEncryptedDatabaseSnapshot() error {
	log.Printf("WARN: loadEncryptedDatabaseSnapshot is deprecated, use loadEncryptedSnapshotToFile")
	return nil
}

func (s *Server) persistEncryptedDatabaseSnapshot() error {
	dbPath := strings.TrimSpace(s.cfg.DBPath)
	if dbPath == "" || len(s.storageKey) == 0 {
		return nil
	}
	tmpPath := dbPath + ".tmp"
	raw, err := os.ReadFile(tmpPath)
	if err != nil {
		log.Printf("ERROR: failed to read temp database file at %s: %v", tmpPath, err)
		return err
	}
	if len(raw) == 0 {
		log.Printf("WARN: temp database file is empty, skipping persist")
		return nil
	}
	defer zeroBytes(raw)
	log.Printf("INFO: reading temp database file (%d bytes)", len(raw))
	blob, err := encryptDbBlobWithKey(s.storageKey, raw)
	if err != nil {
		log.Printf("ERROR: failed to encrypt database snapshot: %v", err)
		return err
	}
	encPath := dbPath + ".enc"
	log.Printf("INFO: persisting encrypted database snapshot to %s (%d bytes)", encPath, len(blob))
	tempPath := encPath + ".new"
	if err := os.WriteFile(tempPath, blob, 0o600); err != nil {
		log.Printf("ERROR: failed to write database snapshot to temp file: %v", err)
		return err
	}
	if pathExists(encPath) {
		if err := os.Remove(encPath); err != nil {
			log.Printf("WARN: failed to remove old database snapshot: %v", err)
		}
	}
	if err := os.Rename(tempPath, encPath); err != nil {
		log.Printf("ERROR: failed to rename temp file to database snapshot: %v", err)
		return err
	}
	log.Printf("INFO: database snapshot persisted successfully")
	return nil
}

func UnsealDatabaseFile(dbPath, passphrase string) error {
	dbPath = strings.TrimSpace(dbPath)
	passphrase = strings.TrimSpace(passphrase)
	if dbPath == "" || passphrase == "" {
		return nil
	}
	if pathExists(dbPath) {
		return nil
	}
	encPath := dbPath + ".enc"
	if !pathExists(encPath) {
		return nil
	}

	raw, err := os.ReadFile(encPath)
	if err != nil {
		return err
	}
	plain, err := decryptDbBlob(raw, passphrase)
	if err != nil {
		return err
	}
	defer zeroBytes(plain)
	return os.WriteFile(dbPath, plain, 0o600)
}

func SealDatabaseFile(dbPath, passphrase string) error {
	dbPath = strings.TrimSpace(dbPath)
	passphrase = strings.TrimSpace(passphrase)
	if dbPath == "" || passphrase == "" {
		return nil
	}
	if !pathExists(dbPath) {
		return nil
	}

	raw, err := os.ReadFile(dbPath)
	if err != nil {
		return err
	}
	defer zeroBytes(raw)
	blob, err := encryptDbBlob(raw, passphrase)
	if err != nil {
		return err
	}
	encPath := dbPath + ".enc"
	if err := os.WriteFile(encPath, blob, 0o600); err != nil {
		return err
	}
	return os.Remove(dbPath)
}

func encryptDbBlob(plain []byte, passphrase string) ([]byte, error) {
	salt := randomSecureBytes(16)
	defer zeroBytes(salt)
	key := derivePassphraseKey(passphrase, salt, storageKeyIterations)
	defer zeroBytes(key)
	ciphertext, nonce, err := encryptAesGcm(key, plain)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(nonce)
	out := make([]byte, len(storageDbFileMagic)+len(salt)+len(nonce)+len(ciphertext))
	offset := 0
	copy(out[offset:], []byte(storageDbFileMagic))
	offset += len(storageDbFileMagic)
	copy(out[offset:], salt)
	offset += len(salt)
	copy(out[offset:], nonce)
	offset += len(nonce)
	copy(out[offset:], ciphertext)
	return out, nil
}

func decryptDbBlob(blob []byte, passphrase string) ([]byte, error) {
	minSize := len(storageDbFileMagic) + 16 + storageNonceSize + 16
	if len(blob) < minSize {
		return nil, errors.New("invalid encrypted database blob")
	}
	if string(blob[:len(storageDbFileMagic)]) != storageDbFileMagic {
		return nil, errors.New("invalid encrypted database header")
	}
	offset := len(storageDbFileMagic)
	salt := append([]byte{}, blob[offset:offset+16]...)
	offset += 16
	nonce := append([]byte{}, blob[offset:offset+storageNonceSize]...)
	offset += storageNonceSize
	ciphertext := append([]byte{}, blob[offset:]...)
	defer zeroBytes(salt)
	defer zeroBytes(nonce)
	defer zeroBytes(ciphertext)
	key := derivePassphraseKey(passphrase, salt, storageKeyIterations)
	defer zeroBytes(key)
	return decryptAesGcm(key, nonce, ciphertext)
}

func encryptDbBlobWithKey(key, plain []byte) ([]byte, error) {
	ciphertext, nonce, err := encryptAesGcm(key, plain)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(nonce)
	out := make([]byte, len(storageDbFileMagic)+len(nonce)+len(ciphertext))
	offset := 0
	copy(out[offset:], []byte(storageDbFileMagic))
	offset += len(storageDbFileMagic)
	copy(out[offset:], nonce)
	offset += len(nonce)
	copy(out[offset:], ciphertext)
	return out, nil
}

func decryptDbBlobWithKey(key, blob []byte) ([]byte, error) {
	minSize := len(storageDbFileMagic) + storageNonceSize + 16
	if len(blob) < minSize {
		return nil, errors.New("invalid encrypted database blob")
	}
	if string(blob[:len(storageDbFileMagic)]) != storageDbFileMagic {
		return nil, errors.New("invalid encrypted database header")
	}
	offset := len(storageDbFileMagic)
	nonce := append([]byte{}, blob[offset:offset+storageNonceSize]...)
	offset += storageNonceSize
	ciphertext := append([]byte{}, blob[offset:]...)
	defer zeroBytes(nonce)
	defer zeroBytes(ciphertext)
	return decryptAesGcm(key, nonce, ciphertext)
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
