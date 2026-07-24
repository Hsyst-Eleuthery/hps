package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keySizeBytes      = 32
	nonceSizeBytes    = 12
	tagSizeBytes      = 16
	saltSizeBytes     = 16
	defaultIterations = 210000
)

type ProxyIdentity struct {
	Fingerprint  string
	PublicKeyPEM string
}

type masterKeyEnvelope struct {
	Version    int    `json:"Version"`
	Kdf        string `json:"Kdf"`
	Iterations int    `json:"Iterations"`
	Salt       string `json:"Salt"`
	Nonce      string `json:"Nonce"`
	Tag        string `json:"Tag"`
	Ciphertext string `json:"Ciphertext"`
}

type encryptedKeyEnvelope struct {
	Version      int    `json:"Version"`
	KeyType      string `json:"KeyType"`
	PublicKeyPem string `json:"PublicKeyPem"`
	Nonce        string `json:"Nonce"`
	Tag          string `json:"Tag"`
	Ciphertext   string `json:"Ciphertext"`
}

type storageKeyEnvelope struct {
	Version    int    `json:"Version"`
	KeyType    string `json:"KeyType"`
	Nonce      string `json:"Nonce"`
	Tag        string `json:"Tag"`
	Ciphertext string `json:"Ciphertext"`
}

func EnsureProxyCryptoIdentity(username string, passphrase []byte, cryptoDir string) (ProxyIdentity, error) {
	u := normalizeUsername(username)
	if u == "" {
		return ProxyIdentity{}, errors.New("usuario obrigatorio")
	}
	if len(strings.TrimSpace(string(passphrase))) == 0 {
		return ProxyIdentity{}, errors.New("senha obrigatoria")
	}
	if strings.TrimSpace(cryptoDir) == "" {
		return ProxyIdentity{}, errors.New("diretorio de criptografia invalido")
	}
	if err := os.MkdirAll(cryptoDir, 0o700); err != nil {
		return ProxyIdentity{}, err
	}

	masterPath := filepath.Join(cryptoDir, u+".masterkey.hps")
	loginPath := filepath.Join(cryptoDir, u+".login.hps.key")
	localPath := filepath.Join(cryptoDir, u+".local.hps.key")

	if !fileExists(masterPath) || !fileExists(loginPath) || !fileExists(localPath) {
		if err := generateIdentityFiles(masterPath, loginPath, localPath, string(passphrase)); err != nil {
			return ProxyIdentity{}, err
		}
	}
	masterKey, err := decryptMasterKey(masterPath, string(passphrase))
	if err != nil {
		return ProxyIdentity{}, err
	}
	zero(masterKey)

	pub, err := loadLoginPublicPEM(loginPath)
	if err != nil {
		return ProxyIdentity{}, err
	}
	fingerprint := sha256Hex([]byte(pub))[:32]
	return ProxyIdentity{Fingerprint: fingerprint, PublicKeyPEM: pub}, nil
}

func EnsureProxyStorageKey(username string, passphrase []byte, cryptoDir string) ([]byte, error) {
	u := normalizeUsername(username)
	if u == "" {
		return nil, errors.New("usuario obrigatorio")
	}
	if len(strings.TrimSpace(string(passphrase))) == 0 {
		return nil, errors.New("senha obrigatoria")
	}
	if strings.TrimSpace(cryptoDir) == "" {
		return nil, errors.New("diretorio de criptografia invalido")
	}
	if err := os.MkdirAll(cryptoDir, 0o700); err != nil {
		return nil, err
	}

	masterPath := filepath.Join(cryptoDir, u+".masterkey.hps")
	loginPath := filepath.Join(cryptoDir, u+".login.hps.key")
	localPath := filepath.Join(cryptoDir, u+".local.hps.key")
	storagePath := filepath.Join(cryptoDir, u+".storage.hps.key")

	if !fileExists(masterPath) || !fileExists(loginPath) || !fileExists(localPath) {
		if _, err := EnsureProxyCryptoIdentity(username, passphrase, cryptoDir); err != nil {
			return nil, err
		}
	}

	masterKey, err := decryptMasterKey(masterPath, string(passphrase))
	if err != nil {
		return nil, err
	}
	defer zero(masterKey)

	if !fileExists(storagePath) {
		storageKey := randomBytes(keySizeBytes)
		defer zero(storageKey)
		if err := writeStorageKeyFile(storagePath, masterKey, storageKey); err != nil {
			return nil, err
		}
	}
	return decryptStorageKeyFile(storagePath, masterKey)
}

func generateIdentityFiles(masterPath, loginPath, localPath, passphrase string) error {
	masterKey := randomBytes(keySizeBytes)
	defer zero(masterKey)

	loginKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	localKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	loginPrivatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(loginKey)}))
	loginPublicPEM, err := exportPublicPEM(&loginKey.PublicKey)
	if err != nil {
		return err
	}
	localPrivatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(localKey)}))
	localPublicPEM, err := exportPublicPEM(&localKey.PublicKey)
	if err != nil {
		return err
	}

	if err := writeMasterKeyFile(masterPath, passphrase, masterKey); err != nil {
		return err
	}
	if err := writeEncryptedKeyFile(loginPath, "login", loginPrivatePEM, loginPublicPEM, masterKey); err != nil {
		return err
	}
	if err := writeEncryptedKeyFile(localPath, "local", localPrivatePEM, localPublicPEM, masterKey); err != nil {
		return err
	}
	return nil
}

func writeMasterKeyFile(path, passphrase string, masterKey []byte) error {
	salt := randomBytes(saltSizeBytes)
	derived := pbkdf2SHA256([]byte(passphrase), salt, defaultIterations, keySizeBytes)
	nonce := randomBytes(nonceSizeBytes)
	defer zero(salt)
	defer zero(derived)
	defer zero(nonce)

	payload := []byte(base64.StdEncoding.EncodeToString(masterKey))
	// A17 FIX: Use contextual AAD for master key encryption
	ciphertext, tag, err := encryptGCM(derived, nonce, payload, []byte("hps-proxy-master-key"))
	zero(payload)
	if err != nil {
		return err
	}
	defer zero(ciphertext)
	defer zero(tag)

	env := masterKeyEnvelope{
		Version:    1,
		Kdf:        "PBKDF2-SHA256",
		Iterations: defaultIterations,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Tag:        base64.StdEncoding.EncodeToString(tag),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func writeEncryptedKeyFile(path, keyType, privatePEM, publicPEM string, masterKey []byte) error {
	nonce := randomBytes(nonceSizeBytes)
	defer zero(nonce)

	plain := []byte(base64.StdEncoding.EncodeToString([]byte(privatePEM)))
	defer zero(plain)
	// A17 FIX: Use key type as AAD for key file encryption
	ciphertext, tag, err := encryptGCM(masterKey, nonce, plain, []byte("hps-proxy-key-"+keyType))
	if err != nil {
		return err
	}
	defer zero(ciphertext)
	defer zero(tag)

	env := encryptedKeyEnvelope{
		Version:      1,
		KeyType:      keyType,
		PublicKeyPem: publicPEM,
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Tag:          base64.StdEncoding.EncodeToString(tag),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func decryptMasterKey(path, passphrase string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env masterKeyEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, err
	}
	defer zero(salt)
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	defer zero(nonce)
	tag, err := base64.StdEncoding.DecodeString(env.Tag)
	if err != nil {
		return nil, err
	}
	defer zero(tag)
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer zero(ciphertext)

	// A18 FIX: Validate KDF field to prevent algorithm substitution attacks
	if env.Kdf != "" && env.Kdf != "PBKDF2-SHA256" {
		return nil, errors.New("unsupported KDF algorithm: " + env.Kdf)
	}

	iters := env.Iterations
	if iters <= 0 {
		iters = defaultIterations
	}
	// A16 FIX: Enforce minimum iterations to prevent downgrade attacks
	// OWASP 2024 recommends at least 210,000 for PBKDF2-SHA256
	const minIterations = 210000
	if iters < minIterations {
		iters = minIterations
	}
	derived := pbkdf2SHA256([]byte(passphrase), salt, iters, keySizeBytes)
	defer zero(derived)
	// A17 FIX: Use contextual AAD for master key decryption
	plain, err := decryptGCM(derived, nonce, ciphertext, tag, []byte("hps-proxy-master-key"))
	if err != nil {
		return nil, errors.New("senha da chave mestra invalida")
	}
	defer zero(plain)
	master, err := base64.StdEncoding.DecodeString(string(plain))
	if err != nil {
		return nil, errors.New("chave mestra corrompida")
	}
	return master, nil
}

func loadLoginPublicPEM(loginPath string) (string, error) {
	raw, err := os.ReadFile(loginPath)
	if err != nil {
		return "", err
	}
	var env encryptedKeyEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", err
	}
	if strings.TrimSpace(env.PublicKeyPem) == "" {
		return "", errors.New("chave publica de login ausente")
	}
	return env.PublicKeyPem, nil
}

func writeStorageKeyFile(path string, masterKey, storageKey []byte) error {
	nonce := randomBytes(nonceSizeBytes)
	defer zero(nonce)
	plain := []byte(base64.StdEncoding.EncodeToString(storageKey))
	defer zero(plain)
	// A17 FIX: Use storage key AAD for storage key encryption
	ciphertext, tag, err := encryptGCM(masterKey, nonce, plain, []byte("hps-proxy-storage-key"))
	if err != nil {
		return err
	}
	defer zero(ciphertext)
	defer zero(tag)

	env := storageKeyEnvelope{
		Version:    1,
		KeyType:    "storage",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Tag:        base64.StdEncoding.EncodeToString(tag),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func decryptStorageKeyFile(path string, masterKey []byte) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env storageKeyEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	defer zero(nonce)
	tag, err := base64.StdEncoding.DecodeString(env.Tag)
	if err != nil {
		return nil, err
	}
	defer zero(tag)
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer zero(ciphertext)
	// A17 FIX: Use key type as AAD for key file decryption
	plain, err := decryptGCM(masterKey, nonce, ciphertext, tag, []byte("hps-proxy-key-"+env.KeyType))
	if err != nil {
		return nil, errors.New("chave de armazenamento invalida")
	}
	defer zero(plain)
	key, err := base64.StdEncoding.DecodeString(string(plain))
	if err != nil {
		return nil, errors.New("chave de armazenamento corrompida")
	}
	if len(key) != keySizeBytes {
		zero(key)
		return nil, errors.New("tamanho da chave de armazenamento invalido")
	}
	return key, nil
}

func exportPublicPEM(pub *rsa.PublicKey) (string, error) {
	raw, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw})), nil
}

func encryptGCM(key, nonce, plain, aad []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	combined := gcm.Seal(nil, nonce, plain, aad)
	if len(combined) < tagSizeBytes {
		return nil, nil, errors.New("ciphertext invalido")
	}
	ciphertext := make([]byte, len(combined)-tagSizeBytes)
	tag := make([]byte, tagSizeBytes)
	copy(ciphertext, combined[:len(combined)-tagSizeBytes])
	copy(tag, combined[len(combined)-tagSizeBytes:])
	return ciphertext, tag, nil
}

func decryptGCM(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	combined := make([]byte, len(ciphertext)+len(tag))
	copy(combined, ciphertext)
	copy(combined[len(ciphertext):], tag)
	return gcm.Open(nil, nonce, combined, aad)
}

func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand falhou: " + err.Error())
	}
	return b
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
