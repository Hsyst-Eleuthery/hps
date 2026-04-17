package core

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const MaxUploadSize = 100 * 1024 * 1024

func ExtractContractFromContent(content []byte) ([]byte, []byte) {
	startMarker := []byte("# HSYST P2P SERVICE")
	endMarker := []byte("## :END CONTRACT")
	startIdx := bytes.LastIndex(content, startMarker)
	if startIdx < 0 {
		return content, nil
	}
	endIdx := bytes.Index(content[startIdx:], endMarker)
	if endIdx < 0 {
		return content, nil
	}
	endIdx = startIdx + endIdx + len(endMarker)
	contractText := content[startIdx:endIdx]
	body := append([]byte{}, content[:startIdx]...)
	body = append(body, bytesTrimLeftNewlines(content[endIdx:])...)
	return body, bytesTrimSpaces(contractText)
}

func bytesTrimLeftNewlines(b []byte) []byte {
	for len(b) > 0 && (b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	return b
}

func bytesTrimSpaces(b []byte) []byte {
	for len(b) > 0 {
		last := b[len(b)-1]
		if last != ' ' && last != '\n' && last != '\r' && last != '\t' {
			break
		}
		b = b[:len(b)-1]
	}
	for len(b) > 0 {
		first := b[0]
		if first != ' ' && first != '\n' && first != '\r' && first != '\t' {
			break
		}
		b = b[1:]
	}
	return b
}

func (s *Server) VerifyContentSignature(content []byte, signatureB64 string, publicKeyValue string) bool {
	ok, err := s.VerifyContentSignatureDetailed(content, signatureB64, publicKeyValue)
	return err == nil && ok
}

func (s *Server) VerifyContentSignatureDetailed(content []byte, signatureB64 string, publicKeyValue string) (bool, error) {
	pub, err := loadPublicKeyFromValue(publicKeyValue)
	if err != nil || pub == nil {
		if err == nil {
			err = errors.New("invalid public key")
		}
		return false, err
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, err
	}
	h := sha256.Sum256(content)
	if err := rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, nil); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *Server) VerifyStoredContentIntegrity(contentHash string) (bool, string) {
	if strings.TrimSpace(contentHash) == "" {
		return false, "missing_content_hash"
	}
	var signature, publicKey string
	if err := s.DB.QueryRow(`SELECT signature, public_key FROM content WHERE content_hash = ?`, contentHash).Scan(&signature, &publicKey); err != nil {
		return false, "metadata_missing"
	}
	if strings.TrimSpace(signature) == "" || strings.TrimSpace(publicKey) == "" {
		return false, "missing_signature"
	}
	filePath := s.ContentPath(contentHash)
	content, err := s.ReadEncryptedFile(filePath)
	if err != nil {
		return false, "content_missing"
	}
	content, _ = ExtractContractFromContent(content)
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != contentHash {
		return false, "content_tampered"
	}
	ok, _ := s.VerifyContentSignatureDetailed(content, signature, publicKey)
	if !ok {
		return false, "content_signature_invalid"
	}
	return true, ""
}

func loadPublicKeyFromValue(keyValue string) (*rsa.PublicKey, error) {
	value := strings.TrimSpace(keyValue)
	if value == "" {
		return nil, errors.New("empty key")
	}
	var keyBytes []byte
	if strings.Contains(value, "BEGIN PUBLIC KEY") {
		keyBytes = []byte(value)
	} else {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
		keyBytes = decoded
	}
	if block, _ := pem.Decode(keyBytes); block != nil {
		switch block.Type {
		case "PUBLIC KEY":
			pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			pub, ok := pubAny.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("not rsa public key")
			}
			return pub, nil
		case "RSA PUBLIC KEY":
			pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			return pub, nil
		}
	}
	pubAny, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not rsa public key")
	}
	return pub, nil
}

func ValidatePublicKeyValue(keyValue string) error {
	_, err := loadPublicKeyFromValue(keyValue)
	return err
}

func (s *Server) CheckRateLimit(clientIdentifier, actionType string) (bool, string, int) {
	now := time.Now().Unix()
	if actionType == "hps_mint" {
		return true, "", 0
	}

	s.mu.Lock()
	banUntil, banned := s.BannedClients[clientIdentifier]
	if banned {
		if now < int64(banUntil) {
			remaining := int(int64(banUntil) - now)
			s.mu.Unlock()
			return false, "Banned for " + itoa(remaining) + " seconds", remaining
		}
		delete(s.BannedClients, clientIdentifier)
	}
	s.mu.Unlock()

	var lastAction int64
	var attemptCount int
	_ = s.DB.QueryRow("SELECT last_action, attempt_count FROM rate_limits WHERE client_identifier = ? AND action_type = ?", clientIdentifier, actionType).Scan(&lastAction, &attemptCount)
	if lastAction == 0 {
		return true, "", 0
	}
	minInterval := int64(60)
	switch actionType {
	case "usage_contract", "contract_transfer", "hps_transfer", "inventory_transfer":
		minInterval = 1
	case "upload":
		minInterval = 5
	case "login":
		minInterval = 10
	case "dns":
		minInterval = 5
	case "report":
		minInterval = 30
	case "hps_mint":
		minInterval = 20
	}
	if now-lastAction < minInterval {
		remaining := int(minInterval - (now - lastAction))
		return false, "Rate limit: " + itoa(remaining) + "s remaining", remaining
	}
	return true, "", 0
}

func (s *Server) UpdateRateLimit(clientIdentifier, actionType string) {
	if actionType == "hps_mint" {
		return
	}
	now := time.Now().Unix()
	var attemptCount int
	_ = s.DB.QueryRow("SELECT attempt_count FROM rate_limits WHERE client_identifier = ? AND action_type = ?", clientIdentifier, actionType).Scan(&attemptCount)
	attemptCount++
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO rate_limits
		(client_identifier, action_type, last_action, attempt_count) VALUES (?, ?, ?, ?)`,
		clientIdentifier, actionType, now, attemptCount)
}

func (s *Server) GetRedirectedHash(oldHash string) string {
	var newHash string
	_ = s.DB.QueryRow("SELECT new_hash FROM content_redirects WHERE old_hash = ?", oldHash).Scan(&newHash)
	return newHash
}

func (s *Server) EvaluateContractViolationForContent(contentHash string) (bool, string) {
	contracts, invalidReason := s.GetContractsForContent(contentHash)
	if len(contracts) == 0 {
		if s.GetContractCertification("content", contentHash) != nil {
			return false, ""
		}
		return true, "missing_contract"
	}
	if invalidReason != "" {
		return true, invalidReason
	}
	for _, c := range contracts {
		if verified, ok := c["verified"].(bool); ok && !verified {
			return true, "invalid_contract"
		}
	}
	return false, ""
}

func (s *Server) EvaluateContractViolationForDomain(domain string) (bool, string) {
	contracts, invalidReason := s.GetContractsForDomain(domain)
	if len(contracts) == 0 {
		if s.GetContractCertification("domain", domain) != nil {
			return false, ""
		}
		return true, "missing_contract"
	}
	if invalidReason != "" {
		return true, invalidReason
	}
	for _, c := range contracts {
		if verified, ok := c["verified"].(bool); ok && !verified {
			return true, "invalid_contract"
		}
	}
	return false, ""
}

func (s *Server) ContentPath(hash string) string {
	return filepath.Join(s.FilesDir, hash+".dat")
}

func (s *Server) DdnsPath(hash string) string {
	return filepath.Join(s.FilesDir, hash+".ddns")
}

func (s *Server) ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
