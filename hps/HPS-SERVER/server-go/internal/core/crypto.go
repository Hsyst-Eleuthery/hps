package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// KeyPurpose defines which key to use for signing
type KeyPurpose int

const (
	KeyPurposeDefault  KeyPurpose = iota // Server identity key (server_key)
	KeyPurposeCustody                     // Economic operations (custody_key)
	KeyPurposeIssuer                      // Voucher issuance (issuer_key)
	KeyPurposeStorage                     // Storage encryption (storage_key)
)

func (s *Server) GetKeyForPurpose(purpose KeyPurpose) (crypto.PrivateKey, []byte) {
	switch purpose {
	case KeyPurposeCustody:
		if s.CustodyKey != nil {
			return s.CustodyKey, s.CustodyKeyPEM
		}
	case KeyPurposeIssuer:
		if s.IssuerKey != nil {
			return s.IssuerKey, s.IssuerKeyPEM
		}
	case KeyPurposeStorage:
		if s.StorageKey != nil {
			return s.StorageKey, s.StorageKeyPEM
		}
	}
	return s.PrivateKey, s.PublicKeyPEM
}

func (s *Server) GetActiveKeyName(purpose KeyPurpose) string {
	switch purpose {
	case KeyPurposeCustody:
		return "custody_key"
	case KeyPurposeIssuer:
		return "issuer_key"
	case KeyPurposeStorage:
		return "storage_key"
	}
	return "server_key"
}

func signWithKey(key crypto.PrivateKey, data []byte) ([]byte, error) {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	hash := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, ecKey, hash[:])
}

func verifyWithKey(pub crypto.PublicKey, data []byte, sig []byte) bool {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		hash := sha256.Sum256(data)
		return ecdsa.VerifyASN1(key, hash[:], sig)
	case *rsa.PublicKey:
		hash := sha256.Sum256(data)
		err := rsa.VerifyPSS(key, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
		return err == nil
	default:
		return false
	}
}

func (s *Server) SignPayload(payload map[string]any) string {
	return s.SignPayloadWithKey(payload, KeyPurposeDefault)
}

func (s *Server) SignPayloadWithKey(payload map[string]any, purpose KeyPurpose) string {
	key, _ := s.GetKeyForPurpose(purpose)
	message := canonicalJSON(payload)
	sig, err := signWithKey(key, []byte(message))
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func (s *Server) SignRawText(message string) string {
	return s.SignRawTextWithKey(message, KeyPurposeDefault)
}

func (s *Server) SignRawTextWithKey(message string, purpose KeyPurpose) string {
	key, _ := s.GetKeyForPurpose(purpose)
	sig, err := signWithKey(key, []byte(message))
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func VerifyPayloadSignature(payload map[string]any, signatureB64 string, publicKeyValue string) bool {
	pub, err := loadPublicKeyFromValue(publicKeyValue)
	if err != nil || pub == nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}
	message := canonicalJSON(payload)
	return verifyWithKey(pub, []byte(message), sig)
}

func VerifyPayloadSignatureFlexible(payload map[string]any, rawPayloadText string, signatureB64 string, publicKeyValue string) bool {
	if VerifyPayloadSignature(payload, signatureB64, publicKeyValue) {
		return true
	}
	if strings.TrimSpace(rawPayloadText) != "" && VerifyRawTextSignature(rawPayloadText, signatureB64, publicKeyValue) {
		return true
	}
	return false
}

func VerifyRawTextSignature(message string, signatureB64 string, publicKeyValue string) bool {
	pub, err := loadPublicKeyFromValue(publicKeyValue)
	if err != nil || pub == nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}
	return verifyWithKey(pub, []byte(message), sig)
}

func shortTextHash(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(message))
	return hex.EncodeToString(sum[:8])
}

func ShortTextHash(message string) string {
	return shortTextHash(message)
}

// IsValidPublicKeyPEM validates that a string is a valid PEM-encoded public key,
// supporting both raw PEM (-----BEGIN PUBLIC KEY-----) and Base64-encoded PEM.
// C-04 FIX: Require valid PEM format for registration (Proof of Possession).
func IsValidPublicKeyPEM(key string) bool {
	return ValidatePublicKeyValue(key) == nil
}
