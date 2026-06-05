package core

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

func (s *Server) SignPayload(payload map[string]any) string {
	message := canonicalJSON(payload)
	h := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPSS(rand.Reader, s.PrivateKey, crypto.SHA256, h[:], nil)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func (s *Server) SignRawText(message string) string {
	h := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPSS(rand.Reader, s.PrivateKey, crypto.SHA256, h[:], nil)
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
	h := sha256.Sum256([]byte(message))
	return verifyPSSWithFallback(pub, h[:], sig)
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
	h := sha256.Sum256([]byte(message))
	return verifyPSSWithFallback(pub, h[:], sig)
}

func verifyPSSWithFallback(pub *rsa.PublicKey, digest []byte, sig []byte) bool {
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest, sig, nil); err == nil {
		return true
	}
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
	return rsa.VerifyPSS(pub, crypto.SHA256, digest, sig, opts) == nil
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
