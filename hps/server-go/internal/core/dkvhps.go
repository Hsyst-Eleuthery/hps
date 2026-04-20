package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
)

func (s *Server) BuildVoucherDkvhps(ownerPublicKey string, lineage VoucherLineageMetadata) map[string]any {
	voucherKey := base64.StdEncoding.EncodeToString(randomSecureBytes(32))
	lineageKey := s.resolveLineageDkvhps(lineage)
	if lineageKey == "" {
		lineageKey = base64.StdEncoding.EncodeToString(randomSecureBytes(32))
	}
	return map[string]any{
		"version":                  1,
		"voucher_hash":             sha256Hex(voucherKey),
		"lineage_hash":             sha256Hex(lineageKey),
		"voucher_owner_encrypted":  encryptKeyForPublicKey(ownerPublicKey, voucherKey),
		"voucher_issuer_encrypted": encryptKeyForPublicKey(base64Encode(s.PublicKeyPEM), voucherKey),
		"lineage_owner_encrypted":  encryptKeyForPublicKey(ownerPublicKey, lineageKey),
		"lineage_issuer_encrypted": encryptKeyForPublicKey(base64Encode(s.PublicKeyPEM), lineageKey),
	}
}

func (s *Server) resolveLineageDkvhps(lineage VoucherLineageMetadata) string {
	if lineage.Origin == "exchange_in" || len(lineage.SourceVoucherIDs) != 1 {
		return ""
	}
	parent := s.GetVoucherAuditInfo(lineage.SourceVoucherIDs[0])
	if parent == nil {
		return ""
	}
	parentPayload := mapValue(parent["payload"])
	dkvhps := mapValue(parentPayload["dkvhps"])
	return s.decryptIssuerProtectedKey(asString(dkvhps["lineage_issuer_encrypted"]))
}

func encryptKeyForPublicKey(publicKeyValue, plain string) string {
	if publicKeyValue == "" || plain == "" {
		return ""
	}
	pub, err := loadPublicKeyFromValue(publicKeyValue)
	if err != nil || pub == nil {
		return ""
	}
	// Keep OAEP interoperable with .NET/Avalonia clients by using the default empty label.
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte(plain), nil)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func (s *Server) decryptIssuerProtectedKey(ciphertextB64 string) string {
	if s == nil || s.PrivateKey == nil || ciphertextB64 == "" {
		return ""
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return ""
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.PrivateKey, ciphertext, nil)
	if err == nil {
		return string(plain)
	}
	return ""
}
