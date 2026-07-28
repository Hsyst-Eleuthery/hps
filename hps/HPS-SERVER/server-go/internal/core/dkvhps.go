package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
		"version":                  2,
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
	ecdhPub := publicKeyToECDH(pub)
	if ecdhPub == nil {
		return ""
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return ""
	}
	sharedSecret, err := ephemeral.ECDH(ecdhPub)
	if err != nil {
		return ""
	}
	aesKey := sha256.Sum256(sharedSecret)
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	ct := gcm.Seal(nil, nonce, []byte(plain), nil)
	ephemeralPub := ephemeral.PublicKey()
	ephemeralBytes := ephemeralPub.Bytes()
	result := append([]byte{2}, byte(len(ephemeralBytes)))
	result = append(result, ephemeralBytes...)
	result = append(result, nonce...)
	result = append(result, ct...)
	return base64.StdEncoding.EncodeToString(result)
}

func (s *Server) decryptIssuerProtectedKey(ciphertextB64 string) string {
	if s == nil || ciphertextB64 == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil || len(data) < 2 {
		return ""
	}
	pubKeyLen := int(data[1])
	if len(data) < 2+pubKeyLen+12 {
		return ""
	}
	ephemeralBytes := data[2 : 2+pubKeyLen]
	ephemeralPub, err := ecdh.X25519().NewPublicKey(ephemeralBytes)
	if err != nil {
		return ""
	}
	if s.EncryptionKey == nil {
		return ""
	}
	sharedSecret, err := s.EncryptionKey.ECDH(ephemeralPub)
	if err != nil {
		return ""
	}
	aesKey := sha256.Sum256(sharedSecret)
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonceStart := 2 + pubKeyLen
	nonce := data[nonceStart : nonceStart+gcm.NonceSize()]
	ct := data[nonceStart+gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return ""
	}
	return string(plain)
}

func publicKeyToECDH(pub any) *ecdh.PublicKey {
	switch p := pub.(type) {
	case *ecdh.PublicKey:
		return p
	case *ecdsa.PublicKey:
		// Convert ECDSA P-256 public key to ECDH
		if p.Curve == elliptic.P256() {
			ecdhKey, err := p.ECDH()
			if err != nil {
				return nil
			}
			return ecdhKey
		}
		return nil
	default:
		return nil
	}
}
