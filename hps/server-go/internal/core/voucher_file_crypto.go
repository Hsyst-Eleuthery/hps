package core

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type voucherStorageEnvelope struct {
	Version                int    `json:"version"`
	Scheme                 string `json:"scheme"`
	VoucherHash            string `json:"voucher_hash,omitempty"`
	LineageHash            string `json:"lineage_hash,omitempty"`
	VoucherIssuerEncrypted string `json:"voucher_issuer_encrypted,omitempty"`
	LineageIssuerEncrypted string `json:"lineage_issuer_encrypted,omitempty"`
	LineageNonce           string `json:"lineage_nonce,omitempty"`
	Ciphertext             string `json:"ciphertext,omitempty"`
}

type voucherStorageInnerEnvelope struct {
	VoucherNonce string `json:"voucher_nonce"`
	Ciphertext   string `json:"ciphertext"`
}

func deriveVoucherFileCipherKey(scope, secret string) []byte {
	sum := sha256.Sum256([]byte(scope + ":" + secret))
	key := make([]byte, len(sum))
	copy(key, sum[:])
	return key
}

func (s *Server) EncodeVoucherFileForStorage(voucher map[string]any) []byte {
	plain := []byte(FormatHpsVoucherHsyst(voucher))
	payload := mapValue(voucher["payload"])
	dkvhps := mapValue(payload["dkvhps"])
	voucherSecret := s.decryptIssuerProtectedKey(asString(dkvhps["voucher_issuer_encrypted"]))
	lineageSecret := s.decryptIssuerProtectedKey(asString(dkvhps["lineage_issuer_encrypted"]))
	if voucherSecret == "" || lineageSecret == "" {
		return plain
	}
	voucherKey := deriveVoucherFileCipherKey("voucher", voucherSecret)
	lineageKey := deriveVoucherFileCipherKey("lineage", lineageSecret)
	defer zeroBytes(voucherKey)
	defer zeroBytes(lineageKey)

	voucherCipher, voucherNonce, err := encryptAesGcm(voucherKey, plain)
	if err != nil {
		return plain
	}
	defer zeroBytes(voucherNonce)
	innerPayload, err := json.Marshal(voucherStorageInnerEnvelope{
		VoucherNonce: base64.StdEncoding.EncodeToString(voucherNonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(voucherCipher),
	})
	if err != nil {
		return plain
	}
	lineageCipher, lineageNonce, err := encryptAesGcm(lineageKey, innerPayload)
	if err != nil {
		return plain
	}
	defer zeroBytes(lineageNonce)
	envelope, err := json.Marshal(voucherStorageEnvelope{
		Version:                1,
		Scheme:                 "hps-voucher-dkvhps",
		VoucherHash:            asString(dkvhps["voucher_hash"]),
		LineageHash:            asString(dkvhps["lineage_hash"]),
		VoucherIssuerEncrypted: asString(dkvhps["voucher_issuer_encrypted"]),
		LineageIssuerEncrypted: asString(dkvhps["lineage_issuer_encrypted"]),
		LineageNonce:           base64.StdEncoding.EncodeToString(lineageNonce),
		Ciphertext:             base64.StdEncoding.EncodeToString(lineageCipher),
	})
	if err != nil {
		return plain
	}
	return envelope
}

func (s *Server) DecodeVoucherFileFromStorage(raw []byte) ([]byte, error) {
	var envelope voucherStorageEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Scheme != "hps-voucher-dkvhps" {
		return raw, nil
	}
	voucherSecret := s.decryptIssuerProtectedKey(envelope.VoucherIssuerEncrypted)
	lineageSecret := s.decryptIssuerProtectedKey(envelope.LineageIssuerEncrypted)
	if voucherSecret == "" || lineageSecret == "" {
		return nil, errors.New("missing voucher dkvhps secret")
	}
	if envelope.VoucherHash != "" && sha256Hex(voucherSecret) != envelope.VoucherHash {
		return nil, errors.New("voucher dkvhps hash mismatch")
	}
	if envelope.LineageHash != "" && sha256Hex(lineageSecret) != envelope.LineageHash {
		return nil, errors.New("lineage dkvhps hash mismatch")
	}
	voucherKey := deriveVoucherFileCipherKey("voucher", voucherSecret)
	lineageKey := deriveVoucherFileCipherKey("lineage", lineageSecret)
	defer zeroBytes(voucherKey)
	defer zeroBytes(lineageKey)

	lineageNonce, err := base64.StdEncoding.DecodeString(envelope.LineageNonce)
	if err != nil {
		return nil, err
	}
	lineageCipher, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	innerPayload, err := decryptAesGcm(lineageKey, lineageNonce, lineageCipher)
	if err != nil {
		return nil, err
	}
	var inner voucherStorageInnerEnvelope
	if err := json.Unmarshal(innerPayload, &inner); err != nil {
		return nil, err
	}
	voucherNonce, err := base64.StdEncoding.DecodeString(inner.VoucherNonce)
	if err != nil {
		return nil, err
	}
	voucherCipher, err := base64.StdEncoding.DecodeString(inner.Ciphertext)
	if err != nil {
		return nil, err
	}
	return decryptAesGcm(voucherKey, voucherNonce, voucherCipher)
}

func (s *Server) ReadVoucherFile(path string) ([]byte, error) {
	raw, err := s.ReadEncryptedFile(path)
	if err != nil {
		return nil, err
	}
	return s.DecodeVoucherFileFromStorage(raw)
}
