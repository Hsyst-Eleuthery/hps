package core

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

func (s *Server) VerifyContractSignature(contractContent []byte, username string, signature string, publicKeyValue string) bool {
	if len(contractContent) == 0 || username == "" || signature == "" {
		return false
	}
	if publicKeyValue == "" {
		if valid, _, info := ValidateContractStructure(contractContent); valid && info != nil {
			publicKeyValue = ExtractContractDetail(info, "PUBLIC_KEY")
		}
	}
	stored := ""
	if username != "" {
		stored = s.GetRegisteredPublicKey(username)
	}
	if publicKeyValue != "" && username != CustodyUsername && stored != "" && stored != PendingPublicKeyLabel && !PublicKeyValuesEqual(publicKeyValue, stored) {
		return false
	}
	if publicKeyValue == "" {
		if stored == "" {
			return false
		}
		publicKeyValue = stored
	}
	pub, err := loadPublicKeyFromValue(publicKeyValue)
	if err != nil || pub == nil {
		return false
	}
	signedText, err := GetSignedContractText(contractContent)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	h := sha256.Sum256([]byte(signedText))
	if err := rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, nil); err != nil {
		return false
	}
	return true
}

func VerifyContractSignatureWithInfo(contractContent []byte, info *ContractInfo, publicKeyValue string, s *Server) (bool, error) {
	if info == nil {
		return false, errors.New("missing info")
	}
	if info.User == "" || info.Signature == "" {
		return false, errors.New("missing fields")
	}
	if publicKeyValue == "" {
		publicKeyValue = s.GetRegisteredPublicKey(info.User)
	}
	ok := s.VerifyContractSignature(contractContent, info.User, info.Signature, publicKeyValue)
	if !ok {
		return false, errors.New("invalid signature")
	}
	return true, nil
}
