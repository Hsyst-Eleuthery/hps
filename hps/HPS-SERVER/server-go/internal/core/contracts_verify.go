package core

import (
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
			// For custody/system users, the server signs with its own key.
			// If neither the contract nor the users table has a public key,
			// use the server's custody public key directly.
			if username == CustodyUsername || username == "system" {
				serverKey := base64.StdEncoding.EncodeToString(s.CustodyKeyPEM)
				if serverKey == "" {
					return false
				}
				publicKeyValue = serverKey
			} else {
				return false
			}
		} else {
			publicKeyValue = stored
		}
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
	return verifyWithKey(pub, []byte(signedText), sig)
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
