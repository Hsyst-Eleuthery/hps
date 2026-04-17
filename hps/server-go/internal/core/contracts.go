package core

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ContractDetail struct {
	Key   string
	Value any
}

func (s *Server) BuildServerContractText(actionType string, details []ContractDetail, username string) string {
	if !hasContractDetail(details, "PUBLIC_KEY") {
		publicKey := ""
		if username == CustodyUsername {
			publicKey = base64.StdEncoding.EncodeToString(s.PublicKeyPEM)
		} else {
			publicKey = s.GetRegisteredPublicKey(username)
		}
		if strings.TrimSpace(publicKey) != "" {
			details = append([]ContractDetail{{Key: "PUBLIC_KEY", Value: publicKey}}, details...)
		}
	}
	lines := []string{
		"# HSYST P2P SERVICE",
		"## CONTRACT:",
		"### DETAILS:",
		"# ACTION: " + actionType,
	}
	for _, d := range details {
		lines = append(lines, fmt.Sprintf("# %s: %v", d.Key, d.Value))
	}
	lines = append(lines,
		"### :END DETAILS",
		"### START:",
		"# USER: "+username,
		"# SIGNATURE: ",
		"### :END START",
		"## :END CONTRACT",
	)
	return strings.Join(lines, "\n") + "\n"
}

func hasContractDetail(details []ContractDetail, key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	for _, detail := range details {
		if strings.ToUpper(strings.TrimSpace(detail.Key)) == key {
			return true
		}
	}
	return false
}

func (s *Server) SignContractText(contractText string) string {
	signedText, err := GetSignedContractText([]byte(contractText))
	if err != nil {
		return ""
	}
	return s.SignRawText(signedText)
}

func (s *Server) SaveServerContract(actionType string, details []ContractDetail, opID string) string {
	contractText := s.BuildServerContractText(actionType, details, CustodyUsername)
	signature := s.SignContractText(contractText)
	signedText := strings.Replace(contractText, "# SIGNATURE: ", "# SIGNATURE: "+signature, 1)
	return s.SaveContract(actionType, opID, "", CustodyUsername, signature, []byte(signedText))
}

func (s *Server) SaveContract(actionType string, contentHash string, domain string, username string, signature string, contractContent []byte) string {
	contractID := newUUID()
	now := float64(time.Now().UnixNano()) / 1e9
	contentB64 := base64.StdEncoding.EncodeToString(contractContent)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO contracts
		(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		contractID, actionType, nullIfEmptyString(contentHash), nullIfEmptyString(domain), username, signature, now, 1, contentB64)

	contractDir := filepath.Join(s.FilesDir, "contracts")
	_ = os.MkdirAll(contractDir, 0o755)
	_ = s.WriteEncryptedFile(filepath.Join(contractDir, contractID+".contract"), contractContent)
	return contractID
}

func nullIfEmptyString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
