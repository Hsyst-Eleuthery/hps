package core

import (
	"encoding/base64"
	"path/filepath"
)

func (s *Server) GetContractBytes(contractID string) []byte {
	if contractID == "" {
		return nil
	}
	path := filepath.Join(s.FilesDir, "contracts", contractID+".contract")
	if data, err := s.ReadEncryptedFile(path); err == nil {
		return data
	}
	var contentB64 string
	_ = s.DB.QueryRow("SELECT contract_content FROM contracts WHERE contract_id = ?", contractID).Scan(&contentB64)
	if contentB64 == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		return nil
	}
	return data
}

func (s *Server) GetContractsForContent(contentHash string) ([]map[string]any, string) {
	rows, err := s.DB.Query(`SELECT contract_id, action_type, COALESCE(domain, ''), username, signature, timestamp, verified, contract_content
		FROM contracts WHERE content_hash = ? ORDER BY timestamp DESC`, contentHash)
	if err != nil {
		return nil, ""
	}
	type contractRow struct {
		contractID      string
		actionType      string
		domain          string
		username        string
		signature       string
		timestamp       float64
		verified        int
		contractContent string
	}
	pendingRows := []contractRow{}
	for rows.Next() {
		var row contractRow
		if err := rows.Scan(&row.contractID, &row.actionType, &row.domain, &row.username, &row.signature, &row.timestamp, &row.verified, &row.contractContent); err != nil {
			continue
		}
		pendingRows = append(pendingRows, row)
	}
	rows.Close()
	contracts := []map[string]any{}
	invalidReason := ""
	for _, row := range pendingRows {
		contractBytes := s.GetContractBytes(row.contractID)
		var contractText string
		verifiedBool := row.verified != 0
		if len(contractBytes) > 0 {
			contractText = string(contractBytes)
			valid, _, info := ValidateContractStructure(contractBytes)
			if valid && info != nil {
				publicKey := ExtractContractDetail(info, "PUBLIC_KEY")
				if publicKey == "" {
					publicKey = s.GetRegisteredPublicKey(info.User)
				}
				if s.VerifyContractSignature(contractBytes, info.User, info.Signature, publicKey) {
					verifiedBool = true
				} else {
					verifiedBool = false
					if invalidReason == "" {
						invalidReason = "invalid_signature"
					}
				}
				_, _ = s.DB.Exec(`UPDATE contracts SET contract_content = ?, verified = ?, username = ?, signature = ?
					WHERE contract_id = ?`, base64.StdEncoding.EncodeToString(contractBytes), boolToInt(verifiedBool), info.User, info.Signature, row.contractID)
			} else {
				verifiedBool = false
				if invalidReason == "" {
					invalidReason = "invalid_contract"
				}
			}
		}
		contracts = append(contracts, map[string]any{
			"contract_id":      row.contractID,
			"action_type":      row.actionType,
			"domain":           row.domain,
			"username":         row.username,
			"signature":        row.signature,
			"timestamp":        row.timestamp,
			"verified":         verifiedBool,
			"integrity_ok":     verifiedBool,
			"contract_content": contractText,
		})
	}
	return contracts, invalidReason
}

func (s *Server) GetContractsForDomain(domain string) ([]map[string]any, string) {
	rows, err := s.DB.Query(`SELECT contract_id, action_type, COALESCE(content_hash, ''), username, signature, timestamp, verified, contract_content
		FROM contracts WHERE domain = ? ORDER BY timestamp DESC`, domain)
	if err != nil {
		return nil, ""
	}
	type contractRow struct {
		contractID      string
		actionType      string
		contentHash     string
		username        string
		signature       string
		timestamp       float64
		verified        int
		contractContent string
	}
	pendingRows := []contractRow{}
	for rows.Next() {
		var row contractRow
		if err := rows.Scan(&row.contractID, &row.actionType, &row.contentHash, &row.username, &row.signature, &row.timestamp, &row.verified, &row.contractContent); err != nil {
			continue
		}
		pendingRows = append(pendingRows, row)
	}
	rows.Close()
	contracts := []map[string]any{}
	invalidReason := ""
	for _, row := range pendingRows {
		contractBytes := s.GetContractBytes(row.contractID)
		var contractText string
		verifiedBool := row.verified != 0
		if len(contractBytes) > 0 {
			contractText = string(contractBytes)
			valid, _, info := ValidateContractStructure(contractBytes)
			if valid && info != nil {
				publicKey := ExtractContractDetail(info, "PUBLIC_KEY")
				if publicKey == "" {
					publicKey = s.GetRegisteredPublicKey(info.User)
				}
				if s.VerifyContractSignature(contractBytes, info.User, info.Signature, publicKey) {
					verifiedBool = true
				} else {
					verifiedBool = false
					if invalidReason == "" {
						invalidReason = "invalid_signature"
					}
				}
				_, _ = s.DB.Exec(`UPDATE contracts SET contract_content = ?, verified = ?, username = ?, signature = ?
					WHERE contract_id = ?`, base64.StdEncoding.EncodeToString(contractBytes), boolToInt(verifiedBool), info.User, info.Signature, row.contractID)
			} else {
				verifiedBool = false
				if invalidReason == "" {
					invalidReason = "invalid_contract"
				}
			}
		}
		contracts = append(contracts, map[string]any{
			"contract_id":      row.contractID,
			"action_type":      row.actionType,
			"content_hash":     row.contentHash,
			"username":         row.username,
			"signature":        row.signature,
			"timestamp":        row.timestamp,
			"verified":         verifiedBool,
			"integrity_ok":     verifiedBool,
			"contract_content": contractText,
		})
	}
	return contracts, invalidReason
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
