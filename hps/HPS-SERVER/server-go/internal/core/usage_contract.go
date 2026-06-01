package core

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
)

func (s *Server) LoadUsageContractTemplate() (string, string) {
	path := filepath.Join(s.FilesDir, "usage_contract.txt")
	if _, err := os.Stat(path); err != nil {
		defaultText := "TERMO DE USO DA REDE HSYST\n\n1) Este contrato confirma que voce reconhece o uso da sua chave privada para assinar operacoes nesta rede.\n"
		_ = s.WriteEncryptedFile(path, []byte(defaultText))
	}
	b, err := s.ReadEncryptedFile(path)
	if err != nil {
		return "", ""
	}
	h := sha256.Sum256(b)
	return string(b), hex.EncodeToString(h[:])
}

func (s *Server) UserNeedsUsageContract(username string) bool {
	if username == "" {
		return true
	}
	_, hash := s.LoadUsageContractTemplate()
	var exists int
	_ = s.DB.QueryRow("SELECT 1 FROM usage_contract_acceptance WHERE username = ? AND contract_hash = ? LIMIT 1", username, hash).Scan(&exists)
	return exists != 1
}

func (s *Server) AcceptUsageContract(username string, contractHash string, contractContent []byte, signature string) bool {
	if username == "" || contractHash == "" {
		return false
	}
	_, currentHash := s.LoadUsageContractTemplate()
	if contractHash != currentHash {
		return false
	}
	_, _ = s.DB.Exec("INSERT OR REPLACE INTO usage_contract_acceptance (username, contract_hash, accepted_at) VALUES (?, ?, ?)", username, contractHash, now())
	s.SaveContract("accept_usage", "", "", username, signature, contractContent)
	return true
}

func (s *Server) RemoveUsageContractForUser(username string) {
	if username == "" {
		return
	}
	_, _ = s.DB.Exec("DELETE FROM usage_contract_acceptance WHERE username = ?", username)
	rows, err := s.DB.Query(`SELECT contract_id FROM contracts WHERE username = ? AND action_type = ?`, username, "accept_usage")
	if err != nil {
		_, _ = s.DB.Exec(`DELETE FROM contracts WHERE username = ? AND action_type = ?`, username, "accept_usage")
		return
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var contractID sql.NullString
		if rows.Scan(&contractID) == nil && contractID.Valid && contractID.String != "" {
			ids = append(ids, contractID.String)
		}
	}
	_, _ = s.DB.Exec(`DELETE FROM contracts WHERE username = ? AND action_type = ?`, username, "accept_usage")
	for _, contractID := range ids {
		_ = os.Remove(filepath.Join(s.FilesDir, "contracts", contractID+".contract"))
	}
}
