package core

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) RegisterContractViolation(violationType, reportedBy, contentHash, domain, reason string, applyPenalty bool) string {
	if reason == "" {
		reason = "missing_contract"
	}
	owner := ""
	if domain != "" {
		_ = s.DB.QueryRow(`SELECT username FROM dns_records WHERE domain = ?`, domain).Scan(&owner)
	} else if contentHash != "" {
		_ = s.DB.QueryRow(`SELECT username FROM content WHERE content_hash = ?`, contentHash).Scan(&owner)
	}
	if owner == "" {
		owner = reportedBy
	}
	violationID := NewUUID()
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO contract_violations
		(violation_id, violation_type, content_hash, domain, owner_username, reported_by, timestamp, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		violationID, violationType, nullIfEmptyString(contentHash), nullIfEmptyString(domain), owner, reportedBy, now(), reason)
	if applyPenalty && owner != "" {
		s.AdjustReputation(owner, -20)
	}
	return violationID
}

func (s *Server) EnsureContentRepairPending(contentHash string) string {
	contentHash = strings.TrimSpace(contentHash)
	if contentHash == "" {
		return ""
	}
	var owner string
	_ = s.DB.QueryRow(`SELECT username FROM content WHERE content_hash = ?`, contentHash).Scan(&owner)
	if owner == "" {
		return ""
	}
	var existing string
	_ = s.DB.QueryRow(`SELECT transfer_id FROM pending_transfers
		WHERE target_user = ? AND status = ? AND transfer_type = ? AND content_hash = ?
		ORDER BY timestamp DESC LIMIT 1`, owner, "pending", "content_repair", contentHash).Scan(&existing)
	if existing != "" {
		return existing
	}
	transferID := NewUUID()
	_, _ = s.DB.Exec(`INSERT INTO pending_transfers
		(transfer_id, transfer_type, target_user, original_owner, custody_user, content_hash, domain, app_name, contract_id, status, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transferID, "content_repair", owner, owner, CustodyUsername, contentHash, nil, nil, "", "pending", now())
	return transferID
}

func (s *Server) ClearContractViolation(violationType, contentHash, domain string) {
	if domain != "" {
		_, _ = s.DB.Exec(`DELETE FROM contract_violations WHERE violation_type = ? AND domain = ?`, violationType, domain)
		return
	}
	if contentHash != "" {
		_, _ = s.DB.Exec(`DELETE FROM contract_violations WHERE violation_type = ? AND content_hash = ?`, violationType, contentHash)
	}
}

func (s *Server) ClearContractCertification(targetType, targetID string) {
	if targetType == "" || targetID == "" {
		return
	}
	_, _ = s.DB.Exec(`DELETE FROM contract_certifications WHERE target_type = ? AND target_id = ?`, targetType, targetID)
}

func (s *Server) GetContractViolation(violationType, contentHash, domain string) map[string]any {
	var violationID, owner, reportedBy, reason string
	var ts float64
	var err error
	if domain != "" {
		err = s.DB.QueryRow(`SELECT violation_id, owner_username, reported_by, timestamp, reason
			FROM contract_violations WHERE violation_type = ? AND domain = ? LIMIT 1`, violationType, domain).
			Scan(&violationID, &owner, &reportedBy, &ts, &reason)
	} else {
		err = s.DB.QueryRow(`SELECT violation_id, owner_username, reported_by, timestamp, reason
			FROM contract_violations WHERE violation_type = ? AND content_hash = ? LIMIT 1`, violationType, contentHash).
			Scan(&violationID, &owner, &reportedBy, &ts, &reason)
	}
	if err != nil {
		return nil
	}
	return map[string]any{
		"violation_id":   violationID,
		"owner_username": owner,
		"reported_by":    reportedBy,
		"timestamp":      ts,
		"reason":         reason,
	}
}

func (s *Server) SetContractCertification(targetType, targetID, originalOwner, certifier string) {
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO contract_certifications
		(cert_id, target_type, target_id, original_owner, certifier, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)`,
		NewUUID(), targetType, targetID, originalOwner, certifier, now())
}

func (s *Server) GetContractCertification(targetType, targetID string) map[string]any {
	if targetType == "" || targetID == "" {
		return nil
	}
	var certID, originalOwner, certifier string
	var ts float64
	err := s.DB.QueryRow(`SELECT cert_id, original_owner, certifier, timestamp
		FROM contract_certifications WHERE target_type = ? AND target_id = ? LIMIT 1`,
		targetType, targetID).Scan(&certID, &originalOwner, &certifier, &ts)
	if err != nil {
		return nil
	}
	return map[string]any{
		"cert_id":        certID,
		"target_type":    targetType,
		"target_id":      targetID,
		"original_owner": originalOwner,
		"certifier":      certifier,
		"timestamp":      ts,
	}
}

func (s *Server) SaveContractArchive(targetType, targetID string, contractContent []byte) {
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO contract_valid_archive
		(archive_id, target_type, target_id, contract_content, updated_at)
		VALUES (?, ?, ?, ?, ?)`, NewUUID(), targetType, targetID, contractContent, now())
}

func (s *Server) SaveContractArchiveByContract(contractID string, contractContent []byte) error {
	var contentHash, domain sql.NullString
	err := s.DB.QueryRow(`SELECT content_hash, domain FROM contracts WHERE contract_id = ?`, contractID).Scan(&contentHash, &domain)
	if err != nil {
		return err
	}
	if domain.Valid && domain.String != "" {
		s.SaveContractArchive("domain", domain.String, contractContent)
		return nil
	}
	if contentHash.Valid && contentHash.String != "" {
		s.SaveContractArchive("content", contentHash.String, contractContent)
	}
	return nil
}

func (s *Server) GetContractArchive(targetType, targetID string) []byte {
	var content []byte
	err := s.DB.QueryRow(`SELECT contract_content FROM contract_valid_archive
		WHERE target_type = ? AND target_id = ?`, targetType, targetID).Scan(&content)
	if err != nil {
		return nil
	}
	return content
}

func (s *Server) DeleteContractArchive(targetType, targetID string) {
	if targetType == "" || targetID == "" {
		return
	}
	_, _ = s.DB.Exec(`DELETE FROM contract_valid_archive WHERE target_type = ? AND target_id = ?`, targetType, targetID)
}

func (s *Server) InvalidateContent(contentHash string, keepViolation bool) {
	if contentHash == "" {
		return
	}
	rows, err := s.DB.Query(`SELECT contract_id FROM contracts WHERE content_hash = ?`, contentHash)
	contractIDs := []string{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var contractID string
			if rows.Scan(&contractID) == nil && contractID != "" {
				contractIDs = append(contractIDs, contractID)
			}
		}
	}
	_, _ = s.DB.Exec(`DELETE FROM contracts WHERE content_hash = ?`, contentHash)
	for _, contractID := range contractIDs {
		_ = os.Remove(filepath.Join(s.FilesDir, "contracts", contractID+".contract"))
	}
	if !keepViolation {
		s.ClearContractViolation("content", contentHash, "")
	}
	s.ClearContractCertification("content", contentHash)
	s.DeleteContractArchive("content", contentHash)
}

func (s *Server) InvalidateDomain(domain string, keepViolation bool) {
	if domain == "" {
		return
	}
	rows, err := s.DB.Query(`SELECT contract_id FROM contracts WHERE domain = ?`, domain)
	contractIDs := []string{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var contractID string
			if rows.Scan(&contractID) == nil && contractID != "" {
				contractIDs = append(contractIDs, contractID)
			}
		}
	}
	_, _ = s.DB.Exec(`DELETE FROM contracts WHERE domain = ?`, domain)
	for _, contractID := range contractIDs {
		_ = os.Remove(filepath.Join(s.FilesDir, "contracts", contractID+".contract"))
	}
	if !keepViolation {
		s.ClearContractViolation("domain", "", domain)
	}
	s.ClearContractCertification("domain", domain)
	s.DeleteContractArchive("domain", domain)
}

func (s *Server) RemoveInvalidContracts(contentHash, domain string) {
	if domain != "" {
		rows, err := s.DB.Query(`SELECT contract_id FROM contracts WHERE domain = ? AND verified = 0`, domain)
		contractIDs := []string{}
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var contractID string
				if rows.Scan(&contractID) == nil && contractID != "" {
					contractIDs = append(contractIDs, contractID)
				}
			}
		}
		_, _ = s.DB.Exec(`DELETE FROM contracts WHERE domain = ? AND verified = 0`, domain)
		for _, contractID := range contractIDs {
			_ = os.Remove(filepath.Join(s.FilesDir, "contracts", contractID+".contract"))
		}
		return
	}
	if contentHash != "" {
		rows, err := s.DB.Query(`SELECT contract_id FROM contracts WHERE content_hash = ? AND verified = 0`, contentHash)
		contractIDs := []string{}
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var contractID string
				if rows.Scan(&contractID) == nil && contractID != "" {
					contractIDs = append(contractIDs, contractID)
				}
			}
		}
		_, _ = s.DB.Exec(`DELETE FROM contracts WHERE content_hash = ? AND verified = 0`, contentHash)
		for _, contractID := range contractIDs {
			_ = os.Remove(filepath.Join(s.FilesDir, "contracts", contractID+".contract"))
		}
	}
}
