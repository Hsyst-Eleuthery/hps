package core

import "strings"

func IsForbiddenReplicatedContractUser(username string) bool {
	username = strings.ToLower(strings.TrimSpace(username))
	return username == CustodyUsername || username == "system"
}

func ShouldHideReplicatedContract(username string, verified bool) bool {
	return IsForbiddenReplicatedContractUser(username) && !verified
}

func (s *Server) HasContractReplicationTarget(contractID, contentHash, domain string) bool {
	if strings.TrimSpace(contentHash) != "" {
		var exists int
		_ = s.DB.QueryRow(`SELECT 1 FROM content WHERE content_hash = ? LIMIT 1`, strings.TrimSpace(contentHash)).Scan(&exists)
		if exists == 1 {
			return true
		}
		_ = s.DB.QueryRow(`SELECT 1 FROM pending_transfers WHERE content_hash = ? LIMIT 1`, strings.TrimSpace(contentHash)).Scan(&exists)
		if exists == 1 {
			return true
		}
	}

	if strings.TrimSpace(domain) != "" {
		normalizedDomain := strings.ToLower(strings.TrimSpace(domain))
		var exists int
		_ = s.DB.QueryRow(`SELECT 1 FROM dns_records WHERE domain = ? LIMIT 1`, normalizedDomain).Scan(&exists)
		if exists == 1 {
			return true
		}
		_ = s.DB.QueryRow(`SELECT 1 FROM pending_transfers WHERE domain = ? LIMIT 1`, normalizedDomain).Scan(&exists)
		if exists == 1 {
			return true
		}
	}

	if strings.TrimSpace(contractID) != "" {
		var exists int
		_ = s.DB.QueryRow(`SELECT 1 FROM pending_transfers WHERE contract_id = ? LIMIT 1`, strings.TrimSpace(contractID)).Scan(&exists)
		if exists == 1 {
			return true
		}
	}

	return false
}
