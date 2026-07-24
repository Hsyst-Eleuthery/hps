package core

import "strings"

func IsForbiddenReplicatedContractUser(username string) bool {
	username = strings.ToLower(strings.TrimSpace(username))
	return username == CustodyUsername || username == "system"
}

func ShouldHideReplicatedContract(username string, verified bool) bool {
	return IsForbiddenReplicatedContractUser(username) && !verified
}

func (s *Server) ShouldExposeContractForSync(contentHash, domain, issuerServer string) bool {
	if s == nil {
		return false
	}
	issuerServer = strings.TrimSpace(issuerServer)
	if issuerServer != "" && !MessageServerAddressesEqual(issuerServer, s.Address, s.BindAddress) {
		return false
	}
	if strings.TrimSpace(contentHash) != "" {
		var recordIssuer string
		_ = s.DB.QueryRow(`SELECT COALESCE(issuer_server, '') FROM content WHERE content_hash = ? LIMIT 1`, strings.TrimSpace(contentHash)).Scan(&recordIssuer)
		return strings.TrimSpace(recordIssuer) == "" || MessageServerAddressesEqual(recordIssuer, s.Address, s.BindAddress)
	}
	if strings.TrimSpace(domain) != "" {
		var recordIssuer string
		_ = s.DB.QueryRow(`SELECT COALESCE(issuer_server, '') FROM dns_records WHERE domain = ? LIMIT 1`, strings.ToLower(strings.TrimSpace(domain))).Scan(&recordIssuer)
		return strings.TrimSpace(recordIssuer) == "" || MessageServerAddressesEqual(recordIssuer, s.Address, s.BindAddress)
	}
	return true
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
