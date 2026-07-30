package core

import (
	"crypto/x509"
)

func (s *Server) GetRegisteredPublicKey(username string) string {
	if username == "" {
		return ""
	}
	var key string
	_ = s.DB.QueryRow("SELECT public_key FROM users WHERE username = ?", username).Scan(&key)
	return key
}

// GetServerNodePublicKey returns the public key for a server address from server_nodes table.
// A1 FIX: Use this instead of GetRegisteredPublicKey for server addresses.
func (s *Server) GetServerNodePublicKey(address string) string {
	if address == "" {
		return ""
	}
	var key string
	_ = s.DB.QueryRow("SELECT public_key FROM server_nodes WHERE address = ?", address).Scan(&key)
	return key
}

func PublicKeyValuesEqual(left, right string) bool {
	leftPub, leftErr := loadPublicKeyFromValue(left)
	rightPub, rightErr := loadPublicKeyFromValue(right)
	
	// C-03 FIX: Require both keys to be valid PEM/DER format
	// If either fails to parse, they are NOT equal (fail closed)
	if leftErr != nil || rightErr != nil || leftPub == nil || rightPub == nil {
		return false
	}
	
	leftBytes, errLeft := x509.MarshalPKIXPublicKey(leftPub)
	rightBytes, errRight := x509.MarshalPKIXPublicKey(rightPub)
	if errLeft != nil || errRight != nil {
		return false
	}
	
	return string(leftBytes) == string(rightBytes)
}

func (s *Server) getReputationAndCredit(username string) (int, int) {
	if username == "" {
		return 0, 0
	}
	var rep, credit int
	err := s.DB.QueryRow(`SELECT reputation, reputation_credit FROM users WHERE username = ?`, username).Scan(&rep, &credit)
	if err != nil {
		return 0, 0
	}
	return rep, credit
}

func (s *Server) setReputationAndCredit(username string, reputation int, credit int) {
	if username == "" {
		return
	}
	if reputation < 1 {
		reputation = 1
	}
	if reputation > 100 {
		reputation = 100
	}
	if credit < 0 {
		credit = 0
	}
	_, _ = s.DB.Exec(`UPDATE users SET reputation = ?, reputation_credit = ? WHERE username = ?`, reputation, credit, username)
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO user_reputations (username, reputation, reputation_credit, last_updated, client_identifier)
		VALUES (?, ?, ?, ?, ?)`,
		username, reputation, credit, now(), "system")
}

func (s *Server) AdjustReputation(username string, delta int) {
	if username == "" || delta == 0 {
		return
	}
	rep, credit := s.getReputationAndCredit(username)
	if delta > 0 {
		rep += delta
		if rep > 100 {
			credit += rep - 100
			rep = 100
		}
		s.setReputationAndCredit(username, rep, credit)
		return
	}
	// Negative delta: apply credit before reducing reputation.
	needed := -delta
	if credit > 0 {
		consume := credit
		if consume > needed {
			consume = needed
		}
		credit -= consume
		needed -= consume
	}
	rep -= needed
	if rep < 1 {
		rep = 1
	}
	s.setReputationAndCredit(username, rep, credit)
}
