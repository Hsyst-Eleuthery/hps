package core

import (
	"encoding/json"
	"strings"
)

func cloneMapAny(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func (s *Server) SetExchangeToken(tokenID string, token map[string]any) {
	tokenID = strings.TrimSpace(tokenID)
	if s == nil || tokenID == "" {
		return
	}
	s.stateMu.Lock()
	s.ExchangeTokens[tokenID] = cloneMapAny(token)
	s.stateMu.Unlock()
	s.persistExchangeToken(tokenID, token)
}

func (s *Server) GetExchangeToken(tokenID string) map[string]any {
	tokenID = strings.TrimSpace(tokenID)
	if s == nil || tokenID == "" {
		return nil
	}
	s.stateMu.RLock()
	token := cloneMapAny(s.ExchangeTokens[tokenID])
	s.stateMu.RUnlock()
	if token != nil {
		return token
	}
	return s.loadExchangeToken(tokenID)
}

func (s *Server) DeleteExchangeToken(tokenID string) {
	tokenID = strings.TrimSpace(tokenID)
	if s == nil || tokenID == "" {
		return
	}
	s.stateMu.Lock()
	delete(s.ExchangeTokens, tokenID)
	s.stateMu.Unlock()
	_, _ = s.DB.Exec(`DELETE FROM exchange_tokens WHERE token_id = ?`, tokenID)
}

func (s *Server) UpdateExchangeToken(tokenID string, fn func(map[string]any) bool) map[string]any {
	tokenID = strings.TrimSpace(tokenID)
	if s == nil || tokenID == "" || fn == nil {
		return nil
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	current := cloneMapAny(s.ExchangeTokens[tokenID])
	if current == nil {
		current = s.loadExchangeToken(tokenID)
		if current == nil {
			return nil
		}
	}
	if !fn(current) {
		return nil
	}
	s.ExchangeTokens[tokenID] = current
	s.persistExchangeToken(tokenID, current)
	return cloneMapAny(current)
}

func (s *Server) persistExchangeToken(tokenID string, token map[string]any) {
	if s == nil || s.DB == nil {
		return
	}
	data, err := json.Marshal(token)
	if err != nil {
		return
	}
	_, _ = s.DB.Exec(`INSERT OR REPLACE INTO exchange_tokens
		(token_id, token_data, created_at) VALUES (?, ?, ?)`,
		tokenID, string(data), now())
}

func (s *Server) loadExchangeToken(tokenID string) map[string]any {
	if s == nil || s.DB == nil {
		return nil
	}
	var data string
	err := s.DB.QueryRow(`SELECT token_data FROM exchange_tokens WHERE token_id = ?`, tokenID).Scan(&data)
	if err != nil {
		return nil
	}
	var token map[string]any
	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return nil
	}
	s.stateMu.Lock()
	s.ExchangeTokens[tokenID] = cloneMapAny(token)
	s.stateMu.Unlock()
	return token
}

func (s *Server) SetHpsPowCost(actionType string, value int) {
	actionType = strings.TrimSpace(actionType)
	if s == nil || actionType == "" {
		return
	}
	s.stateMu.Lock()
	s.HpsPowCosts[actionType] = value
	s.stateMu.Unlock()
}

func (s *Server) GetHpsPowCostBase(actionType string) int {
	actionType = strings.TrimSpace(actionType)
	if s == nil || actionType == "" {
		return 0
	}
	s.stateMu.RLock()
	value := s.HpsPowCosts[actionType]
	s.stateMu.RUnlock()
	return value
}

func (s *Server) ListHpsPowCostBases() map[string]int {
	if s == nil {
		return nil
	}
	s.stateMu.RLock()
	out := make(map[string]int, len(s.HpsPowCosts))
	for key, value := range s.HpsPowCosts {
		out[key] = value
	}
	s.stateMu.RUnlock()
	return out
}

// ConsumeExchangeToken atomically retrieves and deletes a token, preventing TOCTOU races.
func (s *Server) ConsumeExchangeToken(tokenID string) map[string]any {
	tokenID = strings.TrimSpace(tokenID)
	if s == nil || tokenID == "" {
		return nil
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	token := cloneMapAny(s.ExchangeTokens[tokenID])
	if token == nil {
		// Try loading from DB within the lock
		if s.DB != nil {
			var data string
			err := s.DB.QueryRow(`SELECT token_data FROM exchange_tokens WHERE token_id = ?`, tokenID).Scan(&data)
			if err == nil {
				var dbToken map[string]any
				if json.Unmarshal([]byte(data), &dbToken) == nil {
					token = cloneMapAny(dbToken)
				}
			}
		}
	}
	if token != nil {
		delete(s.ExchangeTokens, tokenID)
		_, _ = s.DB.Exec(`DELETE FROM exchange_tokens WHERE token_id = ?`, tokenID)
	}
	return token
}
