package core

import "strings"

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
}

func (s *Server) GetExchangeToken(tokenID string) map[string]any {
	tokenID = strings.TrimSpace(tokenID)
	if s == nil || tokenID == "" {
		return nil
	}
	s.stateMu.RLock()
	token := cloneMapAny(s.ExchangeTokens[tokenID])
	s.stateMu.RUnlock()
	return token
}

func (s *Server) DeleteExchangeToken(tokenID string) {
	tokenID = strings.TrimSpace(tokenID)
	if s == nil || tokenID == "" {
		return
	}
	s.stateMu.Lock()
	delete(s.ExchangeTokens, tokenID)
	s.stateMu.Unlock()
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
		return nil
	}
	if !fn(current) {
		return nil
	}
	s.ExchangeTokens[tokenID] = current
	return cloneMapAny(current)
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
