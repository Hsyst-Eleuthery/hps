package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"math/big"
	"time"
)

type PowChallenge struct {
	Challenge     string
	TargetBits    int
	Timestamp     float64
	TargetSeconds float64
	ActionType    string
	VoucherID     string
}

func powChallengeKey(clientIdentifier, actionType string) string {
	return clientIdentifier + ":" + actionType
}

func leadingZeroBits(b []byte) int {
	count := 0
	for _, by := range b {
		if by == 0 {
			count += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if by&(1<<uint(i)) != 0 {
				return count
			}
			count++
		}
	}
	return count
}

func computeTargetBits(hashrate float64, targetSeconds float64) int {
	if hashrate <= 0 {
		return 1
	}
	expected := hashrate * targetSeconds
	if expected <= 1 {
		return 1
	}
	b := math.Ceil(math.Log2(expected))
	if b < 1 {
		b = 1
	}
	if b > 256 {
		b = 256
	}
	return int(b)
}

func (s *Server) GeneratePowChallenge(clientIdentifier string, actionType string) map[string]any {
	now := float64(time.Now().UnixNano()) / 1e9
	s.powMu.Lock()
	if s.LoginAttempts[clientIdentifier] == nil {
		s.LoginAttempts[clientIdentifier] = []float64{}
	}
	filtered := []float64{}
	for _, t := range s.LoginAttempts[clientIdentifier] {
		if now-t < 300 {
			filtered = append(filtered, t)
		}
	}
	s.LoginAttempts[clientIdentifier] = filtered
	s.powMu.Unlock()
	var attemptCount int
	_ = s.DB.QueryRow("SELECT attempt_count FROM rate_limits WHERE client_identifier = ? AND action_type = ?", clientIdentifier, actionType).Scan(&attemptCount)
	if attemptCount == 0 {
		attemptCount = 1
	}
	baseBits := 12
	targetSeconds := 30.0
	switch actionType {
	case "upload":
		baseBits, targetSeconds = 8, 20.0
	case "dns":
		baseBits, targetSeconds = 6, 15.0
	case "report":
		baseBits, targetSeconds = 6, 10.0
	case "hps_mint":
		baseBits, targetSeconds = 12, 30.0
	case "login":
		baseBits, targetSeconds = 12, 20.0
	case "usage_contract":
		baseBits, targetSeconds = 10, 20.0
	case "contract_transfer":
		baseBits, targetSeconds = 10, 20.0
	case "contract_reset":
		baseBits, targetSeconds = 10, 20.0
	case "contract_certify":
		baseBits, targetSeconds = 10, 20.0
	case "hps_transfer":
		baseBits, targetSeconds = 10, 20.0
	}
	s.powMu.RLock()
	recentCount := len(s.LoginAttempts[clientIdentifier]) + attemptCount
	clientHashrate := s.ClientHashrates[clientIdentifier]
	s.powMu.RUnlock()
	if recentCount > 0 {
		baseBits += minInt(10, recentCount)
	}
	if clientHashrate <= 0 {
		clientHashrate = 100000
	}
	targetBits := computeTargetBits(clientHashrate, targetSeconds)
	if targetBits < baseBits {
		targetBits = baseBits
	}

	voucherID := ""
	var challengeMessage []byte
	if actionType == "hps_mint" {
		voucherID = newUUID()
		challengeMessage = []byte("HPSMINT:" + voucherID + ":" + randomHex(16))
	} else {
		challengeMessage = randomBytes(32)
	}
	challenge := base64.StdEncoding.EncodeToString(challengeMessage)

	key := powChallengeKey(clientIdentifier, actionType)
	s.powMu.Lock()
	s.PowChallenges[key] = PowChallenge{
		Challenge:     challenge,
		TargetBits:    targetBits,
		Timestamp:     now,
		TargetSeconds: targetSeconds,
		ActionType:    actionType,
		VoucherID:     voucherID,
	}
	s.powMu.Unlock()
	_, _ = s.DB.Exec("INSERT INTO pow_history (client_identifier, challenge, target_bits, timestamp) VALUES (?, ?, ?, ?)", clientIdentifier, challenge, targetBits, now)

	payload := map[string]any{
		"challenge":      challenge,
		"target_bits":    targetBits,
		"message":        "Solve PoW for " + actionType,
		"target_seconds": targetSeconds,
		"action_type":    actionType,
	}
	if voucherID != "" {
		payload["voucher_id"] = voucherID
	}
	return payload
}

func (s *Server) VerifyPowSolution(clientIdentifier, nonce string, hashrateObserved float64, actionType string) bool {
	ok, _ := s.VerifyPowSolutionDetails(clientIdentifier, nonce, hashrateObserved, actionType)
	return ok
}

func (s *Server) VerifyPowSolutionDetails(clientIdentifier, nonce string, hashrateObserved float64, actionType string) (bool, map[string]any) {
	s.powMu.RLock()
	key := powChallengeKey(clientIdentifier, actionType)
	challengeData, ok := s.PowChallenges[key]
	s.powMu.RUnlock()
	if !ok {
		return false, nil
	}
	if float64(time.Now().UnixNano())/1e9-challengeData.Timestamp > 300 {
		s.powMu.Lock()
		delete(s.PowChallenges, key)
		s.powMu.Unlock()
		return false, nil
	}
	challengeBytes, err := base64.StdEncoding.DecodeString(challengeData.Challenge)
	if err != nil {
		return false, nil
	}
	nonceInt, err := parseUint64(nonce)
	if err != nil {
		return false, nil
	}
	data := append(challengeBytes, uint64ToBytes(nonceInt)...)
	h := sha256.Sum256(data)
	lzb := leadingZeroBits(h[:])
	if lzb >= challengeData.TargetBits {
		solveTime := float64(time.Now().UnixNano())/1e9 - challengeData.Timestamp
		_, _ = s.DB.Exec("UPDATE pow_history SET success = 1, solve_time = ? WHERE client_identifier = ? AND challenge = ?", solveTime, clientIdentifier, challengeData.Challenge)
		s.powMu.Lock()
		delete(s.PowChallenges, key)
		s.LoginAttempts[clientIdentifier] = append(s.LoginAttempts[clientIdentifier], float64(time.Now().UnixNano())/1e9)
		if hashrateObserved > 0 {
			s.ClientHashrates[clientIdentifier] = hashrateObserved
		}
		s.powMu.Unlock()
		return true, map[string]any{
			"challenge":         challengeData.Challenge,
			"target_bits":       challengeData.TargetBits,
			"target_seconds":    challengeData.TargetSeconds,
			"action_type":       actionType,
			"solve_time":        solveTime,
			"hashrate_observed": hashrateObserved,
			"voucher_id":        challengeData.VoucherID,
		}
	}
	return false, nil
}

func randomHex(n int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	for i := range b {
		b[i] = hexChars[int(b[i])%len(hexChars)]
	}
	return string(b)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func parseUint64(value string) (uint64, error) {
	v, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return 0, ErrInvalidNumber
	}
	if !v.IsUint64() {
		return 0, ErrInvalidNumber
	}
	return v.Uint64(), nil
}

func uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var ErrInvalidNumber = errors.New("invalid number")
