package core

import (
	"log"
	"sync"
	"time"
)

const (
	voucherLockTimeoutSec = 60 // 60 seconds lock timeout
	lockCleanupInterval   = 30 // cleanup every 30 seconds
)

// VoucherLock represents a lock on a voucher to prevent double-spend.
type VoucherLock struct {
	VoucherID           string  `json:"voucher_id"`
	LockedBy            string  `json:"locked_by"`
	User                string  `json:"user"`
	Amount              int     `json:"amount"`
	Timestamp           float64 `json:"timestamp"`
	UserSignature       string  `json:"user_signature"`
	ServerASignature    string  `json:"server_a_signature"`
	ServerBConfirmation string  `json:"server_b_confirmation"`
	ExpiresAt           float64 `json:"expires_at"`
	Status              string  `json:"status"` // "pending", "confirmed", "expired", "spent"
}

var (
	lockMu       sync.Mutex
	voucherLocks = map[string]*VoucherLock{}
)

// HandleVoucherLock handles the /voucher/lock endpoint.
// Initiates a lock on a voucher to prevent double-spend.
func (s *Server) HandleVoucherLock(data map[string]any) map[string]any {
	voucherID := asString(data["voucher_id"])
	user := asString(data["user"])
	timestamp := asFloat(data["timestamp"])
	userSignature := asString(data["user_signature"])

	if voucherID == "" || user == "" || timestamp == 0 || userSignature == "" {
		return map[string]any{"success": false, "error": "missing fields"}
	}

	// Check timestamp freshness
	nowTs := now()
	if nowTs-timestamp > 30 || timestamp-nowTs > 30 {
		return map[string]any{"success": false, "error": "timestamp out of range"}
	}

	// Verify voucher exists and is valid
	info := s.GetVoucherAuditInfo(voucherID)
	if info == nil {
		return map[string]any{"success": false, "error": "voucher not found"}
	}
	status := asString(info["status"])
	if status != "valid" {
		return map[string]any{"success": false, "error": "voucher not available"}
	}

	// Check if already locked
	if existing := s.GetVoucherLock(voucherID); existing != nil && existing.Status == "confirmed" {
		return map[string]any{"success": false, "error": "voucher already locked"}
	}

	// Verify user signature on lock request
	payload := mapValue(info["payload"])
	ownerKey := asString(payload["owner_public_key"])
	lockPayload := map[string]any{
		"voucher_id": voucherID,
		"user":       user,
		"timestamp":  timestamp,
	}
	if ownerKey != "" && !VerifyPayloadSignature(lockPayload, userSignature, ownerKey) {
		return map[string]any{"success": false, "error": "invalid user signature"}
	}

	// Server A signs the lock
	serverASignature := s.SignPayload(lockPayload)

	// Request confirmation from other servers
	confirmation := s.RequestLockConfirmation(voucherID, user, asInt(info["value"]))

	// Create lock
	lock := &VoucherLock{
		VoucherID:         voucherID,
		LockedBy:          s.Address,
		User:              user,
		Amount:            asInt(info["value"]),
		Timestamp:         nowTs,
		UserSignature:     userSignature,
		ServerASignature:  serverASignature,
		ServerBConfirmation: confirmation,
		ExpiresAt:         nowTs + voucherLockTimeoutSec,
		Status:            "confirmed",
	}

	// Store in memory and DB
	s.SetVoucherLock(lock)

	return map[string]any{
		"success":           true,
		"voucher_id":        voucherID,
		"status":            "confirmed",
		"expires_at":        lock.ExpiresAt,
		"server_a_signature": serverASignature,
		"server_b_confirmation": confirmation,
	}
}

// HandleVoucherLockConfirm handles the /voucher/lock/confirm endpoint.
// Confirms a lock request from another server.
func (s *Server) HandleVoucherLockConfirm(data map[string]any) map[string]any {
	voucherID := asString(data["voucher_id"])
	user := asString(data["user"])
	amount := asInt(data["amount"])

	if voucherID == "" || user == "" || amount <= 0 {
		return map[string]any{"success": false, "error": "missing fields"}
	}

	// Check if already locked by someone else
	if existing := s.GetVoucherLock(voucherID); existing != nil {
		if existing.Status == "confirmed" && existing.User != user {
			return map[string]any{"success": false, "error": "voucher already locked by another user"}
		}
	}

	// Create local lock record
	lock := &VoucherLock{
		VoucherID: voucherID,
		LockedBy:  "remote",
		User:      user,
		Amount:    amount,
		Timestamp: now(),
		ExpiresAt: now() + voucherLockTimeoutSec,
		Status:    "confirmed",
	}
	s.SetVoucherLock(lock)

	// Sign confirmation
	confirmPayload := map[string]any{
		"voucher_id": voucherID,
		"server":     s.Address,
		"timestamp":  now(),
	}
	signature := s.SignPayload(confirmPayload)

	return map[string]any{
		"success":   true,
		"signature": signature,
		"timestamp": now(),
	}
}

// HandleVoucherSpent handles the /voucher/spent endpoint.
// Notifies that a voucher has been spent.
func (s *Server) HandleVoucherSpent(data map[string]any) map[string]any {
	voucherID := asString(data["voucher_id"])
	if voucherID == "" {
		return map[string]any{"success": false, "error": "missing voucher_id"}
	}

	lock := s.GetVoucherLock(voucherID)
	if lock != nil {
		lock.Status = "spent"
		s.SetVoucherLock(lock)
	}

	return map[string]any{
		"success":    true,
		"voucher_id": voucherID,
		"status":     "spent",
	}
}

// HandleVoucherLockStatus handles the /voucher/:id/lock-status endpoint.
func (s *Server) HandleVoucherLockStatus(voucherID string) map[string]any {
	if voucherID == "" {
		return map[string]any{"success": false, "error": "missing voucher_id"}
	}

	lock := s.GetVoucherLock(voucherID)
	if lock == nil {
		return map[string]any{
			"success":    true,
			"voucher_id": voucherID,
			"locked":     false,
			"status":     "available",
		}
	}

	// Check if expired
	if now() > lock.ExpiresAt && lock.Status == "confirmed" {
		lock.Status = "expired"
		s.SetVoucherLock(lock)
	}

	return map[string]any{
		"success":    true,
		"voucher_id": voucherID,
		"locked":     lock.Status == "confirmed",
		"status":     lock.Status,
		"locked_by":  lock.LockedBy,
		"user":       lock.User,
		"expires_at": lock.ExpiresAt,
	}
}

// GetVoucherLock returns the lock for a voucher, or nil if not locked.
func (s *Server) GetVoucherLock(voucherID string) *VoucherLock {
	lockMu.Lock()
	defer lockMu.Unlock()

	// Check memory first
	if lock, ok := voucherLocks[voucherID]; ok {
		return lock
	}

	// Check DB
	var lock VoucherLock
	var serverBConf []byte
	err := s.DB.QueryRow(`SELECT voucher_id, locked_by, user, amount, created_at,
		user_signature, server_a_signature, server_b_confirmation, expires_at, status
		FROM voucher_locks WHERE voucher_id = ?`, voucherID).
		Scan(&lock.VoucherID, &lock.LockedBy, &lock.User, &lock.Amount, &lock.Timestamp,
			&lock.UserSignature, &lock.ServerASignature, &serverBConf, &lock.ExpiresAt, &lock.Status)
	if err != nil {
		return nil
	}
	lock.ServerBConfirmation = string(serverBConf)

	// Cache in memory
	voucherLocks[voucherID] = &lock
	return &lock
}

// SetVoucherLock stores a lock atomically in memory and DB.
// C-01 FIX: Use BEGIN IMMEDIATE for atomicity.
func (s *Server) SetVoucherLock(lock *VoucherLock) {
	if lock == nil {
		return
	}

	lockMu.Lock()
	defer lockMu.Unlock()

	_ = s.BeginTx()
	txDone := false
	defer func() {
		if !txDone {
			s.RollbackTx()
		}
	}()
	_, _ = s.TxExec(`INSERT OR REPLACE INTO voucher_locks
		(voucher_id, locked_by, user, amount, user_signature, server_a_signature,
		 server_b_confirmation, created_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		lock.VoucherID, lock.LockedBy, lock.User, lock.Amount,
		lock.UserSignature, lock.ServerASignature, lock.ServerBConfirmation,
		lock.Timestamp, lock.ExpiresAt, lock.Status)
	s.CommitTx()
	txDone = true

	// Update memory cache
	voucherLocks[lock.VoucherID] = lock
}

// RequestLockConfirmation requests confirmation from another server for a lock.
func (s *Server) RequestLockConfirmation(voucherID, user string, amount int) string {
	servers := s.listRemoteServersByPriority()
	if len(servers) == 0 {
		return ""
	}

	lockPayload := map[string]any{
		"voucher_id": voucherID,
		"user":       user,
		"amount":     amount,
	}

	for _, serverAddr := range servers {
		ok, resp, errMsg := s.MakeRemoteRequestJSON(serverAddr, "/voucher/lock/confirm", "POST", lockPayload)
		if ok {
			signature := asString(resp["signature"])
			if signature != "" {
				return signature
			}
		} else {
			log.Printf("lock confirmation failed for %s from %s: %s", voucherID, serverAddr, errMsg)
		}
	}
	return ""
}

// CleanupExpiredLocks removes expired locks.
func (s *Server) CleanupExpiredLocks() {
	lockMu.Lock()
	defer lockMu.Unlock()

	nowTs := now()
	_ = s.BeginTx()
	txDone := false
	defer func() {
		if !txDone {
			s.RollbackTx()
		}
	}()
	for voucherID, lock := range voucherLocks {
		if nowTs > lock.ExpiresAt && lock.Status == "confirmed" {
			lock.Status = "expired"
			_, _ = s.TxExec(`UPDATE voucher_locks SET status = ? WHERE voucher_id = ?`,
				"expired", voucherID)
			delete(voucherLocks, voucherID)
		}
	}
	s.CommitTx()
	txDone = true
}

// NotifyLockSpent notifies all servers that a voucher has been spent.
func (s *Server) NotifyLockSpent(voucherID string) {
	servers := s.listRemoteServersByPriority()
	for _, serverAddr := range servers {
		go func(addr string) {
			s.MakeRemoteRequestJSON(addr, "/voucher/spent", "POST", map[string]any{
				"voucher_id": voucherID,
			})
		}(serverAddr)
	}
}

func init() {
	go func() {
		ticker := time.NewTicker(lockCleanupInterval * time.Second)
		for range ticker.C {
			// Cleanup will be triggered when server instance is available
		}
	}()
}
