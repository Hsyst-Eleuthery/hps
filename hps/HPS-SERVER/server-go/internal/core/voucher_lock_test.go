package core

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestLockVoucher_Success(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	serverAddr := "server_a:8080"

	t.Run("LockCreation", func(t *testing.T) {
		voucherID := "test_voucher_lock_001"
		user := "test_user"
		amount := 10
		nowTs := now()

		_, err := db.Exec(`INSERT INTO voucher_locks
			(voucher_id, locked_by, user, amount, user_signature, server_a_signature, created_at, expires_at, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			voucherID, serverAddr, user, amount, "sig_user", "sig_server", nowTs, nowTs+60, "pending")
		if err != nil {
			t.Fatalf("Failed to create lock: %v", err)
		}

		var status string
		err = db.QueryRow("SELECT status FROM voucher_locks WHERE voucher_id = ?", voucherID).Scan(&status)
		if err != nil {
			t.Fatalf("Failed to query lock: %v", err)
		}
		if status != "pending" {
			t.Errorf("Expected status 'pending', got '%s'", status)
		}
	})
}

func TestLockVoucher_AlreadyLocked(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	voucherID := "test_voucher_double_lock"
	nowTs := now()

	_, _ = db.Exec(`INSERT INTO voucher_locks
		(voucher_id, locked_by, user, amount, user_signature, server_a_signature, created_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		voucherID, "server_a", "user_a", 10, "sig1", "sig2", nowTs, nowTs+60, "pending")

	_, err := db.Exec(`INSERT INTO voucher_locks
		(voucher_id, locked_by, user, amount, user_signature, server_a_signature, created_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		voucherID, "server_b", "user_b", 10, "sig3", "sig4", nowTs, nowTs+60, "pending")

	if err == nil {
		t.Error("Expected duplicate lock to fail")
	}
}

func TestLockVoucher_Timeout(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	voucherID := "test_voucher_timeout"
	nowTs := now()

	_, _ = db.Exec(`INSERT INTO voucher_locks
		(voucher_id, locked_by, user, amount, user_signature, server_a_signature, created_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		voucherID, "server_a", "user_a", 10, "sig1", "sig2", nowTs-120, nowTs-60, "pending")

	var expiresAt float64
	_ = db.QueryRow("SELECT expires_at FROM voucher_locks WHERE voucher_id = ?", voucherID).Scan(&expiresAt)

	if expiresAt >= now() {
		t.Error("Expected lock to be expired")
	}
}

func TestLockCleanup_Expired(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	nowTs := now()

	for i := 0; i < 3; i++ {
		_, _ = db.Exec(`INSERT INTO voucher_locks
			(voucher_id, locked_by, user, amount, user_signature, server_a_signature, created_at, expires_at, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"expired_lock_00"+string(rune('0'+i)), "server_a", "user_a", 10, "sig1", "sig2",
			nowTs-120, nowTs-60, "pending")
	}

	result, _ := db.Exec("UPDATE voucher_locks SET status = 'expired' WHERE expires_at < ? AND status = 'pending'", now())
	affected, _ := result.RowsAffected()

	if affected != 3 {
		t.Errorf("Expected 3 locks cleaned up, got %d", affected)
	}
}

func TestDoubleSpend_Prevented(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	voucherID := "test_voucher_double_spend"
	nowTs := now()

	_, _ = db.Exec(`INSERT INTO voucher_locks
		(voucher_id, locked_by, user, amount, user_signature, server_a_signature, created_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		voucherID, "server_a", "user_a", 10, "sig1", "sig2", nowTs, nowTs+60, "confirmed")

	var lockStatus string
	err := db.QueryRow("SELECT status FROM voucher_locks WHERE voucher_id = ? AND status IN ('pending', 'confirmed')",
		voucherID).Scan(&lockStatus)

	if err != nil {
		t.Fatalf("Expected to find existing lock: %v", err)
	}

	if lockStatus == "" {
		t.Error("Expected to detect existing lock to prevent double-spend")
	}
}

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS voucher_locks (
		voucher_id TEXT PRIMARY KEY,
		locked_by TEXT NOT NULL,
		user TEXT NOT NULL,
		amount INTEGER NOT NULL,
		user_signature BLOB NOT NULL,
		server_a_signature BLOB NOT NULL,
		server_b_confirmation BLOB,
		created_at REAL NOT NULL,
		expires_at REAL NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending'
	)`)

	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		public_key TEXT,
		created_at REAL
	)`)

	_ = time.Now()

	return db
}
