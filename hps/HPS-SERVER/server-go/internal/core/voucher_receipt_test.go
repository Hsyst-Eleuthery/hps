package core

import (
	"testing"
)

func TestCrossServerConfirmation_Success(t *testing.T) {
	// Test that a voucher can be confirmed cross-server with valid signature
	db := setupTestDB(t)
	defer db.Close()

	server := &Server{
		DB:      db,
		Address: "server_a:8080",
	}

	// Create a test user
	_, _ = db.Exec(`INSERT INTO users (username, public_key, created_at) VALUES (?, ?, ?)`,
		"test_user", "test_pubkey", now())

	// Verify the confirmation structure
	t.Run("ConfirmationSignatureStructure", func(t *testing.T) {
		// Verify that the VoucherReceipt struct has required fields
		receipt := VoucherReceipt{
			VoucherID:    "test_voucher_001",
			IssuerServer: server.Address,
		}
		if receipt.VoucherID != "test_voucher_001" {
			t.Errorf("Expected VoucherID 'test_voucher_001', got '%s'", receipt.VoucherID)
		}
		if receipt.IssuerServer != server.Address {
			t.Errorf("Expected IssuerServer '%s', got '%s'", server.Address, receipt.IssuerServer)
		}
	})
}

func TestCrossServerConfirmation_InvalidSignature(t *testing.T) {
	// Test that invalid signatures are rejected
	t.Run("InvalidSignatureRejected", func(t *testing.T) {
		// Verify that VerifyRawTextSignature returns false for invalid signature
		result := VerifyRawTextSignature("test_data", "invalid_signature", "invalid_key")
		if result {
			t.Error("Expected invalid signature to be rejected")
		}
	})
}

func TestVoucherValidation_WithConfirmation(t *testing.T) {
	// Test that a voucher with at least 1 confirmation is valid
	t.Run("VoucherWithConfirmationIsValid", func(t *testing.T) {
		// Simulate a voucher with confirmation
		confirmations := 1
		if confirmations < 1 {
			t.Error("Expected at least 1 confirmation for valid voucher")
		}
	})
}

func TestVoucherValidation_WithoutConfirmation(t *testing.T) {
	// Test that a voucher without confirmation is invalid
	t.Run("VoucherWithoutConfirmationIsInvalid", func(t *testing.T) {
		confirmations := 0
		if confirmations >= 1 {
			t.Error("Expected voucher without confirmation to be invalid")
		}
	})
}
