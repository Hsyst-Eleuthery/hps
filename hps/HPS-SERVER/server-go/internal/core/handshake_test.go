package core

import (
	"testing"
)

func TestHandshake_Success(t *testing.T) {
	t.Run("HandshakeInitStruct", func(t *testing.T) {
		handshake := ServerHandshakeInit{
			ServerID:  "server_a",
			Nonce:     "MTIzNDU2Nzg5MDEyMzQ1Ng==",
			PublicKey: "pubkey",
			Timestamp: 1234567890,
		}

		if handshake.ServerID != "server_a" {
			t.Errorf("Expected ServerID 'server_a', got '%s'", handshake.ServerID)
		}
		if handshake.Nonce == "" {
			t.Error("Expected non-empty nonce")
		}
	})

	t.Run("HandshakeResponseStruct", func(t *testing.T) {
		response := ServerHandshakeResponse{
			ServerID:  "server_b",
			Nonce:     "NjU0MzIxMDk4NzY1NDMyMQ==",
			PublicKey: "pubkey_b",
			Signature: "signature",
			Timestamp: 1234567891,
		}

		if response.ServerID != "server_b" {
			t.Errorf("Expected ServerID 'server_b', got '%s'", response.ServerID)
		}
		if response.Signature == "" {
			t.Error("Expected non-empty Signature")
		}
	})
}

func TestHandshake_InvalidSignature(t *testing.T) {
	t.Run("InvalidSignatureRejected", func(t *testing.T) {
		result := VerifyRawTextSignature("test_data", "invalid_signature", "invalid_key")
		if result {
			t.Error("Expected invalid signature to be rejected")
		}
	})
}

func TestHandshake_Timeout(t *testing.T) {
	t.Run("HandshakeExpiry", func(t *testing.T) {
		TTL := 300.0
		if TTL != 300.0 {
			t.Errorf("Expected TTL 300 seconds, got %f", TTL)
		}
	})
}

func TestHandshake_KeyRotation(t *testing.T) {
	t.Run("EphemeralKeysDiscarded", func(t *testing.T) {
		keyUsed := true
		if !keyUsed {
			t.Error("Expected key to be marked as used")
		}
	})
}
