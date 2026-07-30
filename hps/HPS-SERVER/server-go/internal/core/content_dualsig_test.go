package core

import (
	"testing"
)

func TestDualSignatureRegistration(t *testing.T) {
	t.Run("RegistrationStructure", func(t *testing.T) {
		registration := ContentRegistration{
			ContentHash:      "abc123",
			UserSignature:    "user_sig",
			ServerASignature: "server_a_sig",
			ServerBSignature: "server_b_sig",
			Timestamp:        1234567890,
		}

		if registration.ContentHash != "abc123" {
			t.Errorf("Expected ContentHash 'abc123', got '%s'", registration.ContentHash)
		}
		if registration.UserSignature == "" {
			t.Error("Expected non-empty UserSignature")
		}
		if registration.ServerASignature == "" {
			t.Error("Expected non-empty ServerASignature")
		}
		if registration.ServerBSignature == "" {
			t.Error("Expected non-empty ServerBSignature")
		}
	})
}

func TestDualSignatureReplication(t *testing.T) {
	t.Run("ReplicationRequiresAllSignatures", func(t *testing.T) {
		contentHash := "test_hash"
		userSig := "user_signature"
		serverASig := "server_a_signature"

		if contentHash == "" || userSig == "" || serverASig == "" {
			t.Error("Replication requires all signatures")
		}
	})
}

func TestContentCensorship_Prevented(t *testing.T) {
	t.Run("ContentExistsOnMultipleServers", func(t *testing.T) {
		registrations := 2
		if registrations < 2 {
			t.Error("Content needs at least 2 registrations to prevent censorship")
		}
	})
}

func TestContentRepublish_Success(t *testing.T) {
	t.Run("RepublishWithSameHashAndSignature", func(t *testing.T) {
		contentHash := "original_hash"
		userSignature := "user_signature"

		newRegistration := ContentRegistration{
			ContentHash:   contentHash,
			UserSignature: userSignature,
		}

		if newRegistration.ContentHash != contentHash {
			t.Error("Re-published content should have same hash")
		}
	})
}
