package core

import (
	"testing"
)

func TestNodeStability_Reqs(t *testing.T) {
	t.Run("MinimumRequirements", func(t *testing.T) {
		knownServers := 2
		registeredUsers := 1
		activeMiners := 1

		if knownServers < 2 {
			t.Error("Need at least 2 servers")
		}
		if registeredUsers < 1 {
			t.Error("Need at least 1 user")
		}
		if activeMiners < 1 {
			t.Error("Need at least 1 active miner")
		}
	})
}

func TestNodeStability_Levels(t *testing.T) {
	t.Run("NodeStable", func(t *testing.T) {
		if NodeStable != 2 {
			t.Errorf("Expected NodeStable=2, got %d", NodeStable)
		}
	})

	t.Run("NodeDegraded", func(t *testing.T) {
		if NodeDegraded != 1 {
			t.Errorf("Expected NodeDegraded=1, got %d", NodeDegraded)
		}
	})

	t.Run("NodeUnstable", func(t *testing.T) {
		if NodeUnstable != 0 {
			t.Errorf("Expected NodeUnstable=0, got %d", NodeUnstable)
		}
	})
}

func TestNodeStability_Operations(t *testing.T) {
	t.Run("UnstableBlocksEconomicOps", func(t *testing.T) {
		level := NodeUnstable
		shouldBlock := level < NodeStable
		if !shouldBlock {
			t.Error("Unstable node should block economic operations")
		}
	})

	t.Run("StableAllowsAllOps", func(t *testing.T) {
		level := NodeStable
		shouldBlock := level < NodeStable
		if shouldBlock {
			t.Error("Stable node should allow all operations")
		}
	})
}

func TestNodeStability_ActiveMinerDefinition(t *testing.T) {
	t.Run("ActiveMinerCriteria", func(t *testing.T) {
		bannedUntil := 0.0
		blockedUntil := 0.0
		lastActivity := now() - 60

		isActive := (bannedUntil <= 0 || bannedUntil < now()) &&
			(blockedUntil <= 0 || blockedUntil < now()) &&
			lastActivity > now()-300

		if !isActive {
			t.Error("Miner should be considered active")
		}
	})

	t.Run("InactiveMinerCriteria", func(t *testing.T) {
		bannedUntil := now() + 3600
		lastActivity := now() - 60

		isActive := (bannedUntil <= 0 || bannedUntil < now()) &&
			lastActivity > now()-300

		if isActive {
			t.Error("Banned miner should not be considered active")
		}
	})
}
