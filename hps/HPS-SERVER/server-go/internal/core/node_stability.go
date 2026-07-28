package core

import (
	"log"
	"strings"
	"sync"
	"time"
)

// NodeStabilityLevel represents the stability level of an HPS node.
type NodeStabilityLevel int

const (
	// NodeUnstable - Does not meet minimum requirements (2S+1U+1M)
	NodeUnstable NodeStabilityLevel = iota
	// NodeDegraded - Partially meets requirements, limited functionality
	NodeDegraded
	// NodeStable - Meets all minimum requirements
	NodeStable
)

const (
	// Minimum requirements for a stable node
	MinKnownServers   = 1 // At least 1 other server (+ itself = 2S)
	MinRegisteredUsers = 1 // At least 1 registered user
	MinActiveMiners    = 1 // At least 1 active miner (mining RIGHT NOW)

	// Stability check interval
	stabilityCheckInterval = 30 * time.Second

	// Minimum time before a server is considered "known" (30 seconds)
	minServerUptime = 30.0

	// Miner activity window: miner must have updated within this time to be considered "active"
	// 300 seconds = 5 minutes - miner must be actively polling/mining
	minerActivityWindow = 300.0
)

// NodeStability holds the current stability state of the node.
type NodeStability struct {
	mu               sync.RWMutex
	Level            NodeStabilityLevel
	KnownServers     int
	RegisteredUsers  int
	ActiveMiners     int
	LastCheck        float64
	UnstableSince    float64
	Reasons          []string
}

var globalStability = &NodeStability{
	Level: NodeUnstable,
}

// CheckNodeStability verifies if the node meets minimum 2S+1U+1M requirements.
func (s *Server) CheckNodeStability() NodeStability {
	globalStability.mu.Lock()
	defer globalStability.mu.Unlock()

	nowTs := now()
	previousLevel := globalStability.Level

	// Count known servers (excluding self)
	var knownServers int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM known_servers 
		WHERE is_active = 1 AND last_connected > ? AND address != ?`,
		nowTs-minServerUptime, s.Address).Scan(&knownServers)

	// Count registered users (non-system users)
	var registeredUsers int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM users 
		WHERE username != 'custody' AND username != 'owner' 
		AND password_hash != '' AND public_key != '' AND public_key != 'pending'`,
	).Scan(&registeredUsers)

	// Count active miners (mining RIGHT NOW - not banned, not blocked, recent activity within 5 min)
	var activeMiners int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM miner_stats ms 
		WHERE (ms.banned_until IS NULL OR ms.banned_until < ?)
		AND ms.last_updated > ?
		AND NOT EXISTS (
			SELECT 1 FROM miner_pending_sigs mps 
			WHERE mps.username = ms.username AND mps.blocked_until > ?
		)`,
		nowTs, nowTs-minerActivityWindow, nowTs).Scan(&activeMiners)

	// Determine stability level and reasons
	var reasons []string
	level := NodeStable

	if knownServers < MinKnownServers {
		level = NodeUnstable
		reasons = append(reasons, "insufficient_known_servers")
	}
	if registeredUsers < MinRegisteredUsers {
		if level > NodeUnstable {
			level = NodeDegraded
		}
		reasons = append(reasons, "insufficient_registered_users")
	}
	if activeMiners < MinActiveMiners {
		if level > NodeUnstable {
			level = NodeDegraded
		}
		reasons = append(reasons, "insufficient_active_miners")
	}

	// Track unstable duration
	if level == NodeUnstable {
		if globalStability.UnstableSince == 0 {
			globalStability.UnstableSince = nowTs
		}
	} else {
		globalStability.UnstableSince = 0
	}

	// Log state transitions
	if previousLevel != level {
		log.Printf("node stability changed: %d -> %d (servers=%d, users=%d, miners=%d)",
			previousLevel, level, knownServers, registeredUsers, activeMiners)
	}

	globalStability.Level = level
	globalStability.KnownServers = knownServers
	globalStability.RegisteredUsers = registeredUsers
	globalStability.ActiveMiners = activeMiners
	globalStability.LastCheck = nowTs
	globalStability.Reasons = reasons

	return NodeStability{
		Level:           level,
		KnownServers:    knownServers,
		RegisteredUsers: registeredUsers,
		ActiveMiners:    activeMiners,
		LastCheck:       nowTs,
		Reasons:         reasons,
	}
}

// GetNodeStability returns the current node stability (thread-safe).
func GetNodeStability() NodeStability {
	globalStability.mu.RLock()
	defer globalStability.mu.RUnlock()
	return NodeStability{
		Level:           globalStability.Level,
		KnownServers:    globalStability.KnownServers,
		RegisteredUsers: globalStability.RegisteredUsers,
		ActiveMiners:    globalStability.ActiveMiners,
		LastCheck:       globalStability.LastCheck,
		UnstableSince:   globalStability.UnstableSince,
		Reasons:         globalStability.Reasons,
	}
}

// IsNodeStable returns true if node meets minimum 2S+1U+1M requirements.
func IsNodeStable() bool {
	globalStability.mu.RLock()
	defer globalStability.mu.RUnlock()
	return globalStability.Level >= NodeStable
}

// IsNodeDegraded returns true if node is degraded but not fully unstable.
func IsNodeDegraded() bool {
	globalStability.mu.RLock()
	defer globalStability.mu.RUnlock()
	return globalStability.Level == NodeDegraded
}

// IsNodeUnstable returns true if node does not meet minimum requirements.
func IsNodeUnstable() bool {
	globalStability.mu.RLock()
	defer globalStability.mu.RUnlock()
	return globalStability.Level == NodeUnstable
}

// GetNodeStabilityStatus returns a detailed status for the /node/status endpoint.
func (s *Server) GetNodeStabilityStatus() map[string]any {
	stability := s.CheckNodeStability()
	nowTs := now()

	status := "stable"
	switch stability.Level {
	case NodeUnstable:
		status = "unstable"
	case NodeDegraded:
		status = "degraded"
	}

	unstableDuration := float64(0)
	if stability.UnstableSince > 0 {
		unstableDuration = nowTs - stability.UnstableSince
	}

	return map[string]any{
		"status":              status,
		"level":               int(stability.Level),
		"known_servers":       stability.KnownServers,
		"min_known_servers":   MinKnownServers,
		"registered_users":    stability.RegisteredUsers,
		"min_registered_users": MinRegisteredUsers,
		"active_miners":       stability.ActiveMiners,
		"min_active_miners":   MinActiveMiners,
		"miner_activity_window_seconds": 300,
		"requirements_met":    stability.Level >= NodeStable,
		"reasons":             stability.Reasons,
		"unstable_duration":   unstableDuration,
		"last_check":          stability.LastCheck,
		"server_address":      s.Address,
	}
}

// CanAcceptCrossServerRequests checks if the node can accept cross-server requests.
func (s *Server) CanAcceptCrossServerRequests() (bool, string) {
	stability := s.CheckNodeStability()

	if stability.Level == NodeUnstable {
		return false, "node_unstable: insufficient_known_servers"
	}
	if stability.Level == NodeDegraded {
		// Allow but with warnings
		log.Printf("WARNING: accepting cross-server request on degraded node")
	}
	return true, ""
}

// CanProcessEconomicOperations checks if the node can process economic operations.
func (s *Server) CanProcessEconomicOperations() (bool, string) {
	stability := s.CheckNodeStability()

	if stability.Level == NodeUnstable {
		return false, "node_unstable: economic_operations_disabled"
	}
	if stability.Level == NodeDegraded {
		// Check specific requirements for economic ops
		if stability.ActiveMiners < MinActiveMiners {
			return false, "node_degraded: no_active_miners"
		}
	}
	return true, ""
}

// GetFallbackResponse returns an appropriate fallback response for unstable nodes.
func (s *Server) GetFallbackResponse(operation string) map[string]any {
	stability := s.CheckNodeStability()

	response := map[string]any{
		"success": false,
		"error":   "node_unstable",
		"status":  "unstable",
		"operation": operation,
		"min_requirements": map[string]any{
			"servers":  MinKnownServers + 1, // +1 for self
			"users":    MinRegisteredUsers,
			"miners":   MinActiveMiners,
		},
		"current_state": map[string]any{
			"servers": stability.KnownServers,
			"users":   stability.RegisteredUsers,
			"miners":  stability.ActiveMiners,
		},
		"reasons": stability.Reasons,
	}

	// Add specific guidance based on missing requirements
	var guidance []string
	for _, reason := range stability.Reasons {
		switch reason {
		case "insufficient_known_servers":
			guidance = append(guidance, "Connect to at least one other HPS server")
		case "insufficient_registered_users":
			guidance = append(guidance, "Register at least one user account")
		case "insufficient_active_miners":
			guidance = append(guidance, "Start at least one active miner")
		}
	}
	response["guidance"] = guidance

	return response
}

// ShouldBlockExternalRequest determines if an external request should be blocked.
func (s *Server) ShouldBlockExternalRequest(path string) (bool, string) {
	// Never block health/info endpoints
	allowlist := []string{
		"/health",
		"/server_info",
		"/node/status",
	}
	for _, allowed := range allowlist {
		if strings.HasPrefix(path, allowed) {
			return false, ""
		}
	}

	// Check stability
	stability := s.CheckNodeStability()
	if stability.Level == NodeUnstable {
		// Block most operations on unstable nodes
		blockPaths := []string{
			"/exchange/",
			"/voucher/",
			"/transfer/",
			"/content/register",
			"/content/replicate",
			"/handshake/",
		}
		for _, blocked := range blockPaths {
			if strings.HasPrefix(path, blocked) {
				return true, "node_unstable"
			}
		}
	}

	return false, ""
}

// StartStabilityMonitor starts the background stability monitoring.
func (s *Server) StartStabilityMonitor() {
	go func() {
		// Initial check
		s.CheckNodeStability()

		ticker := time.NewTicker(stabilityCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				s.CheckNodeStability()
			}
		}
	}()
}

// HandleNodeStatus handles the /node/status endpoint.
func (s *Server) HandleNodeStatus() map[string]any {
	return s.GetNodeStabilityStatus()
}
