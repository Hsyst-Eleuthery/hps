package core

import (
	"fmt"
	"log"
	"runtime"
	"time"
)

// ServerAuditStats holds non-economic server statistics for audit contracts.
type ServerAuditStats struct {
	ServerID           string  `json:"server_id"`
	ServerAddress      string  `json:"server_address"`
	StartTime          float64 `json:"start_time"`
	FirstBootTime      float64 `json:"first_boot_time"`
	UptimeSeconds      float64 `json:"uptime_seconds"`
	UptimeContinuous   float64 `json:"uptime_continuous"`
	TotalUsers         int     `json:"total_users"`
	OnlineUsers        int     `json:"online_users"`
	TotalContent       int     `json:"total_content"`
	TotalDNS           int     `json:"total_dns"`
	TotalContracts     int     `json:"total_contracts"`
	TotalMiners        int     `json:"total_miners"`
	ActiveMiners       int     `json:"active_miners"`
	KnownServers       int     `json:"known_servers"`
	NodeStability      string  `json:"node_stability"`
	GoVersion          string  `json:"go_version"`
	Platform           string  `json:"platform"`
	OwnerEnabled       bool    `json:"owner_enabled"`
	OwnerUsername       string  `json:"owner_username"`
	OwnerRevenueShare  float64 `json:"owner_revenue_share"`
	CodeHash           string  `json:"code_hash"`
	Timestamp          float64 `json:"timestamp"`
}

// ServerAuditContract is the complete audit contract emitted on login/signup.
type ServerAuditContract struct {
	Type        string            `json:"type"`
	Version     int               `json:"version"`
	ServerID    string            `json:"server_id"`
	ContractID  string            `json:"contract_id"`
	Stats       ServerAuditStats  `json:"stats"`
	Signature   string            `json:"signature"`
	IssuedAt    float64           `json:"issued_at"`
}

// GenerateAuditContract creates a custody audit contract with server statistics.
func (s *Server) GenerateAuditContract(username string) map[string]any {
	stats := s.collectAuditStats(username)
	
	// Build contract payload
	contract := map[string]any{
		"type":       "server_audit",
		"version":    1,
		"server_id":  stats.ServerID,
		"username":   username,
		"stats":      stats,
		"issued_at":  now(),
	}
	
	// Sign with custody key
	signature := s.SignPayloadWithKey(contract, KeyPurposeCustody)
	contract["signature"] = signature
	
	// Save as contract
	contractID := s.SaveServerContract("server_audit", []ContractDetail{
		{Key: "SERVER_ID", Value: stats.ServerID},
		{Key: "USERNAME", Value: username},
		{Key: "UPTIME", Value: int(stats.UptimeSeconds)},
		{Key: "TOTAL_USERS", Value: stats.TotalUsers},
		{Key: "ONLINE_USERS", Value: stats.OnlineUsers},
		{Key: "ACTIVE_MINERS", Value: stats.ActiveMiners},
		{Key: "KNOWN_SERVERS", Value: stats.KnownServers},
		{Key: "NODE_STABILITY", Value: stats.NodeStability},
		{Key: "CODE_HASH", Value: stats.CodeHash},
	}, username)
	
	contract["contract_id"] = contractID
	
	log.Printf("audit contract issued: user=%s contract=%s uptime=%.0fs users=%d miners=%d servers=%d",
		username, contractID, stats.UptimeSeconds, stats.TotalUsers, stats.ActiveMiners, stats.KnownServers)
	
	return contract
}

// collectAuditStats gathers all non-economic server statistics.
func (s *Server) collectAuditStats(username string) ServerAuditStats {
	nowTs := now()
	uptime := time.Since(s.StartTime).Seconds()
	
	// Count users
	var totalUsers int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM users 
		WHERE username != 'custody' AND username != 'owner'`).Scan(&totalUsers)
	
	// Count online users (authenticated in last 5 minutes)
	var onlineUsers int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM users 
		WHERE last_activity > ? AND username != 'custody' AND username != 'owner'`,
		nowTs-300).Scan(&onlineUsers)
	
	// Count content
	var totalContent int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM content`).Scan(&totalContent)
	
	// Count DNS records
	var totalDNS int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM dns_records`).Scan(&totalDNS)
	
	// Count contracts
	var totalContracts int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM contracts`).Scan(&totalContracts)
	
	// Count total miners (registered in miner_stats)
	var totalMiners int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM miner_stats`).Scan(&totalMiners)
	
	// Count active miners (mining now - last_updated within 5 min, not banned, not blocked)
	var activeMiners int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM miner_stats ms 
		WHERE (ms.banned_until IS NULL OR ms.banned_until < ?)
		AND ms.last_updated > ?
		AND NOT EXISTS (
			SELECT 1 FROM miner_pending_sigs mps 
			WHERE mps.username = ms.username AND mps.blocked_until > ?
		)`, nowTs, nowTs-300, nowTs).Scan(&activeMiners)
	
	// Count known servers
	var knownServers int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM known_servers 
		WHERE is_active = 1 AND last_connected > ?`, nowTs-86400).Scan(&knownServers)
	
	// Get node stability
	stability := s.CheckNodeStability()
	stabilityStr := "stable"
	switch stability.Level {
	case NodeUnstable:
		stabilityStr = "unstable"
	case NodeDegraded:
		stabilityStr = "degraded"
	}
	
	// Get first boot time (oldest contract)
	var firstBoot float64
	_ = s.DB.QueryRow(`SELECT MIN(timestamp) FROM contracts LIMIT 1`).Scan(&firstBoot)
	if firstBoot <= 0 {
		firstBoot = nowTs
	}
	
	// Calculate continuous uptime (time since last server restart)
	continuousUptime := uptime
	
	// Owner revenue share (if enabled)
	ownerRevenueShare := 0.0
	if s.cfg.OwnerEnabled {
		ownerRevenueShare = s.cfg.ExchangeFeeRate
	}
	
	// Use embedded compile-time hash (not runtime computation)
	codeHash := ServerCodeHash
	
	return ServerAuditStats{
		ServerID:          s.ServerID,
		ServerAddress:     s.Address,
		StartTime:         float64(s.StartTime.Unix()),
		FirstBootTime:     firstBoot,
		UptimeSeconds:     uptime,
		UptimeContinuous:  continuousUptime,
		TotalUsers:        totalUsers,
		OnlineUsers:       onlineUsers,
		TotalContent:      totalContent,
		TotalDNS:          totalDNS,
		TotalContracts:    totalContracts,
		TotalMiners:       totalMiners,
		ActiveMiners:      activeMiners,
		KnownServers:      knownServers,
		NodeStability:     stabilityStr,
		GoVersion:         runtime.Version(),
		Platform:          fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		OwnerEnabled:      s.cfg.OwnerEnabled,
		OwnerUsername:      s.cfg.OwnerUsername,
		OwnerRevenueShare: ownerRevenueShare,
		CodeHash:          codeHash,
		Timestamp:         nowTs,
	}
}

// HandleAuditContractRequest handles requests for audit contracts.
func (s *Server) HandleAuditContractRequest(data map[string]any) map[string]any {
	username := asString(data["username"])
	if username == "" {
		return map[string]any{"success": false, "error": "missing username"}
	}
	
	// Verify user exists
	var exists int
	_ = s.DB.QueryRow(`SELECT COUNT(1) FROM users WHERE username = ?`, username).Scan(&exists)
	if exists == 0 {
		return map[string]any{"success": false, "error": "user not found"}
	}
	
	contract := s.GenerateAuditContract(username)
	return map[string]any{
		"success":  true,
		"contract": contract,
	}
}

// HandleCodeIntegrityCheck handles the /server/integrity endpoint.
// Returns the compile-time embedded hash and server stats for clients to verify.
// O hash é embutido no binário durante a compilação - não é calculado em runtime.
func (s *Server) HandleCodeIntegrityCheck() map[string]any {
	return map[string]any{
		"success":      true,
		"server_id":    s.ServerID,
		"code_hash":    ServerCodeHash,
		"code_version": ServerCodeVersion,
		"build_time":   ServerBuildTimestamp,
		"go_version":   runtime.Version(),
		"platform":     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"start_time":   float64(s.StartTime.Unix()),
		"uptime":       time.Since(s.StartTime).Seconds(),
		"timestamp":    now(),
	}
}

// EmitAuditContractOnAuth emits an audit contract after successful authentication.
func (s *Server) EmitAuditContractOnAuth(username string) map[string]any {
	contract := s.GenerateAuditContract(username)
	return contract
}
