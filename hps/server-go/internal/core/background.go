package core

import (
	"context"
	"sync"
	"time"
)

func (s *Server) StartBackgroundJobs(ctx context.Context) {
	go s.periodicCleanup(ctx)
	go s.periodicPing(ctx)
	go s.periodicDbSeal(ctx)
}

func (s *Server) periodicCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nowTs := now()
			_, _ = s.DB.Exec(`DELETE FROM rate_limits WHERE last_action < ?`, nowTs-86400)
			_, _ = s.DB.Exec(`DELETE FROM pow_history WHERE timestamp < ?`, nowTs-604800)
			_, _ = s.DB.Exec(`DELETE FROM server_sync_history WHERE last_sync < ?`, nowTs-2592000)
			_, _ = s.DB.Exec(`DELETE FROM server_connectivity_log WHERE timestamp < ?`, nowTs-2592000)
			_, _ = s.DB.Exec(`UPDATE network_nodes SET is_online = 0 WHERE last_seen < ?`, nowTs-3600)
			_, _ = s.DB.Exec(`UPDATE server_nodes SET is_active = 0 WHERE last_seen < ?`, nowTs-86400)
			_, _ = s.DB.Exec(`UPDATE known_servers SET is_active = 0 WHERE last_connected < ?`, nowTs-604800)
			_, _ = s.DB.Exec(`DELETE FROM client_files WHERE last_sync < ?`, nowTs-2592000)
			_, _ = s.DB.Exec(`DELETE FROM client_dns_files WHERE last_sync < ?`, nowTs-2592000)
			_, _ = s.DB.Exec(`DELETE FROM client_contracts WHERE last_sync < ?`, nowTs-2592000)
			s.CleanupHpsTransferSessions()
		}
	}
}

func (s *Server) periodicPing(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rows, err := s.DB.Query(`SELECT address FROM known_servers WHERE is_active = 1`)
			if err != nil {
				continue
			}
			var servers []string
			for rows.Next() {
				var addr string
				if rows.Scan(&addr) == nil {
					servers = append(servers, addr)
				}
			}
			rows.Close()
			for _, serverAddress := range servers {
				if serverAddress == s.Address || serverAddress == s.BindAddress {
					continue
				}
				ok, _, _ := s.MakeRemoteRequestJSON(serverAddress, "/server_info", "GET", nil)
				if ok {
					_, _ = s.DB.Exec(`UPDATE server_nodes SET last_seen = ?, reputation = MIN(100, reputation + 1) WHERE address = ?`,
						now(), serverAddress)
				} else {
					_, _ = s.DB.Exec(`UPDATE server_nodes SET reputation = MAX(1, reputation - 1) WHERE address = ?`,
						serverAddress)
				}
			}
		}
	}
}

func (s *Server) periodicDbSeal(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.persistEncryptedDatabaseSnapshot()
		}
	}
}

func (s *Server) SyncWithNetwork() error {
	rows, err := s.DB.Query(`SELECT address FROM known_servers WHERE is_active = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()
	servers := make([]string, 0)
	for rows.Next() {
		var address string
		if rows.Scan(&address) != nil {
			continue
		}
		if address == s.Address || address == s.BindAddress {
			continue
		}
		servers = append(servers, address)
	}
	var wg sync.WaitGroup
	for _, address := range servers {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			_ = s.SyncWithServer(addr)
		}(address)
	}
	wg.Wait()
	return nil
}

func (s *Server) TriggerNetworkSyncIfStale(minInterval time.Duration) bool {
	if s == nil {
		return false
	}
	if minInterval <= 0 {
		minInterval = 30 * time.Second
	}

	nowTs := time.Now()
	s.mu.Lock()
	if !s.lastNetworkSyncAt.IsZero() && nowTs.Sub(s.lastNetworkSyncAt) < minInterval {
		s.mu.Unlock()
		return false
	}
	s.lastNetworkSyncAt = nowTs
	s.mu.Unlock()

	go func() {
		_ = s.SyncWithNetwork()
		_, _ = s.SelectBackupServer()
	}()
	return true
}

func (s *Server) SelectBackupServer() (string, error) {
	var backup string
	err := s.DB.QueryRow(`SELECT address FROM server_nodes
		WHERE is_active = 1 AND address != ?
		ORDER BY reputation DESC, last_seen DESC LIMIT 1`, s.Address).Scan(&backup)
	if err != nil {
		return "", err
	}
	return backup, nil
}
