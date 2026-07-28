package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"hpsserver/internal/core"
	"hpsserver/internal/socket"
)

const adminSessionTimeout = 30 * time.Minute

func readPasswordHidden(prompt string) (string, error) {
	fmt.Print(prompt)
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(passBytes), nil
}

var (
	authenticatedUser      string
	authenticatedUserMu    sync.Mutex
	authenticatedUserSince time.Time
)

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func checkPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func generateSalt() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func startAdminConsole(ctx context.Context, stop context.CancelFunc, srv *core.Server, sock *socket.Server) {
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("HPS Administration Console")
		fmt.Println("Type \"help\" for commands")

		var userCount int
		_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM admin_users`).Scan(&userCount)
		if userCount == 0 {
			fmt.Println()
			fmt.Println("=== FIRST-TIME SETUP ===")
			fmt.Println("No admin users configured. Create the first admin account.")
			fmt.Print("Username: ")
			if !scanner.Scan() {
				return
			}
			firstUser := strings.TrimSpace(scanner.Text())
			if firstUser == "" {
				fmt.Println("Setup cancelled: username cannot be empty.")
				return
			}
			firstPass, passErr := readPasswordHidden("Password: ")
			if passErr != nil {
				fmt.Printf("Setup error: %v\n", passErr)
				return
			}
			if len(strings.TrimSpace(firstPass)) < 6 {
				fmt.Println("Setup cancelled: password must be at least 6 characters.")
				return
			}
			hashStr, err := hashPassword(firstPass)
			if err != nil {
				fmt.Printf("Setup error: %v\n", err)
				return
			}
			now := float64(time.Now().Unix())
			_, err = srv.DB.Exec(`INSERT INTO admin_users (username, password_hash, created_at, last_login, is_active) VALUES (?, ?, ?, ?, 1)`,
				firstUser, hashStr, now, now)
			if err != nil {
				fmt.Printf("Setup error: %v\n", err)
				return
			}
			authenticatedUserMu.Lock()
			authenticatedUser = firstUser
			authenticatedUserSince = time.Now()
			authenticatedUserMu.Unlock()
			fmt.Printf("Admin user '%s' created and logged in.\n", firstUser)
			_ = srv.RecordAdminAudit("root_setup", fmt.Sprintf("first admin %s created", firstUser), "console_admin", "localhost")
		}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			authenticatedUserMu.Lock()
			currentUser := authenticatedUser
			lastActivity := authenticatedUserSince
			authenticatedUserMu.Unlock()
			if currentUser != "" && time.Since(lastActivity) > adminSessionTimeout {
				fmt.Println("Session expired due to inactivity.")
				authenticatedUserMu.Lock()
				authenticatedUser = ""
				authenticatedUserSince = time.Time{}
				authenticatedUserMu.Unlock()
				continue
			}
			if currentUser == "" {
				fmt.Print("(hps-admin:login) ")
			} else {
				fmt.Printf("(hps-admin:%s) ", currentUser)
			}
			if !scanner.Scan() {
				return
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			args := strings.Fields(line)
			cmd := strings.ToLower(args[0])

			if cmd != "login" && cmd != "help" && cmd != "logout" && currentUser == "" {
				fmt.Println("Access denied. Type 'login' to authenticate.")
				continue
			}
			// Reset session timeout on any authenticated command
			if currentUser != "" {
				authenticatedUserMu.Lock()
				authenticatedUserSince = time.Now()
				authenticatedUserMu.Unlock()
			}

			recordAdminAction := func(action string, argsList []string) {
				argStr := strings.Join(argsList, " ")
				authenticatedUserMu.Lock()
				au := authenticatedUser
				authenticatedUserMu.Unlock()
				_ = srv.RecordAdminAudit(action, argStr, au, "console_admin")
			}

			switch cmd {
			case "login":
				authenticatedUserMu.Lock()
				alreadyAuth := authenticatedUser
				authenticatedUserMu.Unlock()
				if alreadyAuth != "" {
					fmt.Printf("Already authenticated as %s. Use 'logout' first.\n", alreadyAuth)
					continue
				}
				if len(args) < 2 {
					fmt.Print("Username: ")
					if !scanner.Scan() {
						return
					}
					args = append(args, strings.TrimSpace(scanner.Text()))
				}
				if len(args) < 3 {
					loginPass, passErr := readPasswordHidden("Password: ")
					if passErr != nil {
						fmt.Printf("Login error: %v\n", passErr)
						continue
					}
					args = append(args, loginPass)
				}
				loginUser := args[1]
				loginPass := args[2]
				var storedHash string
				var isActive int
				err := srv.DB.QueryRow(`SELECT password_hash, is_active FROM admin_users WHERE username = ?`, loginUser).
					Scan(&storedHash, &isActive)
				if err == sql.ErrNoRows || isActive == 0 {
					fmt.Println("Invalid username or password.")
					continue
				}
				if err != nil {
					fmt.Printf("Login error: %v\n", err)
					continue
				}
				if !checkPassword(loginPass, storedHash) {
					fmt.Println("Invalid username or password.")
					continue
				}
				authenticatedUserMu.Lock()
				authenticatedUser = loginUser
				authenticatedUserSince = time.Now()
				authenticatedUserMu.Unlock()
				now := float64(time.Now().Unix())
				_, _ = srv.DB.Exec(`UPDATE admin_users SET last_login = ? WHERE username = ?`, now, loginUser)
				_ = srv.RecordAdminAudit("login", "admin console login", loginUser, "console_admin")
				fmt.Printf("Authenticated as %s.\n", loginUser)
				continue

			case "logout":
				authenticatedUserMu.Lock()
				au := authenticatedUser
				authenticatedUserMu.Unlock()
				if au == "" {
					fmt.Println("Not logged in.")
					continue
				}
				_ = srv.RecordAdminAudit("logout", "admin console logout", au, "console_admin")
				fmt.Printf("Logged out %s.\n", au)
				authenticatedUserMu.Lock()
				authenticatedUser = ""
				authenticatedUserSince = time.Time{}
				authenticatedUserMu.Unlock()
				continue

			case "help":
				fmt.Println("Available commands:")
				fmt.Println("  login [username] [password] - Authenticate as admin")
				fmt.Println("  logout - End admin session")
				fmt.Println("  contracts [hash|domain|user|type] [value] - Search contracts")
				fmt.Println("  verify_contract <id> - Verify contract signature")
				fmt.Println("  online_users - List online users")
				fmt.Println("  ban_user <username> <duration_seconds> <reason> - Ban user")
				fmt.Println("  reputation <username> [new_reputation] - View/set reputation")
				fmt.Println("  server_stats - Server statistics")
				fmt.Println("  content_stats - Content statistics by MIME")
				fmt.Println("  node_stats - Online node statistics")
				fmt.Println("  list_reports - List pending reports")
				fmt.Println("  resolve_report <report_id> [ban|warn|ignore] - Resolve report")
				fmt.Println("  sync_network - Start network sync")
				fmt.Println("  generate_voucher <username> <value> - Generate admin voucher")
				fmt.Println("  config - Decrypt config for editing")
				fmt.Println("  config show - Display current config values")
				fmt.Println("  config apply - Apply config changes and restart")
				fmt.Println("  miner_rate <username> [min_fee max_fee] - View/set miner rate")
				fmt.Println("  exchange_titles - List active exchange titles")
				fmt.Println("  miner_block <username> [duration_sec] - Block miner")
				fmt.Println("  fee_market - Show fee market data")
				fmt.Println("  supply_chain <voucher_id> - Verify voucher in supply chain")
				fmt.Println("  content_receipt <content_hash> - Verify content receipt")
				fmt.Println("  exit - Stop server")
				fmt.Println("  help - Show help")

			case "contracts":
				searchType := "all"
				searchValue := ""
				if len(args) > 1 {
					searchType = strings.ToLower(args[1])
				}
				if len(args) > 2 {
					searchValue = args[2]
				}
				escapedValue := strings.ReplaceAll(searchValue, "%", "\\%")
				escapedValue = strings.ReplaceAll(escapedValue, "_", "\\_")
				query := `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, timestamp, verified FROM contracts ORDER BY timestamp DESC LIMIT 50`
				params := []any{}
				switch searchType {
				case "hash":
					query = `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, timestamp, verified FROM contracts WHERE content_hash LIKE ? ESCAPE '\' ORDER BY timestamp DESC`
					params = append(params, "%"+escapedValue+"%")
				case "domain":
					query = `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, timestamp, verified FROM contracts WHERE domain LIKE ? ESCAPE '\' ORDER BY timestamp DESC`
					params = append(params, "%"+escapedValue+"%")
				case "user":
					query = `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, timestamp, verified FROM contracts WHERE username LIKE ? ESCAPE '\' ORDER BY timestamp DESC`
					params = append(params, "%"+escapedValue+"%")
				case "type":
					query = `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, timestamp, verified FROM contracts WHERE action_type = ? ORDER BY timestamp DESC`
					params = append(params, searchValue)
				}
				rows, err := srv.DB.Query(query, params...)
				if err != nil {
					fmt.Printf("contracts error: %v\n", err)
					continue
				}
				defer rows.Close()
				count := 0
				for rows.Next() {
					var id, actionType, contentHash, domain, username string
					var ts float64
					var verified int
					if rows.Scan(&id, &actionType, &contentHash, &domain, &username, &ts, &verified) != nil {
						continue
					}
					fmt.Printf("- %s | %s | user=%s | hash=%s | domain=%s | verified=%t | ts=%.0f\n",
						id, actionType, username, contentHash, domain, verified == 1, ts)
					count++
				}
				if count == 0 {
					fmt.Println("No contracts found.")
				} else {
					fmt.Printf("Total: %d\n", count)
				}
			case "verify_contract":
				if len(args) < 2 {
					fmt.Println("Usage: verify_contract <contract_id>")
					continue
				}
				contractID := args[1]
				var username, signature string
				var contractContent []byte
				err := srv.DB.QueryRow(`SELECT username, signature, contract_content FROM contracts WHERE contract_id = ?`, contractID).
					Scan(&username, &signature, &contractContent)
				if err == sql.ErrNoRows {
					fmt.Println("Contract not found.")
					continue
				}
				if err != nil {
					fmt.Printf("verify_contract error: %v\n", err)
					continue
				}
				valid, errMsg, info := core.ValidateContractStructure(contractContent)
				if !valid || info == nil {
					fmt.Printf("Invalid contract: %s\n", errMsg)
					continue
				}
				ok := srv.VerifyContractSignature(contractContent, info.User, info.Signature, "")
				_, _ = srv.DB.Exec(`UPDATE contracts SET verified = ? WHERE contract_id = ?`, boolToInt(ok), contractID)
				if ok {
					fmt.Println("Valid signature.")
				} else {
					fmt.Println("Invalid signature.")
				}
			case "server_stats":
				var users, contents, dns, contracts, onlineNodes, pendingReports, knownServers, admins int
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM content`).Scan(&contents)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM dns_records`).Scan(&dns)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM contracts`).Scan(&contracts)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM network_nodes WHERE is_online = 1`).Scan(&onlineNodes)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM content_reports WHERE resolved = 0`).Scan(&pendingReports)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM known_servers WHERE is_active = 1`).Scan(&knownServers)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM admin_users WHERE is_active = 1`).Scan(&admins)
				fmt.Printf("Total users: %d\n", users)
				fmt.Printf("Total content: %d\n", contents)
				fmt.Printf("Total DNS: %d\n", dns)
				fmt.Printf("Total contracts: %d\n", contracts)
				fmt.Printf("Online nodes: %d\n", onlineNodes)
				fmt.Printf("Connected clients: %d\n", srv.ConnectedClients)
				fmt.Printf("Known servers: %d\n", knownServers)
				fmt.Printf("Active admins: %d\n", admins)
				fmt.Printf("Pending reports: %d\n", pendingReports)
			case "online_users":
				users := sock.ListOnlineUsers()
				fmt.Printf("Online users: %d\n", len(users))
				for _, u := range users {
					fmt.Printf("  %s | %s | %s | %s\n", u.Username, u.NodeType, u.Address, u.ClientIdentifier)
				}
			case "ban_user":
				if len(args) < 4 {
					fmt.Println("Usage: ban_user <username> <duration_seconds> <reason>")
					continue
				}
				duration, err := strconv.Atoi(args[2])
				if err != nil || duration <= 0 {
					fmt.Println("Invalid duration.")
					continue
				}
				username := args[1]
				reason := strings.Join(args[3:], " ")
				recordAdminAction("ban_user", args[1:])
				if sock.BanUser(username, duration, reason) {
					fmt.Printf("User %s banned for %d seconds\n", username, duration)
				} else {
					fmt.Printf("User %s not found online\n", username)
				}
			case "reputation":
				if len(args) < 2 {
					fmt.Println("Usage: reputation <username> [new_reputation]")
					continue
				}
				username := args[1]
				var current int
				err := srv.DB.QueryRow(`SELECT reputation FROM user_reputations WHERE username = ?`, username).Scan(&current)
				if err == sql.ErrNoRows {
					fmt.Printf("User %s not found\n", username)
					continue
				}
				if err != nil {
					fmt.Printf("reputation error: %v\n", err)
					continue
				}
				if len(args) == 2 {
					fmt.Printf("Reputation of %s: %d\n", username, current)
					continue
				}
				newRep, convErr := strconv.Atoi(args[2])
				if convErr != nil {
					fmt.Println("Invalid reputation value.")
					continue
				}
				recordAdminAction("reputation", args[1:])
				_, _ = srv.DB.Exec(`UPDATE user_reputations SET reputation = ?, last_updated = ? WHERE username = ?`, newRep, float64(time.Now().Unix()), username)
				_, _ = srv.DB.Exec(`UPDATE users SET reputation = ? WHERE username = ?`, newRep, username)
				sock.EmitReputationUpdate(username, newRep)
				fmt.Printf("Reputation of %s changed to %d\n", username, newRep)
			case "content_stats":
				rows, err := srv.DB.Query(`SELECT mime_type, COUNT(*) as count, COALESCE(SUM(size),0) as total_size
					FROM content
					GROUP BY mime_type
					ORDER BY count DESC`)
				if err != nil {
					fmt.Printf("content_stats error: %v\n", err)
					continue
				}
				defer rows.Close()
				fmt.Println("Content statistics by MIME type:")
				for rows.Next() {
					var mimeType string
					var count int
					var totalSize int64
					if rows.Scan(&mimeType, &count, &totalSize) != nil {
						continue
					}
					fmt.Printf("  %s: %d files, %dMB\n", mimeType, count, totalSize/(1024*1024))
				}
			case "node_stats":
				rows, err := srv.DB.Query(`SELECT node_type, COUNT(*) as count, COALESCE(AVG(reputation), 0)
					FROM network_nodes
					WHERE is_online = 1
					GROUP BY node_type`)
				if err != nil {
					fmt.Printf("node_stats error: %v\n", err)
					continue
				}
				defer rows.Close()
				fmt.Println("Node statistics:")
				for rows.Next() {
					var nodeType string
					var count int
					var avgRep float64
					if rows.Scan(&nodeType, &count, &avgRep) != nil {
						continue
					}
					fmt.Printf("  %s: %d nodes, average reputation: %.1f\n", nodeType, count, avgRep)
				}
			case "list_reports":
				rows, err := srv.DB.Query(`SELECT report_id, content_hash, reported_user, reporter, timestamp
					FROM content_reports
					WHERE resolved = 0
					ORDER BY timestamp DESC`)
				if err != nil {
					fmt.Printf("list_reports error: %v\n", err)
					continue
				}
				defer rows.Close()
				count := 0
				for rows.Next() {
					var reportID, contentHash, reportedUser, reporter string
					var ts float64
					if rows.Scan(&reportID, &contentHash, &reportedUser, &reporter, &ts) != nil {
						continue
					}
					fmt.Printf("Report ID: %s\n", reportID)
					fmt.Printf("  Content Hash: %s\n", contentHash)
					fmt.Printf("  Reported User: %s\n", reportedUser)
					fmt.Printf("  Reporter: %s\n", reporter)
					fmt.Printf("  Timestamp: %s\n", time.Unix(int64(ts), 0).Format("2006-01-02 15:04:05"))
					count++
				}
				if count == 0 {
					fmt.Println("No pending reports.")
				}
			case "resolve_report":
				if len(args) < 2 {
					fmt.Println("Usage: resolve_report <report_id> [action: ban|warn|ignore]")
					continue
				}
				reportID := args[1]
				action := "warn"
				if len(args) >= 3 {
					action = strings.ToLower(args[2])
				}
				var contentHash, reportedUser, reporter string
				err := srv.DB.QueryRow(`SELECT content_hash, reported_user, reporter
					FROM content_reports
					WHERE report_id = ? AND resolved = 0`, reportID).Scan(&contentHash, &reportedUser, &reporter)
				if err == sql.ErrNoRows {
					fmt.Printf("Report %s not found or already resolved\n", reportID)
					continue
				}
				if err != nil {
					fmt.Printf("resolve_report error: %v\n", err)
					continue
				}
				recordAdminAction("resolve_report", args[1:])
				switch action {
				case "ban":
					_, _ = srv.DB.Exec(`UPDATE user_reputations SET reputation = 1 WHERE username = ?`, reportedUser)
					_, _ = srv.DB.Exec(`UPDATE users SET reputation = 1 WHERE username = ?`, reportedUser)
					_, _ = srv.DB.Exec(`DELETE FROM content WHERE content_hash = ?`, contentHash)
					if delErr := core.SecureDeleteFile(srv.ContentPath(contentHash)); delErr != nil {
						fmt.Printf("Warning: failed to securely delete content: %v\n", delErr)
					}
					fmt.Printf("User %s banned and content removed\n", reportedUser)
				case "warn":
					_, _ = srv.DB.Exec(`UPDATE user_reputations SET reputation = MAX(1, reputation - 20) WHERE username = ?`, reportedUser)
					_, _ = srv.DB.Exec(`UPDATE users SET reputation = MAX(1, reputation - 20) WHERE username = ?`, reportedUser)
					fmt.Printf("User %s warned (-20 reputation)\n", reportedUser)
				case "ignore":
					fmt.Println("Report marked as ignored.")
				default:
					fmt.Println("Invalid action. Use: ban, warn, or ignore.")
					continue
				}
				_, _ = srv.DB.Exec(`UPDATE content_reports SET resolved = 1, resolution_type = ? WHERE report_id = ?`, action, reportID)
				var rep int
				if srv.DB.QueryRow(`SELECT reputation FROM user_reputations WHERE username = ?`, reportedUser).Scan(&rep) == nil {
					sock.EmitReputationUpdate(reportedUser, rep)
				}
				fmt.Printf("Report %s resolved\n", reportID)
			case "sync_network":
				fmt.Println("Starting network synchronization...")
				go func() {
					if err := srv.SyncWithNetwork(); err != nil {
						fmt.Printf("sync_network error: %v\n", err)
					}
				}()
				fmt.Println("Synchronization started")
			case "generate_voucher":
				if len(args) < 3 {
					fmt.Println("Usage: generate_voucher <username> <value>")
					continue
				}
				username := strings.TrimSpace(args[1])
				value, err := strconv.Atoi(args[2])
				if err != nil || value <= 0 {
					fmt.Println("Invalid amount.")
					continue
				}
				ownerKey := srv.GetUserPublicKey(username)
				if ownerKey == "" {
					ownerKey = srv.GetRegisteredPublicKey(username)
				}
				if ownerKey == "" {
					fmt.Println("User has no registered public key.")
					continue
				}
				recordAdminAction("generate_voucher", args[1:])
				offer := srv.CreateVoucherOfferWithStatus(
					username,
					ownerKey,
					value,
					"admin_test",
					nil,
					map[string]any{"type": "admin_test"},
					"",
					"issued",
				)
				voucherID := fmt.Sprintf("%v", offer["voucher_id"])
				nowTs := float64(time.Now().UnixNano()) / 1e9
				contractID := srv.SaveServerContract("admin_generated_voucher", []core.ContractDetail{
					{Key: "VOUCHER_ID", Value: voucherID},
					{Key: "OWNER", Value: username},
					{Key: "ISSUER", Value: srv.Address},
					{Key: "VALUE", Value: value},
					{Key: "REASON", Value: "admin_test"},
				}, voucherID)
				srv.RecordVoucherSupplyChain(voucherID, value, username, nowTs, contractID)
				srv.DB.Exec(`INSERT OR REPLACE INTO hps_vouchers
					(voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature,
					 owner_signature, status, lineage_origin, invalidated, last_updated)
					SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 'valid', 'admin_test', 0, ?
					FROM hps_voucher_offers WHERE offer_id = ?`,
					voucherID, srv.Address, username, value, "admin_test",
					nowTs, offer["payload_canonical"], "", "", nowTs, offer["offer_id"])
				sock.EmitPendingVoucherOffersForUser(username)
				fmt.Printf("Voucher generated: %s (%d HPS) - tracked in supply chain\n", voucherID, value)
			case "config":
				if len(args) > 1 {
					sub := strings.ToLower(args[1])
					switch sub {
					case "apply":
						if err := srv.ApplyEncryptedConfigAndRestart(); err != nil {
							fmt.Printf("config apply error: %v\n", err)
						} else {
							fmt.Println("Config applied, server will restart...")
						}
					case "show":
						cfg := srv.ConfigData
						if cfg == nil {
							fmt.Println("No config loaded. Use 'config' to generate a template.")
						} else {
							fmt.Println("Current server config:")
							fmt.Printf("  Server name:      %s\n", cfg.ServerName)
							fmt.Printf("  Owner:            %s\n", cfg.OwnerName)
							fmt.Printf("  Custody account:  %s\n", cfg.CustodyName)
							fmt.Printf("  Max TX time:      %.0f seconds\n", cfg.MaxTxTimeSeconds)
							fmt.Printf("  Min TX time:      %.0f seconds\n", cfg.MinTxTimeSeconds)
							fmt.Printf("  Default miner fee: %d\n", cfg.DefaultMinerFee)
							fmt.Printf("  Volatile fees:    %t\n", cfg.VolatileFees)
							fmt.Printf("  Config version:   %d\n", cfg.ConfigVersion)
							fmt.Printf("  Config file:      %s\n", srv.ConfigFilePath())
							fmt.Printf("  Encrypted file:   %s\n", srv.ConfigEncryptedPath())
						}
					default:
						fmt.Printf("Unknown config subcommand: %s\n", sub)
					}
				} else {
					tmpPath, err := srv.DecryptConfigToTemp()
					if err != nil {
						fmt.Printf("config error: %v\n", err)
					} else {
						fmt.Printf("Config decrypted to: %s\n", tmpPath)
						fmt.Println("Edit the file, then type 'config apply' to encrypt and restart")
					}
				}
			case "miner_rate":
				if len(args) < 2 {
					fmt.Println("Usage: miner_rate <username> [min_fee max_fee]")
					continue
				}
				username := args[1]
				if len(args) >= 4 {
					minFee, _ := strconv.Atoi(args[2])
					maxFee, _ := strconv.Atoi(args[3])
					volatile := 1
					if len(args) >= 5 {
						volatile, _ = strconv.Atoi(args[4])
					}
					srv.UpsertMinerRateConfig(username, minFee, maxFee, volatile, -1, 3, 86400, 60)
					fmt.Printf("Miner rate config updated for %s: min=%d max=%d volatile=%d\n", username, minFee, maxFee, volatile)
				} else {
					cfg := srv.GetMinerRateConfig(username)
					fmt.Printf("Miner rate config for %s:\n", username)
					fmt.Printf("  Min fee: %v\n", cfg["min_fee_per_tx"])
					fmt.Printf("  Max fee: %v\n", cfg["max_fee_per_tx"])
					fmt.Printf("  Volatile: %v\n", cfg["fee_volatility_enabled"])
					fmt.Printf("  Max TX time: %v\n", cfg["max_tx_time_seconds"])
					pending := srv.GetMinerPendingSig(username)
					fmt.Printf("  Pending: %v | Negative balance: %v\n",
						pending["pending_count"],
						pending["negative_balance"])
				}
			case "exchange_titles":
				titles := srv.ListActiveExchangeTitles()
				if len(titles) == 0 {
					fmt.Println("No active exchange titles.")
				} else {
					for _, t := range titles {
						fmt.Printf("  %v | source=%v | value=%v | burned=%v | status=%v | holder=%v\n",
							t["title_id"], t["source_server"],
							t["value"], t["burned_value"],
							t["status"], t["holder_username"])
					}
				}
			case "miner_block":
				if len(args) < 2 {
					fmt.Println("Usage: miner_block <username> [duration_sec]")
					continue
				}
				username := args[1]
				duration := 60.0
				if len(args) >= 3 {
					d, _ := strconv.ParseFloat(args[2], 64)
					if d > 0 {
						duration = d
					}
				}
				recordAdminAction("miner_block", args[1:])
				srv.SetMinerBlocked(username, duration)
				fmt.Printf("Miner %s blocked for %.0f seconds\n", username, duration)
			case "fee_market":
				data := srv.GetFeeMarketData()
				fmt.Printf("Fee Market Data:\n")
				fmt.Printf("  Pending transfers: %v\n", data["pending_transfers"])
				fmt.Printf("  Available miners: %v\n", data["available_miners"])
				fmt.Printf("  Average fee: %v\n", data["average_fee"])
				fmt.Printf("  Demand/Supply ratio: %.2f\n", data["demand_supply_ratio"])
				fmt.Printf("  Base multiplier: %.2f\n", data["base_multiplier"])
			case "supply_chain":
				if len(args) < 2 {
					fmt.Println("Usage: supply_chain <voucher_id>")
					continue
				}
				vid := args[1]
				if srv.VerifyVoucherSupplyChain(vid) {
					fmt.Printf("Voucher %s FOUND in supply chain\n", vid)
				} else {
					fmt.Printf("Voucher %s NOT found in supply chain\n", vid)
				}
				var chainHash string
				_ = srv.DB.QueryRow(`SELECT chain_hash FROM voucher_supply_chain WHERE voucher_id = ?`, vid).Scan(&chainHash)
				if chainHash != "" {
					fmt.Printf("  Chain hash: %s\n", chainHash)
				}
				fmt.Printf("  Supply chain tip: %s\n", srv.GetSupplyChainTip())
			case "content_receipt":
				if len(args) < 2 {
					fmt.Println("Usage: content_receipt <content_hash>")
					continue
				}
				ch := args[1]
				found, contractID := srv.VerifyContentReceipt(ch)
				if found {
					fmt.Printf("Content %s FOUND in receipt chain (contract: %s)\n", ch, contractID)
				} else {
					fmt.Printf("Content %s NOT found in receipt chain\n", ch)
				}
			case "exit":
				fmt.Println("Stopping server...")
				stop()
				return
			default:
				fmt.Printf("Unknown command: %s\n", cmd)
			}
		}
	}()
}
