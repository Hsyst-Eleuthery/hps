package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"hpsserver/internal/core"
	"hpsserver/internal/socket"
)

func startAdminConsole(ctx context.Context, stop context.CancelFunc, srv *core.Server, sock *socket.Server) {
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("HPS Administration Console")
		fmt.Println("Type \"help\" for commands")
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			fmt.Print("(hps-admin) ")
			if !scanner.Scan() {
				return
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			args := strings.Fields(line)
			cmd := strings.ToLower(args[0])
			switch cmd {
			case "help":
				fmt.Println("Available commands:")
				fmt.Println("  contracts [hash|domain|user|type] [value] - Buscar contratos")
				fmt.Println("  verify_contract <id> - Verificar assinatura de contrato")
				fmt.Println("  online_users - Listar usuÃƒÂ¡rios online")
				fmt.Println("  ban_user <username> <duration_seconds> <reason> - Banir usuÃƒÂ¡rio online")
				fmt.Println("  reputation <username> [new_reputation] - Ver/alterar reputaÃƒÂ§ÃƒÂ£o")
				fmt.Println("  server_stats - EstatÃƒÂ­sticas do servidor")
				fmt.Println("  content_stats - EstatÃƒÂ­sticas de conteÃƒÂºdo por MIME")
				fmt.Println("  node_stats - EstatÃƒÂ­sticas dos nÃƒÂ³s online")
				fmt.Println("  list_reports - Listar denÃƒÂºncias pendentes")
				fmt.Println("  resolve_report <report_id> [ban|warn|ignore] - Resolver denÃƒÂºncia")
				fmt.Println("  sync_network - Iniciar sincronizaÃƒÂ§ÃƒÂ£o com a rede")
				fmt.Println("  generate_voucher <username> <value> - Gerar voucher admin")
				fmt.Println("  exit - Parar servidor")
				fmt.Println("  help - Mostrar ajuda")
			case "contracts":
				searchType := "all"
				searchValue := ""
				if len(args) > 1 {
					searchType = strings.ToLower(args[1])
				}
				if len(args) > 2 {
					searchValue = args[2]
				}
				query := `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, timestamp, verified FROM contracts ORDER BY timestamp DESC LIMIT 50`
				params := []any{}
				switch searchType {
				case "hash":
					query = `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, timestamp, verified FROM contracts WHERE content_hash LIKE ? ORDER BY timestamp DESC`
					params = append(params, "%"+searchValue+"%")
				case "domain":
					query = `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, timestamp, verified FROM contracts WHERE domain LIKE ? ORDER BY timestamp DESC`
					params = append(params, "%"+searchValue+"%")
				case "user":
					query = `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, timestamp, verified FROM contracts WHERE username LIKE ? ORDER BY timestamp DESC`
					params = append(params, "%"+searchValue+"%")
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
					fmt.Println("Nenhum contrato encontrado.")
				} else {
					fmt.Printf("Total: %d\n", count)
				}
			case "verify_contract":
				if len(args) < 2 {
					fmt.Println("Uso: verify_contract <contract_id>")
					continue
				}
				contractID := args[1]
				var username, signature string
				var contractContent []byte
				err := srv.DB.QueryRow(`SELECT username, signature, contract_content FROM contracts WHERE contract_id = ?`, contractID).
					Scan(&username, &signature, &contractContent)
				if err == sql.ErrNoRows {
					fmt.Println("Contrato nÃƒÂ£o encontrado.")
					continue
				}
				if err != nil {
					fmt.Printf("verify_contract error: %v\n", err)
					continue
				}
				valid, errMsg, info := core.ValidateContractStructure(contractContent)
				if !valid || info == nil {
					fmt.Printf("Contrato invÃƒÂ¡lido: %s\n", errMsg)
					continue
				}
				ok := srv.VerifyContractSignature(contractContent, info.User, info.Signature, "")
				_, _ = srv.DB.Exec(`UPDATE contracts SET verified = ? WHERE contract_id = ?`, boolToInt(ok), contractID)
				if ok {
					fmt.Println("Assinatura vÃƒÂ¡lida.")
				} else {
					fmt.Println("Assinatura invÃƒÂ¡lida.")
				}
			case "server_stats":
				var users, contents, dns, contracts, onlineNodes, pendingReports, knownServers int
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM content`).Scan(&contents)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM dns_records`).Scan(&dns)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM contracts`).Scan(&contracts)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM network_nodes WHERE is_online = 1`).Scan(&onlineNodes)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM content_reports WHERE resolved = 0`).Scan(&pendingReports)
				_ = srv.DB.QueryRow(`SELECT COUNT(*) FROM known_servers WHERE is_active = 1`).Scan(&knownServers)
				fmt.Printf("Total users: %d\n", users)
				fmt.Printf("Total content: %d\n", contents)
				fmt.Printf("Total DNS: %d\n", dns)
				fmt.Printf("Total contracts: %d\n", contracts)
				fmt.Printf("Online nodes: %d\n", onlineNodes)
				fmt.Printf("Connected clients: %d\n", srv.ConnectedClients)
				fmt.Printf("Known servers: %d\n", knownServers)
				fmt.Printf("Pending reports: %d\n", pendingReports)
			case "online_users":
				users := sock.ListOnlineUsers()
				fmt.Printf("Online users: %d\n", len(users))
				for _, u := range users {
					fmt.Printf("  %s | %s | %s | %s\n", u.Username, u.NodeType, u.Address, u.ClientIdentifier)
				}
			case "ban_user":
				if len(args) < 4 {
					fmt.Println("Uso: ban_user <username> <duration_seconds> <reason>")
					continue
				}
				duration, err := strconv.Atoi(args[2])
				if err != nil || duration <= 0 {
					fmt.Println("DuraÃƒÂ§ÃƒÂ£o invÃƒÂ¡lida.")
					continue
				}
				username := args[1]
				reason := strings.Join(args[3:], " ")
				if sock.BanUser(username, duration, reason) {
					fmt.Printf("User %s banned for %d seconds\n", username, duration)
				} else {
					fmt.Printf("User %s not found online\n", username)
				}
			case "reputation":
				if len(args) < 2 {
					fmt.Println("Uso: reputation <username> [new_reputation]")
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
					fmt.Println("Nova reputaÃƒÂ§ÃƒÂ£o invÃƒÂ¡lida.")
					continue
				}
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
					fmt.Println("Uso: resolve_report <report_id> [action: ban|warn|ignore]")
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
				switch action {
				case "ban":
					_, _ = srv.DB.Exec(`UPDATE user_reputations SET reputation = 1 WHERE username = ?`, reportedUser)
					_, _ = srv.DB.Exec(`UPDATE users SET reputation = 1 WHERE username = ?`, reportedUser)
					_, _ = srv.DB.Exec(`DELETE FROM content WHERE content_hash = ?`, contentHash)
					_ = os.Remove(srv.ContentPath(contentHash))
					fmt.Printf("User %s banned and content removed\n", reportedUser)
				case "warn":
					_, _ = srv.DB.Exec(`UPDATE user_reputations SET reputation = MAX(1, reputation - 20) WHERE username = ?`, reportedUser)
					_, _ = srv.DB.Exec(`UPDATE users SET reputation = MAX(1, reputation - 20) WHERE username = ?`, reportedUser)
					fmt.Printf("User %s warned (-20 reputation)\n", reportedUser)
				case "ignore":
					fmt.Println("Report marked as ignored.")
				default:
					fmt.Println("AÃƒÂ§ÃƒÂ£o invÃƒÂ¡lida. Use: ban, warn ou ignore.")
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
					fmt.Println("Uso: generate_voucher <username> <value>")
					continue
				}
				username := strings.TrimSpace(args[1])
				value, err := strconv.Atoi(args[2])
				if err != nil || value <= 0 {
					fmt.Println("Quantidade invÃƒÂ¡lida.")
					continue
				}
				ownerKey := srv.GetUserPublicKey(username)
				if ownerKey == "" {
					ownerKey = srv.GetRegisteredPublicKey(username)
				}
				if ownerKey == "" {
					fmt.Println("Usuario sem chave publica registrada.")
					continue
				}
				offer := srv.CreateVoucherOffer(
					username,
					ownerKey,
					value,
					"admin_test",
					nil,
					map[string]any{"type": "admin_test"},
					"",
				)
				sock.EmitPendingVoucherOffersForUser(username)
				fmt.Printf("Voucher gerado: %s (%d HPS)\n", fmt.Sprintf("%v", offer["voucher_id"]), value)
			case "exit":
				fmt.Println("Stopping server...")
				stop()
				return
			default:
				fmt.Printf("Comando desconhecido: %s\n", cmd)
			}
		}
	}()
}
