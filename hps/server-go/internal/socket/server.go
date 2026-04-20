package socket

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hpsserver/internal/core"
	socketio "hpsserver/internal/socketio"
)

const (
	maxContentPerUser          = 1000
	maxDNSPerUser              = 100
	maxUploadContentBytes      = 150 * 1024 * 1024
	maxUploadContractOverhead  = 4 * 1024 * 1024
	maxUploadBase64PayloadSize = 220 * 1024 * 1024
	maxDdnsBase64PayloadSize   = 8 * 1024 * 1024
	maxChallengeAgeSec         = 60.0
	maxTitleLength             = 256
	maxDescriptionLength       = 4096
	maxMimeTypeLength          = 128
	selectorFlowBuildTag       = "selector-flow-2026-03-11-fallback-delivery-v6"
)

type ClientState struct {
	Authenticated       bool
	ServerAuthenticated bool
	Username            string
	NodeType            string
	Address             string
	NodeID              string
	ClientIdentifier    string
	PublicKey           string
	ConnectTime         float64
}

type inventoryRequestInfo struct {
	Requester    string
	RequesterSID string
	TargetUser   string
}

type inventoryDelivery struct {
	Requester    string
	RequesterSID string
	TransferID   string
	Owner        string
}

type Server struct {
	io                         *socketio.Server
	server                     *core.Server
	mu                         sync.Mutex
	clients                    map[string]*ClientState
	conns                      map[string]socketio.Conn
	challenges                 map[string]map[string]any
	exchangeQuotes             map[string]map[string]any
	liveSessionQuotes          map[string]map[string]any
	liveSessions               map[string]map[string]any
	pendingInventoryRequests   map[string]inventoryRequestInfo
	pendingInventoryDeliveries map[string][]inventoryDelivery
	actionQueueMu              sync.Mutex
	actionQueues               map[string][]*actionQueueTicket
	actionQueueSeq             uint64
	signatureWorkerMu          sync.Mutex
	signatureWorkers           map[string]bool
}

func NewServer(coreServer *core.Server) (*Server, error) {
	io := socketio.NewServer(nil)

	s := &Server{
		io:                         io,
		server:                     coreServer,
		clients:                    map[string]*ClientState{},
		conns:                      map[string]socketio.Conn{},
		challenges:                 map[string]map[string]any{},
		exchangeQuotes:             map[string]map[string]any{},
		liveSessionQuotes:          map[string]map[string]any{},
		liveSessions:               map[string]map[string]any{},
		pendingInventoryRequests:   map[string]inventoryRequestInfo{},
		pendingInventoryDeliveries: map[string][]inventoryDelivery{},
		actionQueues:               map[string][]*actionQueueTicket{},
		signatureWorkers:           map[string]bool{},
	}
	coreServer.UserEventEmitter = s.emitToUser
	s.registerHandlers()
	log.Printf("socket server build tag: %s", selectorFlowBuildTag)
	go s.backgroundAssignUnassignedTransfers()
	go s.backgroundAssignIssuerVerificationJobs()
	go s.backgroundRequestClientSync()
	go s.backgroundBroadcastBackupServer()
	go s.backgroundProcessPendingSignatureActions()
	go s.backgroundExpirePendingExchangeOffers()

	return s, nil
}

func (s *Server) registerHandlers() {
	s.io.OnConnect("/", func(conn socketio.Conn) error {
		log.Printf("client connected: %s", conn.ID())
		s.mu.Lock()
		s.clients[conn.ID()] = &ClientState{ConnectTime: nowSec()}
		s.conns[conn.ID()] = conn
		s.mu.Unlock()
		atomic.AddInt64(&s.server.ConnectedClients, 1)
		conn.Emit("status", map[string]any{"message": "Connected to HPS network"})
		conn.Emit("request_server_auth_challenge", map[string]any{})
		return nil
	})

	s.io.OnDisconnect("/", func(conn socketio.Conn, reason string) {
		log.Printf("client disconnected: %s (%s)", conn.ID(), reason)
		var clientState *ClientState
		s.dropQueuedActionsBySid(conn.ID())
		s.mu.Lock()
		clientState = s.clients[conn.ID()]
		delete(s.clients, conn.ID())
		delete(s.conns, conn.ID())
		s.mu.Unlock()
		if clientState != nil && clientState.Authenticated {
			nodeID := trim(clientState.NodeID)
			clientIdentifier := trim(clientState.ClientIdentifier)
			if nodeID != "" {
				_, _ = s.server.DB.Exec(`UPDATE network_nodes SET is_online = 0, last_seen = ? WHERE node_id = ?`, nowSec(), nodeID)
			} else if clientIdentifier != "" {
				_, _ = s.server.DB.Exec(`UPDATE network_nodes SET is_online = 0, last_seen = ? WHERE client_identifier = ?`, nowSec(), clientIdentifier)
			}
			s.broadcastNetworkState()
		}
		for {
			current := atomic.LoadInt64(&s.server.ConnectedClients)
			if current <= 0 {
				break
			}
			if atomic.CompareAndSwapInt64(&s.server.ConnectedClients, current, current-1) {
				break
			}
		}
	})

	s.io.OnEvent("/", "request_server_auth_challenge", s.handleRequestServerAuthChallenge)
	s.io.OnEvent("/", "verify_server_auth_response", s.handleVerifyServerAuthResponse)
	s.io.OnEvent("/", "request_pow_challenge", s.handleRequestPowChallenge)
	s.io.OnEvent("/", "authenticate", s.handleAuthenticateQueued)
	s.io.OnEvent("/", "request_hps_wallet", s.handleRequestHpsWallet)
	s.io.OnEvent("/", "request_economy_report", s.handleRequestEconomyReport)
	s.io.OnEvent("/", "request_price_settings", s.handleRequestPriceSettings)
	s.io.OnEvent("/", "update_price_settings", s.handleUpdatePriceSettings)
	s.io.OnEvent("/", "get_network_state", s.handleGetNetworkState)
	s.io.OnEvent("/", "get_network_nodes", s.handleGetNetworkNodes)
	s.io.OnEvent("/", "get_servers", s.handleGetServers)
	s.io.OnEvent("/", "resolve_dns", s.handleResolveDNS)
	s.io.OnEvent("/", "search_content", s.handleSearchContent)
	s.io.OnEvent("/", "publish_content", s.handlePublishContentQueued)
	s.io.OnEvent("/", "request_content", s.handleRequestContent)
	s.io.OnEvent("/", "register_dns", s.handleRegisterDNSQueued)
	s.io.OnEvent("/", "transfer_hps", s.handleTransferHPSQueued)
	s.io.OnEvent("/", "mint_hps_voucher", s.handleMintHpsVoucher)
	s.io.OnEvent("/", "confirm_hps_voucher", s.handleConfirmHpsVoucher)
	s.io.OnEvent("/", "request_usage_contract", s.handleRequestUsageContract)
	s.io.OnEvent("/", "accept_usage_contract", s.handleAcceptUsageContractQueued)
	s.io.OnEvent("/", "join_network", s.handleJoinNetwork)
	s.io.OnEvent("/", "report_content", s.handleReportContent)
	s.io.OnEvent("/", "sync_servers", s.handleSyncServers)
	s.io.OnEvent("/", "request_inventory", s.handleRequestInventory)
	s.io.OnEvent("/", "inventory_response", s.handleInventoryResponse)
	s.io.OnEvent("/", "request_inventory_transfer", s.handleRequestInventoryTransfer)
	s.io.OnEvent("/", "accept_inventory_transfer", s.handleAcceptInventoryTransfer)
	s.io.OnEvent("/", "reject_inventory_transfer", s.handleRejectInventoryTransfer)
	s.io.OnEvent("/", "user_activity", s.handleUserActivity)
	s.io.OnEvent("/", "server_ping", s.handleServerPing)
	s.io.OnEvent("/", "get_backup_server", s.handleGetBackupServer)
	s.io.OnEvent("/", "request_voucher_audit", s.handleRequestVoucherAudit)
	s.io.OnEvent("/", "search_contracts", s.handleSearchContracts)
	s.io.OnEvent("/", "get_contract", s.handleGetContract)
	s.io.OnEvent("/", "get_pending_transfers", s.handleGetPendingTransfers)
	s.io.OnEvent("/", "get_miner_transfer", s.handleGetMinerTransfer)
	s.io.OnEvent("/", "get_miner_pending_transfers", s.handleGetMinerPendingTransfers)
	s.io.OnEvent("/", "get_transfer_payload", s.handleGetTransferPayload)
	s.io.OnEvent("/", "sign_transfer", s.handleSignTransfer)
	s.io.OnEvent("/", "request_exchange_trace", s.handleRequestExchangeTrace)
	s.io.OnEvent("/", "invalidate_vouchers", s.handleInvalidateVouchers)
	s.io.OnEvent("/", "submit_fraud_report", s.handleSubmitFraudReport)
	s.io.OnEvent("/", "request_miner_fine", s.handleRequestMinerFine)
	s.io.OnEvent("/", "pay_miner_fine", s.handlePayMinerFine)
	s.io.OnEvent("/", "request_exchange_quote", s.handleRequestExchangeQuote)
	s.io.OnEvent("/", "confirm_exchange", s.handleConfirmExchange)
	s.io.OnEvent("/", "request_live_session_quote", s.handleRequestLiveSessionQuote)
	s.io.OnEvent("/", "pay_live_session", s.handlePayLiveSession)
	s.io.OnEvent("/", "sync_client_files", s.handleSyncClientFiles)
	s.io.OnEvent("/", "sync_client_dns_files", s.handleSyncClientDNSFiles)
	s.io.OnEvent("/", "sync_client_contracts", s.handleSyncClientContracts)
	s.io.OnEvent("/", "request_client_files", s.handleRequestClientFiles)
	s.io.OnEvent("/", "request_client_dns_files", s.handleRequestClientDNSFiles)
	s.io.OnEvent("/", "request_client_contracts", s.handleRequestClientContracts)
	s.io.OnEvent("/", "request_content_from_client", s.handleRequestContentFromClient)
	s.io.OnEvent("/", "request_ddns_from_client", s.handleRequestDDNSFromClient)
	s.io.OnEvent("/", "request_contract_from_client", s.handleRequestContractFromClient)
	s.io.OnEvent("/", "content_from_client", s.handleContentFromClient)
	s.io.OnEvent("/", "content_from_client_failure", s.handleContentFromClientFailure)
	s.io.OnEvent("/", "ddns_from_client", s.handleDDNSFromClient)
	s.io.OnEvent("/", "contract_from_client", s.handleContractFromClient)
	s.io.OnEvent("/", "get_api_app_versions", s.handleGetApiAppVersions)
	s.io.OnEvent("/", "contract_violation", s.handleContractViolation)
	s.io.OnEvent("/", "accept_hps_transfer", s.handleAcceptHpsTransfer)
	s.io.OnEvent("/", "get_contract_canonical", s.handleGetContractCanonical)
	s.io.OnEvent("/", "reject_transfer", s.handleRejectTransfer)
	s.io.OnEvent("/", "renounce_transfer", s.handleRenounceTransfer)
	s.io.OnEvent("/", "invalidate_contract", s.handleInvalidateContract)
	s.io.OnEvent("/", "certify_contract", s.handleCertifyContract)
	s.io.OnEvent("/", "get_contract_canonical_by_target", s.handleGetContractCanonicalByTarget)
	s.io.OnEvent("/", "certify_missing_contract", s.handleCertifyMissingContract)
	s.io.OnEvent("/", "miner_selector_response", s.handleMinerSelectorResponse)
	s.io.OnEvent("/", "miner_selector_reveal_response", s.handleMinerSelectorRevealResponse)
	s.io.OnEvent("/", "get_content_repair_payload", s.handleGetContentRepairPayload)
	s.io.OnEvent("/", "content_integrity_report", s.handleContentIntegrityReport)
	s.io.OnEvent("/", "request_issuer_recheck", s.handleRequestIssuerRecheck)
	s.io.OnEvent("/", "get_phps_market", s.handleGetPhpsMarket)
	s.io.OnEvent("/", "fund_phps_debt", s.handleFundPhpsDebt)
	s.io.OnEvent("/", "submit_issuer_verification_report", s.handleSubmitIssuerVerificationReport)
}

func (s *Server) backgroundAssignUnassignedTransfers() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.assignUnassignedTransfers()
	}
}

func (s *Server) backgroundAssignIssuerVerificationJobs() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.assignPendingIssuerVerificationJobs()
	}
}

func (s *Server) backgroundRequestClientSync() {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.requestClientSyncSnapshots()
		s.requestMissingDataFromClients()
	}
}

func (s *Server) backgroundBroadcastBackupServer() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		backup, err := s.server.SelectBackupServer()
		if err != nil || trim(backup) == "" {
			continue
		}
		s.broadcastToAuthenticated("backup_server", map[string]any{
			"server":    backup,
			"timestamp": nowSec(),
		})
	}
}

func (s *Server) backgroundExpirePendingExchangeOffers() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.server.ReleaseExpiredExchangeTokens(nowSec())
		s.expirePendingExchangeOffers()
		s.expireWithheldExchangeOffers()
	}
}

func (s *Server) expirePendingExchangeOffers() {
	rows, err := s.server.DB.Query(`SELECT offer_id, voucher_id
		FROM hps_voucher_offers
		WHERE status = ? AND expires_at > 0 AND expires_at < ? AND reason LIKE ?`,
		"pending", nowSec(), "exchange_from:%")
	if err != nil {
		return
	}
	type expiredExchangeOffer struct {
		offerID   string
		voucherID string
	}
	var offers []expiredExchangeOffer
	for rows.Next() {
		var offerID, voucherID string
		if rows.Scan(&offerID, &voucherID) != nil {
			continue
		}
		if offerID == "" || voucherID == "" {
			continue
		}
		offers = append(offers, expiredExchangeOffer{offerID: offerID, voucherID: voucherID})
	}
	rows.Close()

	for _, offer := range offers {
		var issuedCount int
		_ = s.server.DB.QueryRow(`SELECT COUNT(1) FROM hps_vouchers WHERE voucher_id = ?`, offer.voucherID).Scan(&issuedCount)
		if issuedCount > 0 {
			_, _ = s.server.DB.Exec(`UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ? AND status = ?`, "issued", offer.offerID, "pending")
			continue
		}

		_, _ = s.server.DB.Exec(`UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ? AND status = ?`, "expired", offer.offerID, "pending")

		transfer, ok := s.getTransferByExchangeOfferVoucherID(offer.voucherID)
		if !ok || transfer == nil {
			continue
		}
		if !strings.EqualFold(asString(transfer["transfer_type"]), "exchange_in") {
			continue
		}
		transferID := asString(transfer["transfer_id"])
		status := strings.ToLower(strings.TrimSpace(asString(transfer["status"])))
		if status != "completed" && status != "signed" && status != "pending_signature" && status != "signature_submitted" {
			continue
		}

		_, _ = s.server.DB.Exec(`UPDATE monetary_transfers SET status = ?, miner_deadline = NULL WHERE transfer_id = ?`, "expired", transferID)
		s.rollbackExchangeTransfer(transfer, "exchange_offer_expired")
		s.notifyMonetaryTransferUpdate(transferID, "expired", "exchange_offer_expired", map[string]any{
			"reason":      "exchange_offer_expired",
			"transfer_id": transferID,
			"voucher_id":  offer.voucherID,
			"offer_id":    offer.offerID,
		})
		payload := map[string]any{
			"success":     false,
			"stage":       "failed",
			"transfer_id": transferID,
			"error":       "O voucher final do cÃ¢mbio expirou antes da confirmaÃ§Ã£o. O valor original foi devolvido.",
		}
		s.emitToUser(asString(transfer["receiver"]), "exchange_complete", payload)
		s.relayExchangeEventToIssuer(transfer, "exchange_complete", payload)
	}
}

func (s *Server) expireWithheldExchangeOffers() {
	rows, err := s.server.DB.Query(`SELECT offer_id, voucher_id
		FROM hps_voucher_offers
		WHERE status = ? AND expires_at > 0 AND expires_at < ? AND reason LIKE ?`,
		"withheld", nowSec(), "exchange_from:%")
	if err != nil {
		return
	}
	type expiredExchangeOffer struct {
		offerID   string
		voucherID string
	}
	var offers []expiredExchangeOffer
	for rows.Next() {
		var offerID, voucherID string
		if rows.Scan(&offerID, &voucherID) != nil {
			continue
		}
		if offerID == "" || voucherID == "" {
			continue
		}
		offers = append(offers, expiredExchangeOffer{offerID: offerID, voucherID: voucherID})
	}
	rows.Close()

	for _, offer := range offers {
		_, _ = s.server.DB.Exec(`UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ? AND status = ?`, "expired", offer.offerID, "withheld")

		transfer, ok := s.getTransferByExchangeOfferVoucherID(offer.voucherID)
		if !ok || transfer == nil {
			continue
		}
		if !strings.EqualFold(asString(transfer["transfer_type"]), "exchange_in") {
			continue
		}
		transferID := asString(transfer["transfer_id"])
		status := strings.ToLower(strings.TrimSpace(asString(transfer["status"])))
		if status == "expired" || status == "rejected" || status == "invalidated" {
			s.rollbackExchangeTransfer(transfer, "exchange_withheld_offer_expired")
			continue
		}

		_, _ = s.server.DB.Exec(`UPDATE monetary_transfers SET status = ?, miner_deadline = NULL WHERE transfer_id = ?`, "expired", transferID)
		s.rollbackExchangeTransfer(transfer, "exchange_withheld_offer_expired")
		s.notifyMonetaryTransferUpdate(transferID, "expired", "exchange_withheld_offer_expired", map[string]any{
			"reason":      "exchange_withheld_offer_expired",
			"transfer_id": transferID,
			"voucher_id":  offer.voucherID,
			"offer_id":    offer.offerID,
		})
		payload := map[string]any{
			"success":     false,
			"stage":       "failed",
			"transfer_id": transferID,
			"error":       "O cÃƒÂ¢mbio expirou antes da liberaÃƒÂ§ÃƒÂ£o do voucher final. O valor original foi devolvido.",
		}
		s.emitToUser(asString(transfer["receiver"]), "exchange_complete", payload)
		s.relayExchangeEventToIssuer(transfer, "exchange_complete", payload)
	}
}

func (s *Server) requestClientSyncSnapshots() {
	type targetConn struct {
		username string
		conn     socketio.Conn
	}
	targets := []targetConn{}
	s.mu.Lock()
	for sid, state := range s.clients {
		if state == nil || !state.Authenticated || trim(state.ClientIdentifier) == "" {
			continue
		}
		conn := s.conns[sid]
		if conn == nil {
			continue
		}
		targets = append(targets, targetConn{username: state.Username, conn: conn})
	}
	s.mu.Unlock()
	if len(targets) == 0 {
		return
	}
	files := make([]map[string]any, 0)
	rowsContent, err := s.server.DB.Query(`SELECT content_hash, title, size FROM content ORDER BY timestamp DESC LIMIT 300`)
	if err == nil {
		for rowsContent.Next() {
			var contentHash, title string
			var size int
			if rowsContent.Scan(&contentHash, &title, &size) != nil || contentHash == "" {
				continue
			}
			files = append(files, map[string]any{
				"content_hash": contentHash,
				"file_name":    title,
				"file_size":    size,
			})
		}
		rowsContent.Close()
	}
	dnsFiles := make([]map[string]any, 0)
	rowsDNS, err := s.server.DB.Query(`SELECT domain, COALESCE(ddns_hash, '') FROM dns_records ORDER BY timestamp DESC LIMIT 300`)
	if err == nil {
		for rowsDNS.Next() {
			var domain, ddnsHash string
			if rowsDNS.Scan(&domain, &ddnsHash) != nil || domain == "" || ddnsHash == "" {
				continue
			}
			dnsFiles = append(dnsFiles, map[string]any{
				"domain":    domain,
				"ddns_hash": ddnsHash,
			})
		}
		rowsDNS.Close()
	}
	contracts := make([]map[string]any, 0)
	rowsContracts, err := s.server.DB.Query(`SELECT contract_id FROM contracts ORDER BY timestamp DESC LIMIT 500`)
	if err == nil {
		for rowsContracts.Next() {
			var contractID string
			if rowsContracts.Scan(&contractID) != nil || contractID == "" {
				continue
			}
			contracts = append(contracts, map[string]any{"contract_id": contractID})
		}
		rowsContracts.Close()
	}
	for _, target := range targets {
		target.conn.Emit("sync_client_files", map[string]any{"files": files})
		target.conn.Emit("sync_client_dns_files", map[string]any{"dns_files": dnsFiles})
		target.conn.Emit("sync_client_contracts", map[string]any{"contracts": contracts})
	}
}

func (s *Server) requestMissingDataFromClients() {
	type targetConn struct {
		clientIdentifier string
		conn             socketio.Conn
	}
	targets := []targetConn{}
	s.mu.Lock()
	for sid, state := range s.clients {
		if state == nil || !state.Authenticated || trim(state.ClientIdentifier) == "" {
			continue
		}
		conn := s.conns[sid]
		if conn == nil {
			continue
		}
		targets = append(targets, targetConn{clientIdentifier: state.ClientIdentifier, conn: conn})
	}
	s.mu.Unlock()
	for _, target := range targets {
		rowsContent, err := s.server.DB.Query(`SELECT cf.content_hash
			FROM client_files cf
			LEFT JOIN content c ON c.content_hash = cf.content_hash
			WHERE cf.client_identifier = ? AND cf.published = 1 AND c.content_hash IS NULL
			ORDER BY cf.last_sync DESC LIMIT 30`, target.clientIdentifier)
		if err == nil {
			for rowsContent.Next() {
				var contentHash string
				if rowsContent.Scan(&contentHash) != nil || contentHash == "" {
					continue
				}
				target.conn.Emit("request_content_from_client", map[string]any{"content_hash": contentHash})
			}
			rowsContent.Close()
		}
		rowsDNS, err := s.server.DB.Query(`SELECT cdf.domain
			FROM client_dns_files cdf
			LEFT JOIN dns_records dr ON dr.domain = cdf.domain
			WHERE cdf.client_identifier = ? AND dr.domain IS NULL
			ORDER BY cdf.last_sync DESC LIMIT 30`, target.clientIdentifier)
		if err == nil {
			for rowsDNS.Next() {
				var domain string
				if rowsDNS.Scan(&domain) != nil || domain == "" {
					continue
				}
				target.conn.Emit("request_ddns_from_client", map[string]any{"domain": domain})
			}
			rowsDNS.Close()
		}
		rowsContracts, err := s.server.DB.Query(`SELECT cc.contract_id
			FROM client_contracts cc
			LEFT JOIN contracts c ON c.contract_id = cc.contract_id
			WHERE cc.client_identifier = ? AND c.contract_id IS NULL
			ORDER BY cc.last_sync DESC LIMIT 50`, target.clientIdentifier)
		if err == nil {
			for rowsContracts.Next() {
				var contractID string
				if rowsContracts.Scan(&contractID) != nil || contractID == "" {
					continue
				}
				target.conn.Emit("request_contract_from_client", map[string]any{"contract_id": contractID})
			}
			rowsContracts.Close()
		}
	}
}

func (s *Server) assignUnassignedTransfers() {
	rows, err := s.server.DB.Query(`SELECT transfer_id, sender, receiver, selector_status, selector_deadline, created_at
		FROM monetary_transfers
		WHERE (assigned_miner IS NULL OR assigned_miner = '')
		  AND status IN (?, ?)`, "awaiting_selector", "pending_signature")
	if err != nil {
		return
	}
	defer rows.Close()
	nowTs := nowSec()
	for rows.Next() {
		var transferID, sender, receiver string
		var selectorStatus sql.NullString
		var selectorDeadline sql.NullFloat64
		var createdAt sql.NullFloat64
		if rows.Scan(&transferID, &sender, &receiver, &selectorStatus, &selectorDeadline, &createdAt) != nil || transferID == "" {
			continue
		}
		// Hard timeout protection: do not stay in awaiting_selector indefinitely.
		if createdAt.Valid && createdAt.Float64 > 0 && (nowTs-createdAt.Float64) >= 35.0 {
			s.assignMinerFallback(transferID, sender, receiver, "selector_timeout")
			continue
		}
		if selectorStatus.Valid && selectorStatus.String == "requested" && selectorDeadline.Valid && selectorDeadline.Float64 > nowTs {
			continue
		}
		s.requestSelectorForTransfer(transferID, sender, receiver)
	}
}

func (s *Server) handleRequestServerAuthChallenge(conn socketio.Conn, data map[string]any) {
	log.Printf("event request_server_auth_challenge sid=%s", conn.ID())
	challenge := core.NewUUID()
	signature := s.server.SignRawText(challenge)
	serverPublicKey := base64.StdEncoding.EncodeToString(s.server.PublicKeyPEM)
	s.mu.Lock()
	s.challenges[conn.ID()] = map[string]any{"challenge": challenge, "timestamp": nowSec()}
	s.mu.Unlock()
	conn.Emit("server_auth_challenge", map[string]any{
		"challenge":         challenge,
		"server_public_key": serverPublicKey,
		"signature":         signature,
	})
}

func (s *Server) handleMinerSelectorResponse(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	transferID := asString(data["transfer_id"])
	if transferID == "" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Missing transfer_id"})
		return
	}
	accept := asBool(data["accept"])
	clientCommit := asString(data["client_commit"])
	var selectorUsername, selectorStatus, selectorNonce, minerListJSON, sender, receiver string
	var selectorDeadline sql.NullFloat64
	err := s.server.DB.QueryRow(`SELECT selector_username, selector_status, selector_deadline, selector_nonce, miner_list_json, sender, receiver
		FROM monetary_transfers WHERE transfer_id = ?`, transferID).
		Scan(&selectorUsername, &selectorStatus, &selectorDeadline, &selectorNonce, &minerListJSON, &sender, &receiver)
	if err != nil {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Transfer not found"})
		return
	}
	if selectorUsername == "" || selectorUsername != client.Username {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Not assigned as selector"})
		return
	}
	if selectorStatus != "requested" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Selector request not active"})
		return
	}
	if selectorDeadline.Valid && selectorDeadline.Float64 > 0 && selectorDeadline.Float64 < nowSec() {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Selector request expired"})
		return
	}
	if !accept {
		_, _ = s.server.DB.Exec(`UPDATE monetary_transfers SET selector_status = ? WHERE transfer_id = ?`, "declined", transferID)
		conn.Emit("miner_selector_ack", map[string]any{"success": true, "declined": true})
		s.requestSelectorForTransfer(transferID, sender, receiver)
		return
	}
	if clientCommit == "" || minerListJSON == "" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Missing commit data"})
		return
	}
	_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
		SET selector_status = ?, selector_client_nonce = ?
		WHERE transfer_id = ?`,
		"committed", clientCommit, transferID)
	conn.Emit("miner_selector_ack", map[string]any{"success": true, "committed": true})
	// Reveal server nonce in phase 2
	conn.Emit("miner_selector_reveal", map[string]any{
		"transfer_id":  transferID,
		"server_nonce": selectorNonce,
	})
}

func (s *Server) handleMinerSelectorRevealResponse(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	transferID := asString(data["transfer_id"])
	if transferID == "" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Missing transfer_id"})
		return
	}
	clientNonce := asString(data["client_nonce"])
	selectedMiner := asString(data["selected_miner"])
	minerListHash := asString(data["miner_list_hash"])
	seedHex := asString(data["seed"])
	selectorContractB64 := asString(data["selector_contract_content"])
	if clientNonce == "" || selectedMiner == "" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Missing reveal data"})
		return
	}
	var selectorUsername, selectorStatus, selectorNonce, selectorCommit, selectorClientCommit, minerListJSON string
	err := s.server.DB.QueryRow(`SELECT selector_username, selector_status, selector_nonce, selector_commit, selector_client_nonce, miner_list_json
		FROM monetary_transfers WHERE transfer_id = ?`, transferID).
		Scan(&selectorUsername, &selectorStatus, &selectorNonce, &selectorCommit, &selectorClientCommit, &minerListJSON)
	if err != nil {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Transfer not found"})
		return
	}
	if selectorUsername == "" || selectorUsername != client.Username {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Not assigned as selector"})
		return
	}
	if selectorStatus != "committed" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Selector reveal not active"})
		return
	}
	if selectorCommit == "" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Missing server commit"})
		return
	}
	if sha256HexString(selectorNonce) != selectorCommit {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Server commit mismatch"})
		return
	}
	if selectorClientCommit == "" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Missing client commit"})
		return
	}
	commitExpected := sha256HexString(clientNonce)
	if commitExpected != selectorClientCommit {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Client commit mismatch"})
		return
	}
	if minerListJSON == "" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Miner list missing"})
		return
	}
	minerListHashExpected := sha256HexString(minerListJSON)
	if minerListHash != "" && minerListHash != minerListHashExpected {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Miner list hash mismatch"})
		return
	}
	var miners []string
	_ = json.Unmarshal([]byte(minerListJSON), &miners)
	if len(miners) == 0 {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Miner list empty"})
		return
	}
	seed := sha256.Sum256([]byte(selectorNonce + ":" + clientNonce + ":" + transferID))
	expectedIndex := int(binary.BigEndian.Uint64(seed[:8]) % uint64(len(miners)))
	expectedMiner := miners[expectedIndex]
	if selectedMiner != expectedMiner {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Selected miner mismatch"})
		return
	}
	if seedHex != "" && seedHex != hex.EncodeToString(seed[:]) {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Seed mismatch"})
		return
	}
	if selectorContractB64 == "" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Missing selector contract"})
		return
	}
	selectorContractBytes, decErr := base64.StdEncoding.DecodeString(selectorContractB64)
	if decErr != nil {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Invalid selector contract: invalid base64"})
		return
	}
	validContract, errMsg, selectorInfo := core.ValidateContractStructure(selectorContractBytes)
	if !validContract || selectorInfo == nil {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Invalid selector contract: " + errMsg})
		return
	}
	if selectorInfo.Action != "miner_selector_client_choice" {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Invalid selector contract action"})
		return
	}
	if selectorInfo.User != client.Username {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Selector contract user mismatch"})
		return
	}
	if !s.server.VerifyContractSignature(selectorContractBytes, client.Username, selectorInfo.Signature, "") {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Invalid selector contract signature"})
		return
	}
	if tid := core.ExtractContractDetail(selectorInfo, "TRANSFER_ID"); tid != "" && tid != transferID {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Selector contract transfer mismatch"})
		return
	}
	if minerFromContract := core.ExtractContractDetail(selectorInfo, "SELECTED_MINER"); minerFromContract != "" && minerFromContract != selectedMiner {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Selector contract miner mismatch"})
		return
	}
	if seedFromContract := core.ExtractContractDetail(selectorInfo, "SEED"); seedFromContract != "" && seedFromContract != hex.EncodeToString(seed[:]) {
		conn.Emit("miner_selector_ack", map[string]any{"success": false, "error": "Selector contract seed mismatch"})
		return
	}
	transfer, _ := s.getMonetaryTransfer(transferID)
	minerDeadline := nowSec() + minerSignatureWindowSeconds(transfer)
	_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
		SET assigned_miner = ?, miner_deadline = ?, status = ?, selector_status = ?, selector_client_nonce = ?, selector_seed = ?
		WHERE transfer_id = ?`,
		selectedMiner, minerDeadline, "pending_signature", "selected", clientNonce, hex.EncodeToString(seed[:]), transferID)
	s.server.SaveContract("miner_selector_client_choice", transferID, "", client.Username, selectorInfo.Signature, selectorContractBytes)
	s.server.SaveServerContract("miner_selector_choice", []core.ContractDetail{
		{Key: "TRANSFER_ID", Value: transferID},
		{Key: "SELECTOR", Value: client.Username},
		{Key: "MINER", Value: selectedMiner},
		{Key: "MINER_LIST_HASH", Value: minerListHashExpected},
		{Key: "MINER_INDEX", Value: expectedIndex},
		{Key: "MINER_COUNT", Value: len(miners)},
		{Key: "SERVER_NONCE", Value: selectorNonce},
		{Key: "CLIENT_NONCE", Value: clientNonce},
		{Key: "SEED", Value: hex.EncodeToString(seed[:])},
	}, transferID)
	conn.Emit("miner_selector_ack", map[string]any{"success": true, "miner": selectedMiner})
	s.emitAssignedMiner(transferID, selectedMiner)
}

func (s *Server) handleVerifyServerAuthResponse(conn socketio.Conn, data map[string]any) {
	log.Printf("event verify_server_auth_response sid=%s", conn.ID())
	clientChallenge := asString(data["client_challenge"])
	clientSignature := asString(data["client_signature"])
	clientPublicKey := asString(data["client_public_key"])
	var challengeMeta map[string]any
	s.mu.Lock()
	challengeMeta, ok := s.challenges[conn.ID()]
	if ok {
		delete(s.challenges, conn.ID())
	}
	client := s.clients[conn.ID()]
	s.mu.Unlock()
	if !ok {
		conn.Emit("server_auth_result", map[string]any{"success": false, "error": "Invalid or expired server auth challenge"})
		return
	}
	if clientPublicKey == "" || clientSignature == "" || clientChallenge == "" {
		conn.Emit("server_auth_result", map[string]any{"success": false, "error": "Invalid client signature"})
		return
	}
	challengeTs := asFloat(challengeMeta["timestamp"])
	if challengeTs > 0 && (nowSec()-challengeTs) > maxChallengeAgeSec {
		conn.Emit("server_auth_result", map[string]any{"success": false, "error": "Server auth challenge expired"})
		return
	}
	if !core.VerifyRawTextSignature(clientChallenge, clientSignature, clientPublicKey) {
		conn.Emit("server_auth_result", map[string]any{"success": false, "error": "Invalid client signature"})
		return
	}
	if client != nil {
		client.ServerAuthenticated = true
		client.PublicKey = clientPublicKey
	}
	log.Printf("server auth ok sid=%s", conn.ID())
	conn.Emit("server_auth_result", map[string]any{"success": true, "client_challenge": clientChallenge})
}

func (s *Server) handleRequestPowChallenge(conn socketio.Conn, data map[string]any) {
	log.Printf("event request_pow_challenge sid=%s action=%s", conn.ID(), asString(data["action_type"]))
	client, ok := s.getClient(conn.ID())
	if !ok || !client.ServerAuthenticated {
		conn.Emit("pow_challenge", map[string]any{"error": "Server not authenticated"})
		return
	}
	clientIdentifier := asString(data["client_identifier"])
	actionType := asString(data["action_type"])
	if actionType == "" {
		actionType = "login"
	}
	if clientIdentifier == "" {
		conn.Emit("pow_challenge", map[string]any{"error": "Client identifier required"})
		return
	}
	client.ClientIdentifier = clientIdentifier
	if actionType == "hps_mint" {
		if !client.Authenticated {
			conn.Emit("pow_challenge", map[string]any{"error": "Not authenticated"})
			return
		}
		if s.server.IsMinerBanned(client.Username) {
			conn.Emit("miner_ban", map[string]any{"reason": "Miner banned from minting", "transfer_id": ""})
			conn.Emit("pow_challenge", map[string]any{"error": "Miner banned from minting"})
			return
		}
	}
	allowed, message, remaining := s.server.CheckRateLimit(clientIdentifier, actionType)
	if !allowed {
		conn.Emit("ban_notification", map[string]any{"duration": remaining, "reason": message})
		conn.Emit("pow_challenge", map[string]any{"error": message, "blocked_until": nowSec() + float64(remaining)})
		return
	}
	challengeData := s.server.GeneratePowChallenge(clientIdentifier, actionType)
	if actionType == "hps_mint" && client.Authenticated {
		suspended, debtStatus := s.server.IsMinerMintingSuspended(client.Username)
		pendingSignatures := asInt(debtStatus["pending_signatures"])
		debtLimit := asInt(debtStatus["debt_limit"])
		pendingFines := asInt(debtStatus["pending_fines"])
		fineGrace := asInt(debtStatus["fine_grace"])
		pendingDelayFines := asInt(debtStatus["pending_delay_fines"])
		promiseActive := asBool(debtStatus["promise_active"]) || asBool(debtStatus["fine_promise_active"])
		nextPendingFines := pendingFines
		if suspended {
			challengeData["minting_withheld"] = true
		}
		warnDebt := (pendingSignatures + 1) >= debtLimit
		if !promiseActive && nextPendingFines > fineGrace && pendingFines <= fineGrace {
			warnDebt = true
		}
		if pendingDelayFines > 0 {
			warnDebt = true
		}
		challengeData["pending_debt_warning"] = warnDebt
	}
	conn.Emit("pow_challenge", challengeData)
}

func (s *Server) handleAuthenticate(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.ServerAuthenticated {
		conn.Emit("authentication_result", map[string]any{"success": false, "error": "Server not authenticated"})
		return
	}
	username := trim(asString(data["username"]))
	publicKeyB64 := trim(asString(data["public_key"]))
	nodeType := asString(data["node_type"])
	if nodeType == "" {
		nodeType = "client"
	}
	clientIdentifier := asString(data["client_identifier"])
	powNonce := asString(data["pow_nonce"])
	hashrateObserved := asFloat(data["hashrate_observed"])
	clientChallengeSignature := asString(data["client_challenge_signature"])
	clientChallenge := asString(data["client_challenge"])

	if username == "" || publicKeyB64 == "" || clientIdentifier == "" || clientChallengeSignature == "" || clientChallenge == "" {
		conn.Emit("authentication_result", map[string]any{"success": false, "error": "Missing key credentials or challenge signature"})
		return
	}
	if username == core.CustodyUsername {
		conn.Emit("authentication_result", map[string]any{"success": false, "error": "O nome de usuÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡rio \"custody\" ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â© de uso especial para a administraÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o do servidor."})
		return
	}
	if !s.server.VerifyPowSolution(clientIdentifier, powNonce, hashrateObserved, "login") {
		conn.Emit("authentication_result", map[string]any{"success": false, "error": "Invalid PoW solution"})
		s.banClientAndNotify(clientIdentifier, 300, "Invalid PoW solution")
		return
	}
	allowed, message, remaining := s.server.CheckRateLimit(clientIdentifier, "login")
	if !allowed {
		conn.Emit("ban_notification", map[string]any{"duration": remaining, "reason": message})
		conn.Emit("authentication_result", map[string]any{"success": false, "error": message, "blocked_until": nowSec() + float64(remaining)})
		return
	}
	if client.PublicKey != "" && client.PublicKey != publicKeyB64 {
		conn.Emit("authentication_result", map[string]any{"success": false, "error": "Public key does not match server authentication"})
		return
	}
	if !core.VerifyRawTextSignature(clientChallenge, clientChallengeSignature, publicKeyB64) {
		conn.Emit("authentication_result", map[string]any{"success": false, "error": "Invalid client challenge signature"})
		return
	}

	var storedKey string
	var reputation int
	err := s.server.DB.QueryRow("SELECT public_key, reputation FROM users WHERE username = ?", username).Scan(&storedKey, &reputation)
	if err == nil {
		if storedKey != "" && storedKey != core.PendingPublicKeyLabel && storedKey != publicKeyB64 {
			conn.Emit("authentication_result", map[string]any{"success": false, "error": "Chave PÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Âºblica invÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡lida, utilize sua chave pÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Âºblica inicial na aba de configuraÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Âµes"})
			violations := s.incrementViolation(clientIdentifier)
			if violations >= 3 {
				s.banClientAndNotify(clientIdentifier, 300, "Multiple invalid public-key attempts")
			}
			return
		}
		_, _ = s.server.DB.Exec("UPDATE users SET last_login = ?, client_identifier = ?, last_activity = ?, public_key = CASE WHEN public_key = ? THEN ? ELSE public_key END WHERE username = ?", nowSec(), clientIdentifier, nowSec(), core.PendingPublicKeyLabel, publicKeyB64, username)
	} else if err == sql.ErrNoRows {
		reputation = 100
		_, _ = s.server.DB.Exec(`INSERT INTO users
			(username, password_hash, public_key, created_at, last_login, reputation, client_identifier, last_activity)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, username, "", publicKeyB64, nowSec(), nowSec(), reputation, clientIdentifier, nowSec())
		_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO user_reputations
			(username, reputation, last_updated, client_identifier) VALUES (?, ?, ?, ?)`, username, reputation, nowSec(), clientIdentifier)
	} else {
		conn.Emit("authentication_result", map[string]any{"success": false, "error": "Internal server error: " + err.Error()})
		return
	}

	client.Authenticated = true
	client.Username = username
	client.NodeType = nodeType
	client.ClientIdentifier = clientIdentifier
	client.PublicKey = publicKeyB64
	s.server.UpdateRateLimit(clientIdentifier, "login")
	conn.Emit("authentication_result", map[string]any{
		"success":           true,
		"username":          username,
		"node_type":         nodeType,
		"reputation":        reputation,
		"client_identifier": clientIdentifier,
	})
	conn.Emit("economy_report", s.server.BuildEconomyReport())
	conn.Emit("hps_economy_status", s.getHpsEconomyStatusPayload())
	conn.Emit("notification", map[string]any{"message": "Authenticated"})
	s.emitContractViolationsForUser(username)
	s.server.TriggerNetworkSyncIfStale(60 * time.Second)
}

func (s *Server) handleRequestHpsWallet(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("hps_wallet_sync", map[string]any{"error": "Not authenticated"})
		return
	}
	s.emitWalletSyncToConn(conn, client.Username)
	s.emitPendingVoucherOffers(client.Username)
}

func (s *Server) emitWalletSyncToUser(username string) {
	username = trim(username)
	if username == "" {
		return
	}
	s.emitToUser(username, "hps_wallet_sync", map[string]any{
		"vouchers":       s.listUserVouchers(username),
		"pending_offers": s.server.ListPendingVoucherOffers(username),
	})
}

func (s *Server) emitWalletSyncToConn(conn socketio.Conn, username string) {
	if conn == nil {
		return
	}
	username = trim(username)
	if username == "" {
		conn.Emit("hps_wallet_sync", map[string]any{"vouchers": []map[string]any{}, "pending_offers": []map[string]any{}})
		return
	}
	conn.Emit("hps_wallet_sync", map[string]any{
		"vouchers":       s.listUserVouchers(username),
		"pending_offers": s.server.ListPendingVoucherOffers(username),
	})
}

func (s *Server) handleRequestEconomyReport(conn socketio.Conn, data map[string]any) {
	conn.Emit("economy_report", s.server.BuildEconomyReport())
	conn.Emit("hps_economy_status", s.getHpsEconomyStatusPayload())
	if s.isExchangeBlocked(s.server.Address) {
		conn.Emit("economy_alert", map[string]any{
			"issuer": s.server.Address,
			"reason": "economy_alert",
		})
	}
}

func (s *Server) canManagePriceSettings(client *ClientState) bool {
	if client == nil || !client.Authenticated {
		return false
	}
	if !s.server.OwnerEnabled() {
		return false
	}
	return strings.EqualFold(trim(client.Username), trim(s.server.OwnerUsername()))
}

func (s *Server) handleRequestPriceSettings(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("price_settings_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}

	conn.Emit("price_settings", map[string]any{
		"prices":       s.server.ListConfiguredPrices(),
		"can_manage":   s.canManagePriceSettings(client),
		"owner_user":   s.server.OwnerUsername(),
		"owner_active": s.server.OwnerEnabled(),
	})
}

func (s *Server) handleUpdatePriceSettings(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("price_settings_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	if !s.canManagePriceSettings(client) {
		conn.Emit("price_settings_ack", map[string]any{"success": false, "error": "Only the server owner can change prices"})
		return
	}

	rawPrices := castMap(data["prices"])
	if len(rawPrices) == 0 {
		conn.Emit("price_settings_ack", map[string]any{"success": false, "error": "No prices provided"})
		return
	}

	for actionType, rawValue := range rawPrices {
		price := asInt(rawValue)
		if price <= 0 {
			conn.Emit("price_settings_ack", map[string]any{"success": false, "error": "Invalid price for " + actionType})
			return
		}
		s.server.SetConfiguredPrice(actionType, price)
	}

	conn.Emit("price_settings_ack", map[string]any{"success": true})
	conn.Emit("price_settings", map[string]any{
		"prices":       s.server.ListConfiguredPrices(),
		"can_manage":   s.canManagePriceSettings(client),
		"owner_user":   s.server.OwnerUsername(),
		"owner_active": s.server.OwnerEnabled(),
	})
	conn.Emit("economy_report", s.server.BuildEconomyReport())
	conn.Emit("hps_economy_status", s.getHpsEconomyStatusPayload())
}

func (s *Server) handleGetNetworkState(conn socketio.Conn, data map[string]any) {
	conn.Emit("network_state", s.networkStatePayload())
}

func (s *Server) handleGetNetworkNodes(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("network_nodes", map[string]any{"error": "Not authenticated"})
		return
	}
	rows, err := s.server.DB.Query(`SELECT node_id, address, public_key, username, last_seen, reputation, node_type, is_online, connection_count, client_identifier
		FROM network_nodes ORDER BY is_online DESC, last_seen DESC`)
	if err != nil {
		conn.Emit("network_nodes", map[string]any{"error": "Internal server error: " + err.Error()})
		return
	}
	defer rows.Close()
	nodes := []map[string]any{}
	for rows.Next() {
		var nodeID, address, publicKey, username, nodeType, clientIdentifier string
		var lastSeen float64
		var reputation, connectionCount int
		var isOnline int
		if scanErr := rows.Scan(&nodeID, &address, &publicKey, &username, &lastSeen, &reputation, &nodeType, &isOnline, &connectionCount, &clientIdentifier); scanErr != nil {
			continue
		}
		nodes = append(nodes, map[string]any{
			"node_id":           nodeID,
			"address":           address,
			"public_key":        publicKey,
			"username":          username,
			"last_seen":         lastSeen,
			"reputation":        reputation,
			"node_type":         nodeType,
			"is_online":         isOnline != 0,
			"connection_count":  connectionCount,
			"client_identifier": clientIdentifier,
		})
	}
	conn.Emit("network_nodes", map[string]any{"nodes": nodes})
}

func (s *Server) networkStatePayload() map[string]any {
	var onlineNodes, totalContent, totalDNS int
	_ = s.server.DB.QueryRow("SELECT COUNT(*) FROM network_nodes WHERE is_online = 1").Scan(&onlineNodes)
	_ = s.server.DB.QueryRow("SELECT COUNT(*) FROM content").Scan(&totalContent)
	_ = s.server.DB.QueryRow("SELECT COUNT(*) FROM dns_records").Scan(&totalDNS)
	rows, err := s.server.DB.Query("SELECT node_type, COUNT(*) FROM network_nodes WHERE is_online = 1 GROUP BY node_type")
	nodeTypes := map[string]any{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var nodeType string
			var count int
			if scanErr := rows.Scan(&nodeType, &count); scanErr == nil {
				nodeTypes[nodeType] = count
			}
		}
	}
	return map[string]any{
		"online_nodes":  onlineNodes,
		"total_content": totalContent,
		"total_dns":     totalDNS,
		"node_types":    nodeTypes,
		"timestamp":     nowSec(),
	}
}

func (s *Server) broadcastNetworkState() {
	payload := s.networkStatePayload()
	s.mu.Lock()
	targets := make([]socketio.Conn, 0, len(s.conns))
	for sid, state := range s.clients {
		if state == nil || !state.Authenticated {
			continue
		}
		conn, ok := s.conns[sid]
		if ok && conn != nil {
			targets = append(targets, conn)
		}
	}
	s.mu.Unlock()
	for _, conn := range targets {
		conn.Emit("network_state", payload)
	}
}

func (s *Server) handleGetServers(conn socketio.Conn, data map[string]any) {
	rows, err := s.server.DB.Query("SELECT address, public_key, last_seen, reputation FROM server_nodes WHERE is_active = 1 ORDER BY reputation DESC, last_seen DESC LIMIT 5")
	if err != nil {
		conn.Emit("server_list", map[string]any{"error": "Internal server error: " + err.Error()})
		return
	}
	defer rows.Close()
	servers := []map[string]any{}
	seen := map[string]bool{}
	for rows.Next() {
		var address, publicKey string
		var lastSeen float64
		var reputation int
		if err := rows.Scan(&address, &publicKey, &lastSeen, &reputation); err == nil {
			seen[core.NormalizeMessageServerAddress(address)] = true
			servers = append(servers, map[string]any{
				"address":    address,
				"public_key": publicKey,
				"last_seen":  lastSeen,
				"reputation": reputation,
			})
		}
	}
	knownRows, err := s.server.DB.Query("SELECT address, last_connected FROM known_servers WHERE is_active = 1 ORDER BY last_connected DESC LIMIT 5")
	if err == nil {
		defer knownRows.Close()
		for knownRows.Next() {
			var address string
			var lastSeen float64
			if knownRows.Scan(&address, &lastSeen) != nil {
				continue
			}
			normalized := core.NormalizeMessageServerAddress(address)
			if normalized == "" || seen[normalized] || core.MessageServerAddressesEqual(address, s.server.Address, s.server.BindAddress) {
				continue
			}
			seen[normalized] = true
			servers = append(servers, map[string]any{
				"address":    address,
				"public_key": "",
				"last_seen":  lastSeen,
				"reputation": 100,
			})
		}
	}
	conn.Emit("server_list", map[string]any{"servers": servers})
}

func (s *Server) handleSearchContent(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("search_results", map[string]any{"error": "Not authenticated"})
		conn.Emit("content_search_status", map[string]any{"status": "error", "error": "Not authenticated"})
		return
	}
	conn.Emit("content_search_status", map[string]any{"status": "running", "query": asString(data["query"])})
	query := asString(data["query"])
	limit := int(asFloat(data["limit"]))
	if limit <= 0 {
		limit = 50
	}
	offset := int(asFloat(data["offset"]))
	contentType := asString(data["content_type"])
	sortBy := asString(data["sort_by"])
	orderClause := "ORDER BY COALESCE(u.reputation, 100) DESC, c.verified DESC, c.replication_count DESC"
	if sortBy == "recent" {
		orderClause = "ORDER BY c.timestamp DESC"
	}
	if sortBy == "popular" {
		orderClause = "ORDER BY c.replication_count DESC, c.last_accessed DESC"
	}
	whereSQL := ""
	params := []any{}
	if trim(query) != "" {
		whereSQL += "(c.title LIKE ? OR c.description LIKE ? OR c.content_hash LIKE ? OR c.username LIKE ?)"
		q := "%" + query + "%"
		params = append(params, q, q, q, q)
	}
	if trim(contentType) != "" {
		if whereSQL != "" {
			whereSQL += " AND "
		}
		whereSQL += "c.mime_type LIKE ?"
		params = append(params, "%"+contentType+"%")
	}
	if whereSQL != "" {
		whereSQL = "WHERE " + whereSQL
	}
	sqlQuery := `SELECT c.content_hash, c.title, c.description, c.mime_type, c.size, c.username, c.signature, c.public_key, c.verified, c.replication_count, COALESCE(u.reputation, 100) as reputation
		FROM content c LEFT JOIN user_reputations u ON c.username = u.username ` + whereSQL + ` ` + orderClause + ` LIMIT ? OFFSET ?`
	params = append(params, limit, offset)
	rows, err := s.server.DB.Query(sqlQuery, params...)
	if err != nil {
		conn.Emit("search_results", map[string]any{"error": "Search failed: " + err.Error()})
		conn.Emit("content_search_status", map[string]any{"status": "error", "error": err.Error()})
		return
	}
	defer rows.Close()
	results := []map[string]any{}
	for rows.Next() {
		var contentHash, title, description, mimeType, username, signature, publicKey string
		var size int64
		var verified, replicationCount, reputation int
		if err := rows.Scan(&contentHash, &title, &description, &mimeType, &size, &username, &signature, &publicKey, &verified, &replicationCount, &reputation); err == nil {
			results = append(results, map[string]any{
				"content_hash":      contentHash,
				"title":             title,
				"description":       description,
				"mime_type":         mimeType,
				"size":              size,
				"username":          username,
				"signature":         signature,
				"public_key":        publicKey,
				"verified":          verified != 0,
				"replication_count": replicationCount,
				"reputation":        reputation,
			})
		}
	}
	conn.Emit("search_results", map[string]any{"results": results})
	conn.Emit("content_search_status", map[string]any{"status": "done", "count": len(results)})
}

func (s *Server) handlePublishContent(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "publish_result")
	if !ok {
		return
	}
	clientIdentifier := actx.ClientIdentifier
	username := actx.Username
	contentHash := asString(data["content_hash"])
	title := asString(data["title"])
	description := asString(data["description"])
	mimeType := asString(data["mime_type"])
	size := int64(asFloat(data["size"]))
	signature := asString(data["signature"])
	publicKeyB64 := asString(data["public_key"])
	contentB64 := asString(data["content_b64"])
	powNonce := asString(data["pow_nonce"])
	hashrateObserved := asFloat(data["hashrate_observed"])
	hpsPayment := castMap(data["hps_payment"])
	liveSessionID := asString(data["live_session_id"])
	isLive := false
	if liveSessionID != "" {
		s.mu.Lock()
		liveSession := s.liveSessions[liveSessionID]
		s.mu.Unlock()
		if liveSession == nil {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Live session not found"})
			return
		}
		if asString(liveSession["owner"]) != username {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Live session owner mismatch"})
			return
		}
		if nowSec() > asFloat(liveSession["expires_at"]) {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Live session expired"})
			return
		}
		liveApp := asString(liveSession["app_name"])
		requestApp := extractAppName(title)
		if liveApp != "" && requestApp != "" && !strings.EqualFold(liveApp, requestApp) {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Live app mismatch"})
			return
		}
		maxSegmentSize := asInt(liveSession["max_segment_size"])
		if maxSegmentSize > 0 && size > int64(maxSegmentSize) {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Live segment exceeds max size"})
			return
		}
		isLive = true
	}
	if contentHash == "" || title == "" || mimeType == "" || size <= 0 || signature == "" || publicKeyB64 == "" || contentB64 == "" {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Missing required fields"})
		return
	}
	if len(title) > maxTitleLength {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Title too long"})
		return
	}
	if len(description) > maxDescriptionLength {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Description too long"})
		return
	}
	if len(mimeType) > maxMimeTypeLength {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Mime type too long"})
		return
	}
	if size > maxUploadContentBytes {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Content exceeds server limit"})
		return
	}
	if len(contentB64) > maxUploadBase64PayloadSize {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Payload too large"})
		return
	}
	contentRaw, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Invalid base64 content"})
		return
	}
	if int64(len(contentRaw)) > (maxUploadContentBytes + maxUploadContractOverhead) {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Decoded payload too large"})
		return
	}
	contentWithoutContract, contractContent := core.ExtractContractFromContent(contentRaw)
	if len(contractContent) == 0 {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Contrato obrigatÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³rio nÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o encontrado"})
		return
	}
	if int64(len(contentWithoutContract)) != size {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Declared size mismatch"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Contrato invÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡lido: " + errMsg})
		return
	}
	transferTitleType, transferTitleTarget, transferTitleApp := parseTransferTitle(title)
	allowedActions := map[string]bool{"upload_file": true}
	if title == "(HPS!dns_change){change_dns_owner=true, proceed=true}" {
		allowedActions["transfer_domain"] = true
	}
	if transferTitleType == "file" || transferTitleType == "content" {
		allowedActions["transfer_content"] = true
	}
	if transferTitleType == "api_app" {
		allowedActions["transfer_api_app"] = true
	}
	if strings.HasPrefix(title, "(HPS!api)") {
		allowedActions["change_api_app"] = true
	}
	if !allowedActions[contractInfo.Action] {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "AÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o do contrato invÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡lida para este upload: " + contractInfo.Action})
		return
	}
	if contractInfo.User != username {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "UsuÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡rio no contrato nÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o corresponde ao usuÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡rio atual"})
		return
	}
	publicKeyOverride := core.ExtractContractDetail(contractInfo, "PUBLIC_KEY")
	if publicKeyOverride == "" {
		publicKeyOverride = publicKeyB64
	}
	if !s.server.VerifyContractSignature(contractContent, username, contractInfo.Signature, publicKeyOverride) {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Assinatura do contrato invÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡lida"})
		return
	}
	actualHash := sha256.Sum256(contentWithoutContract)
	actualHashHex := hex.EncodeToString(actualHash[:])
	if actualHashHex != contentHash {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Hash do conteÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Âºdo (sem contrato) nÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o corresponde ao hash fornecido"})
		return
	}
	transferTo := core.ExtractContractDetail(contractInfo, "TRANSFER_TO")
	transferType := core.ExtractContractDetail(contractInfo, "TRANSFER_TYPE")
	declaredFileHash := core.ExtractContractDetail(contractInfo, "FILE_HASH")
	if declaredFileHash == "" {
		declaredFileHash = core.ExtractContractDetail(contractInfo, "CONTENT_HASH")
	}
	if transferTo == "" {
		transferTo = transferTitleTarget
	}
	dnsChangeMode := title == "(HPS!dns_change){change_dns_owner=true, proceed=true}"
	dnsChangeDomain := ""
	dnsChangeNewOwner := ""
	if dnsChangeMode {
		manifestDomain, manifestNewOwner, manifestErr := parseDNSChangeManifest(contentWithoutContract)
		if manifestErr != "" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": manifestErr})
			return
		}
		dnsChangeDomain = manifestDomain
		dnsChangeNewOwner = manifestNewOwner
		contractDomain := core.ExtractContractDetail(contractInfo, "DOMAIN")
		if contractDomain != "" && contractDomain != dnsChangeDomain {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Domain mismatch between contract and DNS change file"})
			return
		}
		if transferTo == "" {
			transferTo = dnsChangeNewOwner
		}
		if strings.TrimSpace(transferType) == "" {
			transferType = "domain"
		}
	}
	if contractInfo.Action == "transfer_content" {
		if transferTo == "" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Missing transfer target in contract"})
			return
		}
		if declaredFileHash == "" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Missing FILE_HASH in contract"})
			return
		}
		if declaredFileHash != actualHashHex {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "FILE_HASH does not match content hash"})
			return
		}
	}
	if (contractInfo.Action == "transfer_api_app" || contractInfo.Action == "transfer_domain") && transferTo == "" {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Missing transfer target in contract"})
		return
	}
	if transferType != "" {
		normalized := strings.ToLower(strings.TrimSpace(transferType))
		if normalized != "file" && normalized != "content" && normalized != "api_app" && normalized != "domain" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Invalid transfer type in contract"})
			return
		}
	}
	appNameForTransfer := ""
	domainForTransfer := ""
	consumedPendingTransferID := ""
	if contractInfo.Action == "transfer_content" {
		var owner string
		_ = s.server.DB.QueryRow(`SELECT username FROM content WHERE content_hash = ?`, contentHash).Scan(&owner)
		if owner == "" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Content not found for transfer"})
			return
		}
		if owner != username {
			pendingID := getPendingTransferIDForUser(s.server.DB, username, "content", contentHash, "", "")
			if pendingID == "" {
				conn.Emit("publish_result", map[string]any{"success": false, "error": "Only the content owner can transfer this content"})
				return
			}
			consumedPendingTransferID = pendingID
		}
		if transferTo != "" && transferTo == username {
			pendingID := getPendingTransferIDForUser(s.server.DB, username, "content", contentHash, "", "")
			if pendingID == "" {
				conn.Emit("publish_result", map[string]any{"success": false, "error": "No pending transfer for this content"})
				return
			}
			consumedPendingTransferID = pendingID
		}
	}
	if contractInfo.Action == "transfer_api_app" {
		appNameForTransfer = core.ExtractContractDetail(contractInfo, "APP")
		if appNameForTransfer == "" {
			appNameForTransfer = transferTitleApp
		}
		if appNameForTransfer == "" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Missing API app name for transfer"})
			return
		}
		var owner string
		_ = s.server.DB.QueryRow(`SELECT username FROM api_apps WHERE app_name = ?`, appNameForTransfer).Scan(&owner)
		if owner == "" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "API app not found for transfer"})
			return
		}
		if owner != username {
			pendingID := getPendingTransferIDForUser(s.server.DB, username, "api_app", "", "", appNameForTransfer)
			if pendingID == "" {
				conn.Emit("publish_result", map[string]any{"success": false, "error": "Only the API app owner can transfer this app"})
				return
			}
			consumedPendingTransferID = pendingID
		}
		if transferTo != "" && transferTo == username {
			pendingID := getPendingTransferIDForUser(s.server.DB, username, "api_app", "", "", appNameForTransfer)
			if pendingID == "" {
				conn.Emit("publish_result", map[string]any{"success": false, "error": "No pending transfer for this content"})
				return
			}
			consumedPendingTransferID = pendingID
		}
	}
	if contractInfo.Action == "transfer_domain" {
		domainForTransfer = core.ExtractContractDetail(contractInfo, "DOMAIN")
		if domainForTransfer == "" {
			domainForTransfer = core.ExtractContractDetail(contractInfo, "DNAME")
		}
		if domainForTransfer == "" && dnsChangeDomain != "" {
			domainForTransfer = dnsChangeDomain
		}
		if domainForTransfer == "" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Missing domain for transfer"})
			return
		}
		var owner string
		_ = s.server.DB.QueryRow(`SELECT username FROM dns_records WHERE domain = ?`, domainForTransfer).Scan(&owner)
		if owner == "" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Domain not found for transfer"})
			return
		}
		if owner != username {
			pendingID := getPendingTransferIDForUser(s.server.DB, username, "domain", "", domainForTransfer, "")
			if pendingID == "" {
				conn.Emit("publish_result", map[string]any{"success": false, "error": "Only the domain owner can transfer this domain"})
				return
			}
			consumedPendingTransferID = pendingID
		}
		if transferTo != "" && transferTo == username {
			pendingID := getPendingTransferIDForUser(s.server.DB, username, "domain", "", domainForTransfer, "")
			if pendingID == "" {
				conn.Emit("publish_result", map[string]any{"success": false, "error": "No pending transfer for this domain"})
				return
			}
			consumedPendingTransferID = pendingID
		}
	}
	var contentCount int
	_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM content WHERE username = ?`, username).Scan(&contentCount)
	if contentCount >= maxContentPerUser {
		conn.Emit("publish_result", map[string]any{
			"success": false,
			"error":   fmt.Sprintf("Maximum content limit reached (%d)", maxContentPerUser),
		})
		return
	}
	var existingOwner string
	var existingSize int64
	hasExisting := false
	_ = s.server.DB.QueryRow(`SELECT username, size FROM content WHERE content_hash = ?`, contentHash).Scan(&existingOwner, &existingSize)
	if strings.TrimSpace(existingOwner) != "" {
		hasExisting = true
	}
	if hasExisting {
		violation := s.server.GetContractViolation("content", contentHash, "")
		reason := ""
		if violation != nil {
			reason = asString(violation["reason"])
		}
		if reason != "" && reason != "content_tampered" && reason != "content_signature_invalid" && reason != "missing_signature" {
			conn.Emit("publish_result", map[string]any{"success": false, "error": "Content has unresolved contract violations"})
			return
		}
		if reason != "" {
			cert := s.server.GetContractCertification("content", contentHash)
			certifier := ""
			if cert != nil {
				certifier = asString(cert["certifier"])
			}
			if username != existingOwner && username != certifier {
				conn.Emit("publish_result", map[string]any{"success": false, "error": "Apenas o dono ou certificador pode reparar este conteÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Âºdo"})
				return
			}
		}
	}
	var diskQuota, usedDiskSpace int64
	if err := s.server.DB.QueryRow(`SELECT disk_quota, used_disk_space FROM users WHERE username = ?`, username).Scan(&diskQuota, &usedDiskSpace); err == nil {
		deltaSize := size
		if hasExisting {
			deltaSize = size - existingSize
			if deltaSize < 0 {
				deltaSize = 0
			}
		}
		if (usedDiskSpace + deltaSize) > diskQuota {
			availableMB := float64(diskQuota-usedDiskSpace) / (1024.0 * 1024.0)
			conn.Emit("publish_result", map[string]any{
				"success": false,
				"error":   fmt.Sprintf("Disk quota exceeded. Available space: %.2fMB", availableMB),
			})
			return
		}
	}
	if !actx.Deferred && !isLive {
		allowed, message, remaining := s.server.CheckRateLimit(clientIdentifier, "upload")
		if !allowed {
			conn.Emit("publish_result", map[string]any{"success": false, "error": message, "blocked_until": nowSec() + float64(remaining)})
			return
		}
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			clientIdentifier, username, "upload", powNonce, hashrateObserved, hpsPayment,
		)
		if !okAuth {
			conn.Emit("publish_result", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(clientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{
				"data":       data,
				"public_key": actx.PublicKey,
				"payment":    pendingInfo,
			}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "publish_content", username, clientIdentifier, payload, "publish_result")
			return
		}
	}
	filePath := s.server.ContentPath(contentHash)
	if err := s.server.WriteEncryptedFile(filePath, contentRaw, 0o644); err != nil {
		conn.Emit("publish_result", map[string]any{"success": false, "error": "Internal server error: " + err.Error()})
		return
	}
	issuerContractID := s.server.SaveServerContract("content_issuer_attest", []core.ContractDetail{
		{Key: "TARGET_TYPE", Value: "content"},
		{Key: "TARGET_ID", Value: contentHash},
		{Key: "USERNAME", Value: username},
		{Key: "TITLE", Value: title},
	}, contentHash)
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO content
		(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, replication_count, last_accessed, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		contentHash, title, description, mimeType, size, username, signature, publicKeyB64, nowSec(), filePath, 1, 1, nowSec(),
		s.server.Address, base64.StdEncoding.EncodeToString(s.server.PublicKeyPEM), issuerContractID, nowSec())
	if hasExisting {
		deltaSize := size - existingSize
		if deltaSize < 0 {
			deltaSize = 0
		}
		if deltaSize > 0 {
			_, _ = s.server.DB.Exec(`UPDATE users SET used_disk_space = used_disk_space + ? WHERE username = ?`, deltaSize, username)
		}
	} else {
		_, _ = s.server.DB.Exec(`UPDATE users SET used_disk_space = used_disk_space + ? WHERE username = ?`, size, username)
	}
	if hasExisting {
		violation := s.server.GetContractViolation("content", contentHash, "")
		reportedBy := ""
		if violation != nil {
			reportedBy = asString(violation["reported_by"])
		}
		s.server.ClearContractViolation("content", contentHash, "")
		_, _ = s.server.DB.Exec(`DELETE FROM pending_transfers WHERE transfer_type = ? AND content_hash = ? AND status = ?`, "content_repair", contentHash, "pending")
		clearedPayload := map[string]any{
			"violation_type": "content",
			"content_hash":   contentHash,
		}
		s.emitToUser(username, "contract_violation_cleared", clearedPayload)
		if reportedBy != "" && reportedBy != username {
			s.emitToUser(reportedBy, "contract_violation_cleared", clearedPayload)
		}
		pendingForUser := listPendingTransfersForUser(s.server.DB, username)
		s.emitToUser(username, "pending_transfers", map[string]any{"transfers": pendingForUser})
		s.emitToUser(username, "pending_transfer_notice", map[string]any{"count": len(pendingForUser)})
	}
	if strings.HasPrefix(title, "(HPS!api)") {
		okUpdate, msg := processAppUpdate(s.server.DB, title, username, contentHash)
		if !okUpdate {
			_ = os.Remove(filePath)
			_, _ = s.server.DB.Exec(`DELETE FROM content WHERE content_hash = ?`, contentHash)
			conn.Emit("publish_result", map[string]any{"success": false, "error": msg})
			return
		}
		_ = msg
	}
	actionForSave := contractInfo.Action
	domainForContract := ""
	if actionForSave == "upload_file" {
		actionForSave = "upload_file"
	}
	if actionForSave == "transfer_domain" {
		domainForContract = domainForTransfer
	}
	contractID := s.server.SaveContract(actionForSave, contentHash, domainForContract, username, contractInfo.Signature, contractContent)
	if contractInfo.Action == "transfer_content" {
		if transferTo != "" && transferTo != username {
			_, _ = s.server.DB.Exec(`UPDATE content SET username = ? WHERE content_hash = ?`, core.CustodyUsername, contentHash)
			createPendingTransfer(s.server.DB, "content", transferTo, username, contentHash, "", "", contractID)
			pendingForTarget := listPendingTransfersForUser(s.server.DB, transferTo)
			s.emitToUser(transferTo, "pending_transfers", map[string]any{"transfers": pendingForTarget})
			s.emitPendingTransferNotice(transferTo)
		} else if consumedPendingTransferID != "" {
			_, _ = s.server.DB.Exec(`UPDATE content SET username = ? WHERE content_hash = ?`, username, contentHash)
		}
	}
	if contractInfo.Action == "transfer_api_app" {
		if transferTo != "" && transferTo != username {
			_, _ = s.server.DB.Exec(`UPDATE api_apps SET username = ? WHERE app_name = ?`, core.CustodyUsername, appNameForTransfer)
			createPendingTransfer(s.server.DB, "api_app", transferTo, username, "", "", appNameForTransfer, contractID)
			pendingForTarget := listPendingTransfersForUser(s.server.DB, transferTo)
			s.emitToUser(transferTo, "pending_transfers", map[string]any{"transfers": pendingForTarget})
			s.emitPendingTransferNotice(transferTo)
		} else if consumedPendingTransferID != "" {
			_, _ = s.server.DB.Exec(`UPDATE api_apps SET username = ? WHERE app_name = ?`, username, appNameForTransfer)
		}
	}
	if contractInfo.Action == "transfer_domain" {
		if transferTo != "" && transferTo != username {
			currentOwner := ""
			_ = s.server.DB.QueryRow(`SELECT username FROM dns_records WHERE domain = ?`, domainForTransfer).Scan(&currentOwner)
			_, _ = s.server.DB.Exec(`UPDATE dns_records SET username = ? WHERE domain = ?`, core.CustodyUsername, domainForTransfer)
			_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO dns_owner_changes
				(change_id, domain, previous_owner, new_owner, changer, timestamp, change_file_hash)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				core.NewUUID(), domainForTransfer, currentOwner, core.CustodyUsername, username, nowSec(), contentHash)
			createPendingTransfer(s.server.DB, "domain", transferTo, username, contentHash, domainForTransfer, "", contractID)
			pendingForTarget := listPendingTransfersForUser(s.server.DB, transferTo)
			s.emitToUser(transferTo, "pending_transfers", map[string]any{"transfers": pendingForTarget})
			s.emitPendingTransferNotice(transferTo)
		} else if consumedPendingTransferID != "" {
			currentOwner := ""
			_ = s.server.DB.QueryRow(`SELECT username FROM dns_records WHERE domain = ?`, domainForTransfer).Scan(&currentOwner)
			_, _ = s.server.DB.Exec(`UPDATE dns_records SET username = ?, original_owner = ? WHERE domain = ?`, username, username, domainForTransfer)
			_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO dns_owner_changes
				(change_id, domain, previous_owner, new_owner, changer, timestamp, change_file_hash)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				core.NewUUID(), domainForTransfer, currentOwner, username, username, nowSec(), contentHash)
		}
	}
	if consumedPendingTransferID != "" {
		_, _ = s.server.DB.Exec(`DELETE FROM pending_transfers WHERE transfer_id = ?`, consumedPendingTransferID)
		pendingForUser := listPendingTransfersForUser(s.server.DB, username)
		s.emitToUser(username, "pending_transfers", map[string]any{"transfers": pendingForUser})
		s.emitPendingTransferNotice(username)
	}
	s.server.UpdateRateLimit(clientIdentifier, "upload")
	if len(hpsPayment) > 0 {
		s.emitWalletSyncToUser(username)
	}
	conn.Emit("publish_result", map[string]any{
		"success":            true,
		"content_hash":       contentHash,
		"verified":           1,
		"issuer_server":      s.server.Address,
		"issuer_contract_id": issuerContractID,
	})
	if isLive {
		conn.Emit("live_upload_receipt", map[string]any{
			"session_id": liveSessionID,
			"status":     "uploaded",
			"cost":       0,
		})
	}
}

func (s *Server) handleRegisterDNS(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "dns_result")
	if !ok {
		return
	}
	clientIdentifier := actx.ClientIdentifier
	username := actx.Username
	powNonce := asString(data["pow_nonce"])
	hashrateObserved := asFloat(data["hashrate_observed"])
	hpsPayment := castMap(data["hps_payment"])
	domain := strings.ToLower(trim(asString(data["domain"])))
	ddnsContentB64 := asString(data["ddns_content"])
	signature := asString(data["signature"])
	publicKeyB64 := asString(data["public_key"])
	if publicKeyB64 == "" {
		publicKeyB64 = actx.PublicKey
	}
	if domain == "" || ddnsContentB64 == "" || signature == "" {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Missing domain, ddns content or signature"})
		return
	}
	if len(ddnsContentB64) > maxDdnsBase64PayloadSize {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "DDNS payload too large"})
		return
	}
	if !isValidDomain(domain) {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Invalid domain"})
		return
	}
	ddnsRaw, err := base64.StdEncoding.DecodeString(ddnsContentB64)
	if err != nil {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Invalid base64 ddns content"})
		return
	}
	ddnsWithoutContract, contractContent := core.ExtractContractFromContent(ddnsRaw)
	if len(contractContent) == 0 {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Contrato obrigatÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³rio nÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o encontrado no DDNS"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Contrato invÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡lido: " + errMsg})
		return
	}
	if contractInfo.Action != "register_dns" {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "AÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o do contrato invÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡lida: " + contractInfo.Action})
		return
	}
	if contractInfo.User != username {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "UsuÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡rio no contrato nÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o corresponde ao usuÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡rio atual"})
		return
	}
	publicKeyOverride := core.ExtractContractDetail(contractInfo, "PUBLIC_KEY")
	if publicKeyOverride == "" {
		publicKeyOverride = publicKeyB64
	}
	if !s.server.VerifyContractSignature(contractContent, username, contractInfo.Signature, publicKeyOverride) {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Assinatura do contrato invÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡lida"})
		return
	}
	if !bytes.HasPrefix(ddnsWithoutContract, []byte("# HSYST P2P SERVICE")) {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Missing HSYST header in ddns file"})
		return
	}
	headerEnd := []byte("### :END START")
	if !bytes.Contains(ddnsWithoutContract, headerEnd) {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Invalid HSYST header format in ddns file"})
		return
	}
	parts := bytes.SplitN(ddnsWithoutContract, headerEnd, 2)
	if len(parts) != 2 {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Invalid HSYST header format in ddns file"})
		return
	}
	ddnsDataSigned := parts[1]
	verified := 1
	signatureOK, signatureErr := s.server.VerifyContentSignatureDetailed(ddnsDataSigned, signature, publicKeyB64)
	if signatureErr != nil {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Signature verification failed: " + signatureErr.Error()})
		return
	}
	if !signatureOK {
		verified = 0
		s.server.AdjustReputation(username, -5)
		s.emitToUser(username, "reputation_update", map[string]any{"reputation": s.getUserReputation(username)})
	}
	ddnsHash := sha256.Sum256(ddnsWithoutContract)
	ddnsHashHex := hex.EncodeToString(ddnsHash[:])
	ddnsPath := s.server.DdnsPath(ddnsHashHex)
	if err := s.server.WriteEncryptedFile(ddnsPath, ddnsWithoutContract, 0o644); err != nil {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Error saving ddns file: " + err.Error()})
		return
	}
	contentHash := extractContentHashFromDDNS(ddnsWithoutContract)
	if contentHash == "" {
		conn.Emit("dns_result", map[string]any{"success": false, "error": "Could not extract content hash from ddns file"})
		return
	}
	var existingOwner, existingOriginal string
	_ = s.server.DB.QueryRow(`SELECT username, original_owner FROM dns_records WHERE domain = ? LIMIT 1`, domain).Scan(&existingOwner, &existingOriginal)
	if existingOwner != "" && existingOwner != username {
		if existingOwner == core.CustodyUsername || existingOwner == "system" {
			var pendingCount int
			_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM pending_transfers WHERE domain = ? AND status = ?`, domain, "pending").Scan(&pendingCount)
			if pendingCount > 0 {
				conn.Emit("dns_result", map[string]any{
					"success": false,
					"error":   `Domain "` + domain + `" esta sob custodia com transferencia pendente.`,
				})
				return
			}
			var dnsCount int
			_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM dns_records WHERE username = ?`, username).Scan(&dnsCount)
			if dnsCount >= maxDNSPerUser {
				conn.Emit("dns_result", map[string]any{
					"success": false,
					"error":   fmt.Sprintf("Maximum DNS records limit reached (%d)", maxDNSPerUser),
				})
				return
			}
		} else {
			conn.Emit("dns_result", map[string]any{
				"success": false,
				"error":   `Domain "` + domain + `" is already registered by ` + existingOwner + `. Domains are non-transferable via regular registration.`,
			})
			violations := s.incrementViolation(clientIdentifier)
			if violations >= 3 {
				s.banClientAndNotify(clientIdentifier, 600, "Multiple domain takeover attempts")
			}
			return
		}
	}
	if existingOwner == "" {
		var dnsCount int
		_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM dns_records WHERE username = ?`, username).Scan(&dnsCount)
		if dnsCount >= maxDNSPerUser {
			conn.Emit("dns_result", map[string]any{
				"success": false,
				"error":   fmt.Sprintf("Maximum DNS records limit reached (%d)", maxDNSPerUser),
			})
			return
		}
	}
	if existingOwner == username {
		var dnsCount int
		_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM dns_records WHERE username = ?`, username).Scan(&dnsCount)
		if dnsCount >= maxDNSPerUser {
			conn.Emit("dns_result", map[string]any{
				"success": false,
				"error":   fmt.Sprintf("Maximum DNS records limit reached (%d)", maxDNSPerUser),
			})
			return
		}
	}
	originalOwner := username
	if existingOriginal != "" {
		originalOwner = existingOriginal
	}
	if !actx.Deferred {
		allowed, message, remaining := s.server.CheckRateLimit(clientIdentifier, "dns")
		if !allowed {
			conn.Emit("dns_result", map[string]any{"success": false, "error": message, "blocked_until": nowSec() + float64(remaining)})
			violations := s.incrementViolation(clientIdentifier)
			if violations >= 3 {
				s.banClientAndNotify(clientIdentifier, 300, "Multiple rate limit violations")
			}
			return
		}
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			clientIdentifier, username, "dns", powNonce, hashrateObserved, hpsPayment,
		)
		if !okAuth {
			conn.Emit("dns_result", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(clientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{
				"data":       data,
				"public_key": actx.PublicKey,
				"payment":    pendingInfo,
			}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "register_dns", username, clientIdentifier, payload, "dns_result")
			return
		}
	}
	issuerContractID := s.server.SaveServerContract("dns_issuer_attest", []core.ContractDetail{
		{Key: "TARGET_TYPE", Value: "domain"},
		{Key: "TARGET_ID", Value: domain},
		{Key: "USERNAME", Value: username},
		{Key: "CONTENT_HASH", Value: contentHash},
	}, domain)
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO dns_records
		(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, contentHash, username, originalOwner, nowSec(), signature, verified, nowSec(), ddnsHashHex,
		s.server.Address, base64.StdEncoding.EncodeToString(s.server.PublicKeyPEM), issuerContractID, nowSec())
	s.server.SaveContract("register_dns", "", domain, username, contractInfo.Signature, contractContent)
	if verified == 1 {
		s.server.AdjustReputation(username, 1)
		s.emitToUser(username, "reputation_update", map[string]any{"reputation": s.getUserReputation(username)})
	}
	s.server.UpdateRateLimit(clientIdentifier, "dns")
	if len(hpsPayment) > 0 {
		s.emitWalletSyncToUser(username)
	}
	conn.Emit("dns_result", map[string]any{
		"success":            true,
		"domain":             domain,
		"verified":           verified,
		"original_owner":     originalOwner,
		"issuer_server":      s.server.Address,
		"issuer_contract_id": issuerContractID,
	})
}

func (s *Server) handleGetContentRepairPayload(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("content_repair_payload", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	transferID := asString(data["transfer_id"])
	if transferID == "" {
		conn.Emit("content_repair_payload", map[string]any{"success": false, "error": "Missing transfer_id"})
		return
	}
	transfer, ok := s.getPendingTransfer(transferID)
	if !ok {
		conn.Emit("content_repair_payload", map[string]any{"success": false, "error": "Transfer not found"})
		return
	}
	if asString(transfer["transfer_type"]) != "content_repair" || asString(transfer["target_user"]) != client.Username {
		conn.Emit("content_repair_payload", map[string]any{"success": false, "error": "Not authorized"})
		return
	}
	contentHash := asString(transfer["content_hash"])
	if contentHash == "" {
		conn.Emit("content_repair_payload", map[string]any{"success": false, "error": "Missing content hash"})
		return
	}
	var title, description, mimeType, username, signature, publicKey string
	err := s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key
		FROM content WHERE content_hash = ?`, contentHash).
		Scan(&title, &description, &mimeType, &username, &signature, &publicKey)
	if err != nil {
		conn.Emit("content_repair_payload", map[string]any{"success": false, "error": "Content metadata not found"})
		return
	}
	conn.Emit("content_repair_payload", map[string]any{
		"success":      true,
		"transfer_id":  transferID,
		"content_hash": contentHash,
		"title":        title,
		"description":  description,
		"mime_type":    mimeType,
		"username":     username,
		"signature":    signature,
		"public_key":   publicKey,
	})
}

func (s *Server) handleContentIntegrityReport(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("content_integrity_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	contentHash := asString(data["content_hash"])
	reason := asString(data["reason"])
	if contentHash == "" {
		conn.Emit("content_integrity_ack", map[string]any{"success": false, "error": "Missing content hash"})
		return
	}
	if reason == "" {
		reason = "content_tampered"
	}
	s.server.RegisterContractViolation("content", client.Username, contentHash, "", reason, false)
	s.server.EnsureContentRepairPending(contentHash)
	var owner string
	_ = s.server.DB.QueryRow(`SELECT username FROM content WHERE content_hash = ?`, contentHash).Scan(&owner)
	if owner != "" {
		s.emitToUser(owner, "contract_violation_notice", map[string]any{
			"violation_type": "content",
			"content_hash":   contentHash,
			"reason":         reason,
		})
		s.emitPendingTransferNotice(owner)
	}
	conn.Emit("content_integrity_ack", map[string]any{"success": true})
}

func (s *Server) handleTransferHPS(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "hps_transfer_ack")
	if !ok {
		return
	}
	clientIdentifier := actx.ClientIdentifier
	username := actx.Username
	targetUser := trim(asString(data["target_user"]))
	amount := int(asFloat(data["amount"]))
	voucherIDs := toStringSlice(data["voucher_ids"])
	contractContentB64 := asString(data["contract_content"])
	powNonce := asString(data["pow_nonce"])
	hashrateObserved := asFloat(data["hashrate_observed"])
	hpsPayment := castMap(data["hps_payment"])
	if targetUser == "" || amount <= 0 {
		conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": "Invalid transfer data"})
		return
	}
	if contractContentB64 == "" {
		conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": "Missing contract content"})
		return
	}
	contractContent, err := base64.StdEncoding.DecodeString(contractContentB64)
	if err != nil {
		conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": "Invalid contract content"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": "Invalid contract: " + errMsg})
		return
	}
	if contractInfo.Action != "transfer_hps" {
		conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": "Invalid contract action"})
		return
	}
	if contractInfo.User != username {
		conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": "Contract user mismatch"})
		return
	}
	contractVouchers := core.ExtractContractDetail(contractInfo, "VOUCHERS")
	if contractVouchers != "" {
		var contractList []string
		if json.Unmarshal([]byte(contractVouchers), &contractList) != nil {
			conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": "Invalid vouchers in contract"})
			return
		}
		if !sameStringSet(contractList, voucherIDs) {
			conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": "Contract vouchers mismatch"})
			return
		}
	}
	if !s.server.VerifyContractSignature(contractContent, username, contractInfo.Signature, "") {
		conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": "Invalid contract signature"})
		return
	}
	if !actx.Deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			clientIdentifier, username, "hps_transfer", powNonce, hashrateObserved, hpsPayment,
		)
		if !okAuth {
			conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(clientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{
				"data":       data,
				"public_key": actx.PublicKey,
				"payment":    pendingInfo,
			}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "transfer_hps", username, clientIdentifier, payload, "hps_transfer_ack")
			return
		}
	}
	session, reserveErr := s.server.CreateHpsTransferSession(username, targetUser, voucherIDs, amount)
	if session == nil {
		conn.Emit("hps_transfer_ack", map[string]any{"success": false, "error": reserveErr})
		return
	}
	feeAmount, selectorFee, feeSource, adjustedAmount := s.server.AllocateSignatureFees(amount)
	sessionID := asString(session["session_id"])
	totalValue := asInt(session["total_value"])
	if totalValue != amount && feeSource != "custody" {
		s.server.ReleaseVouchersForSession(sessionID)
		s.server.DeleteHpsTransferSession(sessionID)
		conn.Emit("hps_transfer_ack", map[string]any{
			"success": false,
			"error":   "Custodia sem saldo para cobrir taxas do troco",
		})
		return
	}
	contractID := s.server.SaveContract("transfer_hps", "", "", username, contractInfo.Signature, contractContent)
	transferID := core.NewUUID()
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO pending_transfers
		(transfer_id, transfer_type, target_user, original_owner, custody_user, content_hash, domain, app_name, contract_id, status, timestamp, hps_amount, hps_total_value, hps_voucher_ids, hps_session_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transferID, "hps_transfer", targetUser, username, core.CustodyUsername, nil, nil, nil, contractID, "pending", nowSec(), adjustedAmount, totalValue, toJSONString(voucherIDs), sessionID)
	nowTs := nowSec()
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, fee_amount, selector_fee_amount, fee_source, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transferID, "hps_transfer", username, targetUser, adjustedAmount, nowTs, "awaiting_selector", contractID, toJSONString(voucherIDs), feeAmount, selectorFee, feeSource, nowTs+60.0)
	assignedMiner := ""
	s.requestSelectorForTransfer(transferID, username, targetUser)
	s.emitToUser(targetUser, "pending_transfer_notice", map[string]any{"count": countPendingForUser(s.server.DB, targetUser)})
	s.emitWalletSyncToUser(username)
	s.emitToUser(username, "monetary_transfer_pending", map[string]any{
		"transfer_id":    transferID,
		"transfer_type":  "hps_transfer",
		"sender":         username,
		"receiver":       targetUser,
		"amount":         adjustedAmount,
		"assigned_miner": assignedMiner,
		"status": func() string {
			if assignedMiner != "" {
				return "assigned"
			}
			return "awaiting_selector"
		}(),
	})
	s.emitToUser(targetUser, "monetary_transfer_pending", map[string]any{
		"transfer_id":    transferID,
		"transfer_type":  "hps_transfer",
		"sender":         username,
		"receiver":       targetUser,
		"amount":         adjustedAmount,
		"assigned_miner": assignedMiner,
		"status": func() string {
			if assignedMiner != "" {
				return "assigned"
			}
			return "awaiting_selector"
		}(),
	})
	if assignedMiner != "" {
		s.emitToUser(assignedMiner, "miner_signature_request", map[string]any{
			"transfer_id":        transferID,
			"transfer_type":      "hps_transfer",
			"sender":             username,
			"receiver":           targetUser,
			"amount":             adjustedAmount,
			"fee_amount":         feeAmount,
			"selector_fee":       selectorFee,
			"fee_source":         feeSource,
			"contract_id":        contractID,
			"locked_voucher_ids": voucherIDs,
			"deadline":           nowTs + 60.0,
			"miner_deadline":     nowTs + 5.0,
			"pending_signatures": asInt(s.server.GetMinerStats(assignedMiner)["pending_signatures"]),
		})
		s.notifyMonetaryTransferUpdate(transferID, "assigned", "", nil)
		go s.enforceMinerSignatureDeadline(transferID, assignedMiner, nowTs+5.0)
	}
	feeNote := ""
	if feeAmount > 0 && feeSource == "receiver" && adjustedAmount < amount {
		totalFee := feeAmount + selectorFee
		feeNote = " (taxa total: " + intToString(totalFee) + " HPS; minerador: " + intToString(feeAmount) + " HPS; seletor: " + intToString(selectorFee) + " HPS)"
	}
	changeNote := ""
	if totalValue != amount {
		changeNote = " Troco sera emitido pela custodia."
	}
	conn.Emit("hps_transfer_ack", map[string]any{
		"success":     true,
		"message":     "Transferencia de " + intToString(adjustedAmount) + " HPS enviada para " + targetUser + "." + feeNote + changeNote + " Saldo reservado ate confirmacao do destinatario.",
		"transfer_id": transferID,
		"session_id":  sessionID,
		"total_value": totalValue,
	})
}

func (s *Server) handleMintHpsVoucher(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("hps_voucher_error", map[string]any{"error": "Not authenticated"})
		return
	}
	clientIdentifier := client.ClientIdentifier
	username := client.Username
	if s.server.IsMinerBanned(username) {
		conn.Emit("hps_voucher_error", map[string]any{"error": "Miner banned from minting"})
		return
	}
	suspended, debtStatus := s.server.IsMinerMintingSuspended(username)
	powNonce := asString(data["pow_nonce"])
	hashrateObserved := asFloat(data["hashrate_observed"])
	reason := asString(data["reason"])
	if reason == "" {
		reason = "mining"
	}
	contractContentB64 := asString(data["contract_content"])
	validPow, powInfo := s.server.VerifyPowSolutionDetails(clientIdentifier, powNonce, hashrateObserved, "hps_mint")
	if !validPow || powInfo == nil {
		conn.Emit("hps_voucher_error", map[string]any{"error": "Invalid PoW solution"})
		s.banClientAndNotify(clientIdentifier, 300, "Invalid PoW solution")
		return
	}
	s.server.UpdateRateLimit(clientIdentifier, "hps_mint")
	if contractContentB64 != "" {
		contractContent, err := base64.StdEncoding.DecodeString(contractContentB64)
		if err != nil {
			conn.Emit("hps_voucher_error", map[string]any{"error": "Invalid contract: invalid base64"})
			return
		}
		valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
		if !valid || contractInfo == nil {
			conn.Emit("hps_voucher_error", map[string]any{"error": "Invalid contract: " + errMsg})
			return
		}
		if contractInfo.Action != "hps_mint" {
			conn.Emit("hps_voucher_error", map[string]any{"error": "Invalid contract action"})
			return
		}
		if contractInfo.User != username {
			conn.Emit("hps_voucher_error", map[string]any{"error": "Contract user mismatch"})
			return
		}
		if !s.server.VerifyContractSignature(contractContent, username, contractInfo.Signature, "") {
			conn.Emit("hps_voucher_error", map[string]any{"error": "Invalid contract signature"})
			return
		}
		s.server.SaveContract("hps_mint", "", "", username, contractInfo.Signature, contractContent)
	}
	targetBits := asInt(powInfo["target_bits"])
	value := s.server.GetHpsVoucherValueFromBits(targetBits)
	powInfo["nonce"] = powNonce
	voucherID := asString(powInfo["voucher_id"])
	if voucherID == "" {
		voucherID = core.NewUUID()
		powInfo["voucher_id"] = voucherID
	}
	stats := s.server.GetMinerStats(username)
	promiseActive := asBool(stats["fine_promise_active"])
	promiseRemaining := asFloat(stats["fine_promise_amount"])
	if promiseActive && promiseRemaining > 0 {
		if float64(value) <= promiseRemaining {
			s.server.IssueCustodyVoucher(
				value,
				"miner_fine_promise",
				castMap(powInfo),
				map[string]any{"type": "miner_fine_promise", "miner": username},
			)
			newRemaining := promiseRemaining - float64(value)
			if newRemaining < 0 {
				newRemaining = 0
			}
			_, _ = s.server.DB.Exec(`INSERT INTO miner_stats
				(username, fine_promise_amount, fine_promise_active, last_updated)
				VALUES (?, ?, ?, ?)
				ON CONFLICT(username) DO UPDATE SET
					fine_promise_amount = excluded.fine_promise_amount,
					fine_promise_active = excluded.fine_promise_active,
					last_updated = excluded.last_updated`,
				username, newRemaining, intFromBool(newRemaining > 0), nowSec())
			if newRemaining <= 0 {
				s.server.ReleaseWithheldOffersForMiner(username)
				s.emitPendingVoucherOffers(username)
			}
			conn.Emit("hps_voucher_withheld", map[string]any{
				"voucher_id":  voucherID,
				"value":       value,
				"debt_status": s.server.SafeGetMinerDebtStatus(username),
				"mode":        "promise",
			})
			return
		}
		consumeValue := int(promiseRemaining)
		if consumeValue > 0 {
			s.server.IssueCustodyVoucher(
				consumeValue,
				"miner_fine_promise",
				castMap(powInfo),
				map[string]any{"type": "miner_fine_promise", "miner": username},
			)
			value -= consumeValue
		}
		_, _ = s.server.DB.Exec(`INSERT INTO miner_stats
			(username, fine_promise_amount, fine_promise_active, last_updated)
			VALUES (?, 0, 0, ?)
			ON CONFLICT(username) DO UPDATE SET
				fine_promise_amount = 0,
				fine_promise_active = 0,
				last_updated = excluded.last_updated`,
			username, nowSec())
		s.server.ReleaseWithheldOffersForMiner(username)
		s.emitPendingVoucherOffers(username)
	}
	offerStatus := "pending"
	conditions := map[string]any{}
	if suspended {
		offerStatus = "withheld"
		conditions["withheld"] = true
	}
	offer := s.server.CreateVoucherOfferWithStatus(username, client.PublicKey, value, reason, castMap(powInfo), conditions, voucherID, offerStatus)
	if suspended {
		log.Printf("mint withheld sid=%s user=%s reason=suspended debt=%v", conn.ID(), username, debtStatus)
		conn.Emit("hps_voucher_withheld", map[string]any{
			"voucher_id":  offer["voucher_id"],
			"value":       value,
			"debt_status": debtStatus,
		})
		return
	}
	log.Printf("mint offer sid=%s user=%s voucher_id=%s value=%d", conn.ID(), username, asString(offer["voucher_id"]), value)
	conn.Emit("hps_voucher_offer", map[string]any{
		"offer_id":          offer["offer_id"],
		"voucher_id":        offer["voucher_id"],
		"payload":           offer["payload"],
		"payload_canonical": offer["payload_canonical"],
		"expires_at":        offer["expires_at"],
	})
}

func (s *Server) handleConfirmHpsVoucher(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("hps_voucher_error", map[string]any{"error": "Not authenticated"})
		return
	}
	voucherID := asString(data["voucher_id"])
	ownerSignature := asString(data["owner_signature"])
	ownerSignedPayloadText := asString(data["payload_signed_text"])
	if voucherID == "" || ownerSignature == "" {
		conn.Emit("hps_voucher_error", map[string]any{"error": "Missing voucher confirmation data"})
		return
	}
	log.Printf("confirm_hps_voucher sid=%s voucher_id=%s signed_hash=%s signed_present=%t signature_len=%d",
		conn.ID(),
		voucherID,
		core.ShortTextHash(ownerSignedPayloadText),
		strings.TrimSpace(ownerSignedPayloadText) != "",
		len(ownerSignature),
	)
	replayedIssuedVoucher := false
	voucher, finalizeErr := s.server.FinalizeVoucherDetailed(voucherID, ownerSignature, ownerSignedPayloadText)
	if voucher == nil && finalizeErr == "Voucher offer is not pending" {
		existing := s.server.GetVoucherAuditInfo(voucherID)
		if existing != nil {
			signatures := castMap(existing["signatures"])
			if asString(signatures["owner"]) == ownerSignature {
				voucher = map[string]any{
					"voucher_type": "HPS",
					"payload":      castMap(existing["payload"]),
					"signatures":   signatures,
				}
				core.AttachVoucherIntegrity(voucher)
				replayedIssuedVoucher = true
				finalizeErr = ""
			}
		}
	}
	if voucher == nil {
		log.Printf("voucher confirm failed sid=%s voucher_id=%s err=%s", conn.ID(), voucherID, finalizeErr)
		conn.Emit("hps_voucher_error", map[string]any{"error": defaultStr(finalizeErr, "Voucher confirmation failed")})
		return
	}
	log.Printf("voucher issued sid=%s voucher_id=%s owner=%s", conn.ID(), voucherID, asString(castMap(voucher["payload"])["owner"]))
	payload := castMap(voucher["payload"])
	powPayload := castMap(payload["pow"])
	if !replayedIssuedVoucher && asString(powPayload["action_type"]) == "hps_mint" {
		mintedValue := asFloat(payload["value"])
		newValue := s.server.GetEconomyStat("total_minted", 0.0) + mintedValue
		s.server.SetEconomyStat("total_minted", newValue)
		s.server.RecordEconomyEvent("hps_mint")
		contractID := s.server.RecordEconomyContract("hps_mint")
		minerUsername := asString(payload["owner"])
		pending := s.server.IncrementMinerMint(minerUsername, mintedValue)
		s.emitToUser(minerUsername, "miner_signature_update", map[string]any{
			"pending_signatures": pending,
			"debt_status":        s.server.SafeGetMinerDebtStatus(minerUsername),
		})
		s.server.SaveServerContract("hps_mint_receipt", []core.ContractDetail{
			{Key: "MINER", Value: asString(payload["owner"])},
			{Key: "VOUCHER_ID", Value: asString(payload["voucher_id"])},
			{Key: "VALUE", Value: asInt(payload["value"])},
			{Key: "POW_CHALLENGE", Value: asString(powPayload["challenge"])},
			{Key: "POW_NONCE", Value: asString(powPayload["nonce"])},
			{Key: "TARGET_BITS", Value: asInt(powPayload["target_bits"])},
			{Key: "TARGET_SECONDS", Value: asFloat(powPayload["target_seconds"])},
			{Key: "ACTION", Value: asString(powPayload["action_type"])},
		}, asString(payload["voucher_id"]))
		conn.Emit("economy_report", s.server.BuildEconomyReport())
		conn.Emit("hps_economy_status", s.getHpsEconomyStatusPayload())
		if contractID != "" {
			conn.Emit("economy_contract_update", map[string]any{
				"contract_id": contractID,
				"reason":      "hps_mint",
				"timestamp":   nowSec(),
			})
		}
	}
	transfer := s.server.GetTransferByVoucherID(voucherID)
	if transfer != nil && asString(transfer["status"]) == "pending_signature" {
		s.server.LockTransferVouchers(asString(transfer["transfer_id"]))
	}
	session := s.server.GetHpsTransferSessionByVoucher(voucherID)
	if session != nil {
		payer := asString(session["payer"])
		target := asString(session["target"])
		s.server.CompleteHpsTransfer(voucherID)
		if payer != "" {
			s.emitWalletSyncToUser(payer)
		}
		if target != "" {
			s.emitWalletSyncToUser(target)
		}
	}
	conn.Emit("hps_voucher_issued", map[string]any{"voucher": voucher})
	s.emitWalletSyncToConn(conn, client.Username)
}

func (s *Server) handleRequestUsageContract(conn socketio.Conn, data map[string]any) {
	log.Printf("event request_usage_contract sid=%s user=%s", conn.ID(), asString(data["username"]))
	client, ok := s.getClient(conn.ID())
	if !ok || !client.ServerAuthenticated {
		conn.Emit("usage_contract_status", map[string]any{"success": false, "error": "Server not authenticated"})
		return
	}
	username := trim(asString(data["username"]))
	if username == "" {
		conn.Emit("usage_contract_status", map[string]any{"success": false, "error": "Missing username"})
		return
	}
	if username == core.CustodyUsername {
		conn.Emit("usage_contract_status", map[string]any{"success": false, "error": "O nome de usuÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡rio \"custody\" ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â© de uso especial para a administraÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o do servidor."})
		return
	}
	text, hash := s.server.LoadUsageContractTemplate()
	if s.server.UserNeedsUsageContract(username) {
		conn.Emit("usage_contract_required", map[string]any{"contract_text": text, "contract_hash": hash})
		return
	}
	conn.Emit("usage_contract_status", map[string]any{"success": true, "required": false})
}

func (s *Server) handleAcceptUsageContract(conn socketio.Conn, data map[string]any) {
	log.Printf("event accept_usage_contract sid=%s user=%s deferred=%t nonce_present=%t", conn.ID(), asString(data["username"]), asBool(data["_deferred_payment"]), trim(asString(data["pow_nonce"])) != "")
	emitAck := func(payload map[string]any) {
		log.Printf("emit usage_contract_ack sid=%s payload=%v", conn.ID(), payload)
		conn.Emit("usage_contract_ack", payload)
	}
	deferred := asBool(data["_deferred_payment"])
	clientIdentifier := ""
	username := ""
	publicKeyFromClient := ""
	if deferred {
		clientIdentifier = asString(data["_deferred_client_identifier"])
		username = asString(data["_deferred_username"])
		publicKeyFromClient = asString(data["_deferred_public_key"])
	} else {
		client, ok := s.getClient(conn.ID())
		if !ok || !client.ServerAuthenticated {
			emitAck(map[string]any{"success": false, "error": "Server not authenticated"})
			return
		}
		clientIdentifier = asString(data["client_identifier"])
		if clientIdentifier == "" {
			clientIdentifier = client.ClientIdentifier
		}
		if clientIdentifier == "" {
			emitAck(map[string]any{"success": false, "error": "Missing client identifier"})
			return
		}
		username = asString(data["username"])
		if username == "" {
			username = client.Username
		}
		publicKeyFromClient = asString(data["public_key"])
		if publicKeyFromClient == "" {
			publicKeyFromClient = client.PublicKey
		}
	}
	powNonce := asString(data["pow_nonce"])
	hashrateObserved := asFloat(data["hashrate_observed"])
	hpsPayment := castMap(data["hps_payment"])
	contractContentB64 := asString(data["contract_content"])
	publicKeyB64 := asString(data["public_key"])
	if publicKeyB64 == "" {
		publicKeyB64 = publicKeyFromClient
	}
	if contractContentB64 == "" {
		emitAck(map[string]any{"success": false, "error": "Missing contract content"})
		return
	}
	if publicKeyB64 == "" {
		emitAck(map[string]any{"success": false, "error": "Missing public key"})
		return
	}
	contractBytes, err := base64.StdEncoding.DecodeString(contractContentB64)
	if err != nil {
		emitAck(map[string]any{"success": false, "error": "Invalid contract content"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractBytes)
	if !valid || contractInfo == nil {
		emitAck(map[string]any{"success": false, "error": "Invalid contract: " + errMsg})
		return
	}
	if contractInfo.Action != "accept_usage" {
		emitAck(map[string]any{"success": false, "error": "Invalid usage contract action"})
		return
	}
	username = contractInfo.User
	var storedKey string
	_ = s.server.DB.QueryRow(`SELECT public_key FROM users WHERE username = ?`, username).Scan(&storedKey)
	if storedKey != "" && storedKey != core.PendingPublicKeyLabel && storedKey != publicKeyB64 {
		s.server.RemoveUsageContractForUser(username)
		emitAck(map[string]any{
			"success": false,
			"error":   "Chave PÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Âºblica invÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡lida, utilize sua chave pÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Âºblica inicial na aba de configuraÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Âµes",
		})
		return
	}
	if !s.server.VerifyContractSignature(contractBytes, username, contractInfo.Signature, publicKeyB64) {
		emitAck(map[string]any{"success": false, "error": "Invalid contract signature"})
		return
	}
	_, templateHash := s.server.LoadUsageContractTemplate()
	contractText := string(contractBytes)
	if !strings.Contains(contractText, "# USAGE_CONTRACT_HASH: "+templateHash) {
		emitAck(map[string]any{"success": false, "error": "Usage contract version mismatch"})
		return
	}
	if !deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			clientIdentifier, username, "usage_contract", powNonce, hashrateObserved, hpsPayment,
		)
		if !okAuth {
			emitAck(map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(clientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{"data": data, "payment": pendingInfo, "public_key": publicKeyFromClient}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "accept_usage_contract", username, clientIdentifier, payload, "usage_contract_ack")
			return
		}
	}
	if !s.server.AcceptUsageContract(username, templateHash, contractBytes, contractInfo.Signature) {
		emitAck(map[string]any{"success": false, "error": "Usage contract hash mismatch"})
		return
	}
	if len(hpsPayment) > 0 {
		s.emitWalletSyncToUser(username)
	}
	emitAck(map[string]any{"success": true, "deferred_payment": deferred})
}

func (s *Server) handleJoinNetwork(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("network_joined", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	nodeID := trim(asString(data["node_id"]))
	address := trim(asString(data["address"]))
	publicKey := trim(asString(data["public_key"]))
	nodeType := trim(asString(data["node_type"]))
	if nodeType == "" {
		nodeType = "client"
	}
	if nodeID == "" || address == "" || publicKey == "" {
		conn.Emit("network_joined", map[string]any{"success": false, "error": "Missing node data"})
		return
	}
	if err := core.ValidatePublicKeyValue(publicKey); err != nil {
		conn.Emit("network_joined", map[string]any{"success": false, "error": "Invalid public key: " + err.Error()})
		return
	}
	client.Address = address
	client.NodeID = nodeID
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO network_nodes
		(node_id, address, public_key, username, last_seen, reputation, node_type, is_online, client_identifier, connection_count)
		VALUES (?, ?, ?, ?, ?, COALESCE((SELECT reputation FROM network_nodes WHERE node_id = ?), 100), ?, 1, ?, COALESCE((SELECT connection_count + 1 FROM network_nodes WHERE node_id = ?), 1))`,
		nodeID, address, publicKey, client.Username, nowSec(), nodeID, nodeType, client.ClientIdentifier, nodeID)
	conn.Emit("network_joined", map[string]any{"success": true})
	s.broadcastNetworkState()
}

func (s *Server) handleReportContent(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "report_result")
	if !ok {
		return
	}
	clientIdentifier := actx.ClientIdentifier
	powNonce := asString(data["pow_nonce"])
	hashrateObserved := asFloat(data["hashrate_observed"])
	hpsPayment := castMap(data["hps_payment"])
	contentHash := trim(asString(data["content_hash"]))
	reportedUser := trim(asString(data["reported_user"]))
	contractContentB64 := asString(data["contract_content"])
	if contentHash == "" || reportedUser == "" || contractContentB64 == "" {
		conn.Emit("report_result", map[string]any{"success": false, "error": "Missing report data"})
		return
	}
	contractBytes, err := base64.StdEncoding.DecodeString(contractContentB64)
	if err != nil {
		conn.Emit("report_result", map[string]any{"success": false, "error": "Invalid contract content"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractBytes)
	if !valid || contractInfo == nil {
		conn.Emit("report_result", map[string]any{"success": false, "error": "Invalid contract: " + errMsg})
		return
	}
	if contractInfo.Action != "report_content" {
		conn.Emit("report_result", map[string]any{"success": false, "error": "Invalid contract action"})
		return
	}
	if contractInfo.User != actx.Username {
		conn.Emit("report_result", map[string]any{"success": false, "error": "Contract user mismatch"})
		return
	}
	if !s.server.VerifyContractSignature(contractBytes, actx.Username, contractInfo.Signature, "") {
		conn.Emit("report_result", map[string]any{"success": false, "error": "Invalid contract signature"})
		return
	}
	if !actx.Deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			clientIdentifier, actx.Username, "report", powNonce, hashrateObserved, hpsPayment,
		)
		if !okAuth {
			conn.Emit("report_result", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(clientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{"data": data, "payment": pendingInfo, "public_key": actx.PublicKey}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "report_content", actx.Username, clientIdentifier, payload, "report_result")
			return
		}
	}
	reportID := core.NewUUID()
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO content_reports
		(report_id, content_hash, reported_user, reporter, timestamp, resolved, resolution_type)
		VALUES (?, ?, ?, ?, ?, 0, '')`,
		reportID, contentHash, reportedUser, actx.Username, nowSec())
	s.server.SaveContract("report_content", contentHash, "", actx.Username, contractInfo.Signature, contractBytes)
	s.processContentReport(reportID, contentHash, reportedUser, actx.Username)
	if len(hpsPayment) > 0 {
		s.emitWalletSyncToUser(actx.Username)
	}
	conn.Emit("report_result", map[string]any{"success": true, "report_id": reportID})
}

func (s *Server) handleSyncServers(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	servers := toStringSlice(data["servers"])
	for _, addr := range servers {
		addr = trim(addr)
		if addr == "" || core.MessageServerAddressesEqual(addr, s.server.Address, s.server.BindAddress) {
			continue
		}
		addr = core.NormalizeMessageServerAddress(addr)
		if addr == "" {
			continue
		}
		log.Printf("sync_servers: learned known server=%s from client=%s", addr, client.ClientIdentifier)
		_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO known_servers (address, added_date, last_connected, is_active) VALUES (?, ?, ?, 1)`, addr, nowSec(), nowSec())
		go s.server.SyncWithServer(addr)
	}
	s.handleGetServers(conn, nil)
}

func (s *Server) handleRequestInventory(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("inventory_response", map[string]any{"error": "Not authenticated"})
		return
	}
	targetUser := trim(asString(data["target_user"]))
	requestID := trim(asString(data["request_id"]))
	if requestID == "" {
		requestID = core.NewUUID()
	}
	if targetUser == "" {
		conn.Emit("inventory_response", map[string]any{"error": "Missing target user"})
		return
	}
	if _, ok := s.getAuthenticatedConnByUsername(targetUser); !ok {
		conn.Emit("inventory_response", map[string]any{
			"error":      fmt.Sprintf("UsuÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡rio %s nÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o estÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ online", targetUser),
			"request_id": requestID,
		})
		return
	}
	s.mu.Lock()
	s.pendingInventoryRequests[requestID] = inventoryRequestInfo{
		Requester:    client.Username,
		RequesterSID: conn.ID(),
		TargetUser:   targetUser,
	}
	s.mu.Unlock()
	s.emitToUser(targetUser, "inventory_request", map[string]any{
		"request_id": requestID,
		"requester":  client.Username,
	})
}

func (s *Server) handleInventoryResponse(conn socketio.Conn, data map[string]any) {
	requestID := trim(asString(data["request_id"]))
	if requestID == "" {
		return
	}
	s.mu.Lock()
	requestInfo, ok := s.pendingInventoryRequests[requestID]
	if ok {
		delete(s.pendingInventoryRequests, requestID)
	}
	requesterConn := s.conns[requestInfo.RequesterSID]
	s.mu.Unlock()
	if !ok {
		return
	}
	payload := map[string]any{
		"request_id":       requestID,
		"target_user":      requestInfo.TargetUser,
		"inventory_public": asBool(data["inventory_public"]),
		"published":        defaultSlice(data["published"]),
		"local":            defaultSlice(data["local"]),
	}
	if requesterConn != nil {
		requesterConn.Emit("inventory_response", payload)
		return
	}
	s.emitToUser(requestInfo.Requester, "inventory_response", payload)
}

func (s *Server) handleRequestInventoryTransfer(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "inventory_transfer_ack")
	if !ok {
		return
	}
	targetUser := trim(asString(data["target_user"]))
	contentHash := trim(asString(data["content_hash"]))
	if targetUser == "" || contentHash == "" {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Missing target or content"})
		return
	}
	if strings.EqualFold(targetUser, actx.Username) {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Cannot request own inventory item"})
		return
	}
	if _, ok := s.getAuthenticatedConnByUsername(targetUser); !ok {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": fmt.Sprintf("UsuÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡rio %s nÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o estÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¡ online", targetUser)})
		return
	}
	if !actx.Deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			actx.ClientIdentifier, actx.Username, "inventory_transfer", asString(data["pow_nonce"]), asFloat(data["hashrate_observed"]), castMap(data["hps_payment"]),
		)
		if !okAuth {
			conn.Emit("inventory_transfer_ack", map[string]any{"error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(actx.ClientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{
				"data":    data,
				"payment": pendingInfo,
			}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "request_inventory_transfer", actx.Username, actx.ClientIdentifier, payload, "inventory_transfer_ack")
			return
		}
	}
	requestPayload := map[string]any{
		"title":       asString(data["title"]),
		"description": asString(data["description"]),
		"mime_type":   asString(data["mime_type"]),
		"size":        asInt(data["size"]),
	}
	transferID := createPendingTransferWithRequest(
		s.server.DB,
		"inventory",
		targetUser,
		targetUser,
		contentHash,
		"",
		"",
		"",
		actx.Username,
		requestPayload,
	)
	s.emitToUser(targetUser, "inventory_transfer_request", map[string]any{
		"transfer_id":  transferID,
		"requester":    actx.Username,
		"content_hash": contentHash,
		"title":        asString(requestPayload["title"]),
		"description":  asString(requestPayload["description"]),
		"mime_type":    asString(requestPayload["mime_type"]),
		"size":         asInt(requestPayload["size"]),
	})
	conn.Emit("inventory_transfer_ack", map[string]any{
		"success":     true,
		"transfer_id": transferID,
		"message":     fmt.Sprintf("SolicitaÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o enviada para %s.", targetUser),
	})
}

func (s *Server) handleAcceptInventoryTransfer(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Not authenticated"})
		return
	}
	transferID := trim(asString(data["transfer_id"]))
	if transferID == "" {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Missing transfer ID"})
		return
	}
	transfer, ok := s.getPendingTransfer(transferID)
	if !ok || asString(transfer["transfer_type"]) != "inventory" {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Transfer not found"})
		return
	}
	if !strings.EqualFold(asString(transfer["target_user"]), client.Username) {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Unauthorized"})
		return
	}
	requester := trim(asString(transfer["requester_user"]))
	contentHash := trim(asString(transfer["content_hash"]))
	if requester == "" || contentHash == "" {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Transfer data invalid"})
		return
	}
	_, _ = s.server.DB.Exec(`UPDATE pending_transfers SET status = ? WHERE transfer_id = ?`, "approved", transferID)
	s.sendInventoryPayloadToRequester(requester, contentHash, transfer)
	_, _ = s.server.DB.Exec(`DELETE FROM pending_transfers WHERE transfer_id = ?`, transferID)
	conn.Emit("inventory_transfer_ack", map[string]any{"success": true})
}

func (s *Server) handleRejectInventoryTransfer(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Not authenticated"})
		return
	}
	transferID := trim(asString(data["transfer_id"]))
	if transferID == "" {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Missing transfer ID"})
		return
	}
	transfer, ok := s.getPendingTransfer(transferID)
	if !ok || asString(transfer["transfer_type"]) != "inventory" {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Transfer not found"})
		return
	}
	if !strings.EqualFold(asString(transfer["target_user"]), client.Username) {
		conn.Emit("inventory_transfer_ack", map[string]any{"error": "Unauthorized"})
		return
	}
	requester := trim(asString(transfer["requester_user"]))
	_, _ = s.server.DB.Exec(`UPDATE pending_transfers SET status = ? WHERE transfer_id = ?`, "rejected", transferID)
	_, _ = s.server.DB.Exec(`DELETE FROM pending_transfers WHERE transfer_id = ?`, transferID)
	if requester != "" {
		s.emitToUser(requester, "inventory_transfer_rejected", map[string]any{
			"transfer_id": transferID,
			"reason":      "rejected",
		})
	}
	conn.Emit("inventory_transfer_ack", map[string]any{"success": true})
}

func (s *Server) sendInventoryPayloadToRequester(requester, contentHash string, transfer map[string]any) {
	if requester == "" || contentHash == "" {
		return
	}
	requesterConn, _ := s.getAuthenticatedConnByUsername(requester)
	requesterSID := ""
	if requesterConn != nil {
		requesterSID = requesterConn.ID()
	}
	owner := asString(transfer["target_user"])
	s.mu.Lock()
	s.pendingInventoryDeliveries[contentHash] = append(s.pendingInventoryDeliveries[contentHash], inventoryDelivery{
		Requester:    requester,
		RequesterSID: requesterSID,
		TransferID:   asString(transfer["transfer_id"]),
		Owner:        owner,
	})
	s.mu.Unlock()
	filePath := s.server.ContentPath(contentHash)
	if _, err := os.Stat(filePath); err != nil {
		if owner != "" {
			s.emitToUser(owner, "request_content_from_client", map[string]any{"content_hash": contentHash})
		}
		return
	}
	s.dispatchInventoryDeliveries(contentHash)
}

func (s *Server) dispatchInventoryDeliveries(contentHash string) {
	if contentHash == "" {
		return
	}
	s.mu.Lock()
	pending := s.pendingInventoryDeliveries[contentHash]
	delete(s.pendingInventoryDeliveries, contentHash)
	s.mu.Unlock()
	if len(pending) == 0 {
		return
	}
	filePath := s.server.ContentPath(contentHash)
	content, err := s.server.ReadEncryptedFile(filePath)
	if err != nil {
		return
	}
	var title, description, mimeType, username, signature, publicKey string
	err = s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key
		FROM content WHERE content_hash = ?`, contentHash).
		Scan(&title, &description, &mimeType, &username, &signature, &publicKey)
	if err != nil {
		return
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	payload := map[string]any{
		"content_hash": contentHash,
		"content_b64":  base64.StdEncoding.EncodeToString(content),
		"title":        title,
		"description":  description,
		"mime_type":    mimeType,
		"signature":    signature,
		"public_key":   publicKey,
		"owner":        username,
	}
	for _, entry := range pending {
		if entry.RequesterSID != "" {
			s.mu.Lock()
			conn := s.conns[entry.RequesterSID]
			s.mu.Unlock()
			if conn != nil {
				conn.Emit("inventory_transfer_payload", payload)
				continue
			}
		}
		if entry.Requester != "" {
			s.emitToUser(entry.Requester, "inventory_transfer_payload", payload)
		}
	}
}

func (s *Server) handleUserActivity(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	_, _ = s.server.DB.Exec(`UPDATE users SET last_activity = ? WHERE username = ?`, nowSec(), client.Username)
}

func (s *Server) handleServerPing(conn socketio.Conn, data map[string]any) {
	conn.Emit("server_pong", map[string]any{
		"success":    true,
		"server_id":  s.server.ServerID,
		"address":    s.server.Address,
		"public_key": base64.StdEncoding.EncodeToString(s.server.PublicKeyPEM),
		"timestamp":  nowSec(),
	})
}

func (s *Server) handleGetBackupServer(conn socketio.Conn, data map[string]any) {
	var address string
	_ = s.server.DB.QueryRow(`SELECT address FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC, last_seen DESC LIMIT 1`, s.server.Address).Scan(&address)
	if address == "" {
		conn.Emit("backup_server", map[string]any{"success": false, "error": "No backup server available"})
		return
	}
	conn.Emit("backup_server", map[string]any{"success": true, "address": address})
}

func (s *Server) handleRequestVoucherAudit(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("voucher_audit", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	voucherIDs := toStringSlice(data["voucher_ids"])
	requestID := asString(data["request_id"])
	if requestID == "" {
		requestID = core.NewUUID()
	}
	transferID := asString(data["transfer_id"])
	if transferID != "" {
		s.server.ExtendMinerDeadline(transferID, 6.0)
	}
	results := []map[string]any{}
	missing := []string{}
	for _, id := range voucherIDs {
		info := s.server.GetVoucherAuditInfo(id)
		if info != nil {
			info["issuer_server"] = s.server.Address
			info["issuer_server_key"] = base64.StdEncoding.EncodeToString(s.server.PublicKeyPEM)
			results = append(results, info)
		} else if id != "" {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		rows, err := s.server.DB.Query(`SELECT address FROM server_nodes WHERE is_active = 1 ORDER BY reputation DESC`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				if len(missing) == 0 {
					break
				}
				var serverAddr string
				if rows.Scan(&serverAddr) != nil || serverAddr == "" {
					continue
				}
				if serverAddr == s.server.Address || serverAddr == s.server.BindAddress {
					continue
				}
				okRemote, payload, _ := s.server.MakeRemoteRequestJSON(serverAddr, "/voucher/audit", http.MethodPost, map[string]any{
					"voucher_ids": missing,
				})
				if !okRemote || payload == nil || !asBool(payload["success"]) {
					continue
				}
				remoteVouchers := castSliceMap(payload["vouchers"])
				if len(remoteVouchers) == 0 {
					continue
				}
				found := map[string]bool{}
				for _, info := range remoteVouchers {
					vid := asString(info["voucher_id"])
					if vid == "" {
						continue
					}
					results = append(results, info)
					found[vid] = true
				}
				remaining := []string{}
				for _, vid := range missing {
					if !found[vid] {
						remaining = append(remaining, vid)
					}
				}
				missing = remaining
			}
		}
	}
	conn.Emit("voucher_audit", map[string]any{"success": true, "request_id": requestID, "vouchers": results})
}

func (s *Server) handleSearchContracts(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		payload := map[string]any{"success": false, "error": "Not authenticated"}
		conn.Emit("contracts_results", payload)
		return
	}
	queryType := trim(asString(data["search_type"]))
	queryValue := trim(asString(data["search_value"]))
	requestID := trim(asString(data["request_id"]))
	limit := asInt(data["limit"])
	offset := asInt(data["offset"])
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	whereClause := ""
	countParams := []any{}
	sqlQuery := `SELECT contract_id, action_type, COALESCE(content_hash,''), COALESCE(domain,''), username, signature, timestamp, verified, contract_content FROM contracts`
	params := []any{}
	switch queryType {
	case "hash":
		whereClause = " WHERE content_hash LIKE ?"
		countParams = append(countParams, "%"+queryValue+"%")
	case "domain":
		whereClause = " WHERE domain LIKE ?"
		countParams = append(countParams, "%"+queryValue+"%")
	case "user":
		whereClause = " WHERE username LIKE ?"
		countParams = append(countParams, "%"+queryValue+"%")
	case "type":
		whereClause = " WHERE action_type = ?"
		countParams = append(countParams, queryValue)
	case "title":
		whereClause = " WHERE LOWER(COALESCE(contract_content, '')) LIKE LOWER(?)"
		countParams = append(countParams, "%"+queryValue+"%")
	case "api_app":
		whereClause = " WHERE LOWER(COALESCE(contract_content, '')) LIKE LOWER(?)"
		countParams = append(countParams, "%# app: "+queryValue+"%")
	default:
		if queryValue != "" {
			whereClause = ` WHERE (
LOWER(contract_id) LIKE LOWER(?) OR
LOWER(action_type) LIKE LOWER(?) OR
LOWER(COALESCE(content_hash, '')) LIKE LOWER(?) OR
LOWER(COALESCE(domain, '')) LIKE LOWER(?) OR
LOWER(username) LIKE LOWER(?) OR
LOWER(COALESCE(contract_content, '')) LIKE LOWER(?)
)`
			likeValue := "%" + queryValue + "%"
			countParams = append(countParams, likeValue, likeValue, likeValue, likeValue, likeValue, likeValue)
		}
	}
	sqlQuery += whereClause + " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	params = append(params, countParams...)
	params = append(params, limit, offset)
	total := 0
	countQuery := "SELECT COUNT(1) FROM contracts" + whereClause
	if err := s.server.DB.QueryRow(countQuery, countParams...).Scan(&total); err != nil {
		payload := map[string]any{"success": false, "error": err.Error(), "request_id": requestID}
		conn.Emit("contracts_results", payload)
		return
	}
	rows, err := s.server.DB.Query(sqlQuery, params...)
	if err != nil {
		payload := map[string]any{"success": false, "error": err.Error(), "request_id": requestID}
		conn.Emit("contracts_results", payload)
		return
	}
	defer rows.Close()
	contracts := []map[string]any{}
	for rows.Next() {
		var contractID, actionType, contentHash, domain, username, signature, contractContent string
		var timestamp float64
		var verified int
		if err := rows.Scan(&contractID, &actionType, &contentHash, &domain, &username, &signature, &timestamp, &verified, &contractContent); err == nil {
			if core.ShouldHideReplicatedContract(username, verified != 0) {
				continue
			}
			violation := map[string]any(nil)
			if contentHash != "" {
				violation = s.server.GetContractViolation("content", contentHash, "")
			}
			if violation == nil && domain != "" {
				violation = s.server.GetContractViolation("domain", "", domain)
			}
			integrityOK := verified != 0 && violation == nil
			violationReason := ""
			if violation != nil {
				violationReason = asString(violation["reason"])
			}
			contracts = append(contracts, map[string]any{
				"contract_id":      contractID,
				"action_type":      actionType,
				"content_hash":     contentHash,
				"domain":           domain,
				"username":         username,
				"signature":        signature,
				"timestamp":        timestamp,
				"verified":         verified != 0,
				"integrity_ok":     integrityOK,
				"violation_reason": violationReason,
				"contract_content": contractContent,
			})
		}
	}
	payload := map[string]any{"success": true, "contracts": contracts, "total": total, "limit": limit, "offset": offset, "request_id": requestID}
	conn.Emit("contracts_results", payload)
}

func (s *Server) handleGetContract(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		payload := map[string]any{"success": false, "error": "Not authenticated"}
		conn.Emit("contract_details", payload)
		return
	}
	contractID := trim(asString(data["contract_id"]))
	if contractID == "" {
		conn.Emit("contract_details", map[string]any{"success": false, "error": "Missing contract ID"})
		return
	}
	var actionType, contentHash, domain, contractUser, signature, contentB64 string
	var timestamp float64
	var verifiedDB int
	err := s.server.DB.QueryRow(`SELECT action_type, COALESCE(content_hash, ''), COALESCE(domain, ''), username, signature, timestamp, verified, COALESCE(contract_content, '')
		FROM contracts WHERE contract_id = ? LIMIT 1`, contractID).
		Scan(&actionType, &contentHash, &domain, &contractUser, &signature, &timestamp, &verifiedDB, &contentB64)
	if err != nil {
		if s.fetchContractFromNetwork(contractID) {
			err = s.server.DB.QueryRow(`SELECT action_type, COALESCE(content_hash, ''), COALESCE(domain, ''), username, signature, timestamp, verified, COALESCE(contract_content, '')
				FROM contracts WHERE contract_id = ? LIMIT 1`, contractID).
				Scan(&actionType, &contentHash, &domain, &contractUser, &signature, &timestamp, &verifiedDB, &contentB64)
		}
	}
	if err != nil {
		payload := map[string]any{"success": false, "error": "Contract not found"}
		conn.Emit("contract_details", payload)
		return
	}
	content := s.server.GetContractBytes(contractID)
	if len(content) == 0 && contentB64 != "" {
		if decoded, decErr := base64.StdEncoding.DecodeString(contentB64); decErr == nil {
			content = decoded
		}
	}
	if len(content) == 0 {
		payload := map[string]any{"success": false, "error": "Contract not found"}
		conn.Emit("contract_details", payload)
		return
	}
	verified := verifiedDB != 0
	integrityOK := verified
	violationReason := ""
	validContract, _, contractInfo := core.ValidateContractStructure(content)
	if validContract && contractInfo != nil {
		verifyKey := s.server.GetUserPublicKey(contractInfo.User)
		if contractInfo.Action == "hps_exchange_reserved" || contractInfo.Action == "hps_exchange_out" || contractInfo.Action == "hps_exchange_owner_key" {
			issuer := core.ExtractContractDetail(contractInfo, "ISSUER")
			if issuer != "" {
				var serverKey string
				_ = s.server.DB.QueryRow(`SELECT public_key FROM server_nodes WHERE address = ? LIMIT 1`, issuer).Scan(&serverKey)
				if serverKey != "" {
					verifyKey = serverKey
				}
			}
		}
		verified = s.server.VerifyContractSignature(content, contractInfo.User, contractInfo.Signature, verifyKey)
		contractUser = contractInfo.User
		signature = contractInfo.Signature
	}
	if !validContract {
		verified = false
		integrityOK = false
		if domain != "" {
			s.registerContractViolation("domain", "", domain, "invalid_contract", "system", contractUser, false)
		} else if contentHash != "" {
			s.registerContractViolation("content", contentHash, "", "invalid_contract", "system", contractUser, false)
		}
		violationReason = "invalid_contract"
	} else if !verified {
		integrityOK = false
		if domain != "" {
			s.registerContractViolation("domain", "", domain, "invalid_signature", "system", contractUser, false)
		} else if contentHash != "" {
			s.registerContractViolation("content", contentHash, "", "invalid_signature", "system", contractUser, false)
		}
		violationReason = "invalid_signature"
	} else {
		if domain != "" {
			s.clearContractViolation("domain", domain)
			s.server.SaveContractArchive("domain", domain, content)
		} else if contentHash != "" {
			s.clearContractViolation("content", contentHash)
			s.server.SaveContractArchive("content", contentHash, content)
		}
	}
	_, _ = s.server.DB.Exec(`UPDATE contracts SET contract_content = ?, verified = ?, username = ?, signature = ? WHERE contract_id = ?`,
		base64.StdEncoding.EncodeToString(content), intFromBool(verified), contractUser, signature, contractID)
	if violationReason == "" {
		violation := map[string]any(nil)
		if contentHash != "" {
			violation = s.server.GetContractViolation("content", contentHash, "")
		}
		if violation == nil && domain != "" {
			violation = s.server.GetContractViolation("domain", "", domain)
		}
		if violation != nil {
			integrityOK = false
			violationReason = asString(violation["reason"])
		} else {
			integrityOK = verified
		}
	}
	contractPayload := map[string]any{
		"contract_id":      contractID,
		"action_type":      actionType,
		"content_hash":     contentHash,
		"domain":           domain,
		"username":         contractUser,
		"signature":        signature,
		"timestamp":        timestamp,
		"verified":         verified,
		"integrity_ok":     integrityOK,
		"violation_reason": violationReason,
		"contract_content": string(content),
	}
	conn.Emit("contract_details", map[string]any{"success": true, "contract": contractPayload})
}

func (s *Server) handleGetPendingTransfers(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("pending_transfers", map[string]any{"error": "Not authenticated"})
		return
	}
	transfers := listPendingTransfersForUser(s.server.DB, client.Username)
	conn.Emit("pending_transfers", map[string]any{"transfers": transfers})
	conn.Emit("pending_transfer_notice", map[string]any{"count": len(transfers)})
}

func (s *Server) handleGetMinerTransfer(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("miner_transfer", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	transferID := trim(asString(data["transfer_id"]))
	if transferID == "" {
		conn.Emit("miner_transfer", map[string]any{"success": false, "error": "Missing transfer ID"})
		return
	}
	transfer, found := s.getMonetaryTransfer(transferID)
	if !found {
		conn.Emit("miner_transfer", map[string]any{"success": false, "error": "Transfer not found"})
		return
	}
	assigned := asString(transfer["assigned_miner"])
	status := asString(transfer["status"])
	if assigned != client.Username {
		conn.Emit("miner_transfer", map[string]any{"success": false, "error": "Miner not assigned"})
		return
	}
	if status != "pending_signature" && status != "signed" {
		conn.Emit("miner_transfer", map[string]any{"success": false, "error": "Transfer not signable"})
		return
	}
	conn.Emit("miner_transfer", map[string]any{
		"success":  true,
		"transfer": transfer,
	})
}

func (s *Server) handleGetMinerPendingTransfers(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("miner_pending_transfers", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	rows, err := s.server.DB.Query(`SELECT transfer_id
		FROM monetary_transfers
		WHERE assigned_miner = ? AND status = ?
		ORDER BY created_at DESC LIMIT 200`, client.Username, "pending_signature")
	if err != nil {
		conn.Emit("miner_pending_transfers", map[string]any{"success": false, "error": "Failed to query transfers"})
		return
	}
	defer rows.Close()
	transfers := make([]map[string]any, 0)
	for rows.Next() {
		var transferID string
		if rows.Scan(&transferID) != nil || transferID == "" {
			continue
		}
		transfer, found := s.getMonetaryTransfer(transferID)
		if !found {
			continue
		}
		if asString(transfer["assigned_miner"]) != client.Username {
			continue
		}
		if asString(transfer["status"]) != "pending_signature" {
			continue
		}
		transfers = append(transfers, transfer)
	}
	conn.Emit("miner_pending_transfers", map[string]any{
		"success":   true,
		"transfers": transfers,
	})
}

func (s *Server) handleGetTransferPayload(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("transfer_payload", map[string]any{"error": "Not authenticated"})
		return
	}
	transferID := asString(data["transfer_id"])
	if transferID == "" {
		conn.Emit("transfer_payload", map[string]any{"error": "Missing transfer ID"})
		return
	}
	transfer, found := s.getPendingTransfer(transferID)
	if !found {
		conn.Emit("transfer_payload", map[string]any{"error": "Transfer not found"})
		return
	}
	if asString(transfer["target_user"]) != client.Username {
		conn.Emit("transfer_payload", map[string]any{"error": "Unauthorized"})
		return
	}
	contentHash := asString(transfer["content_hash"])
	if contentHash == "" {
		contractID := asString(transfer["contract_id"])
		if contractID != "" {
			_ = s.server.DB.QueryRow(`SELECT content_hash FROM contracts WHERE contract_id = ?`, contractID).Scan(&contentHash)
		}
	}
	if contentHash == "" {
		conn.Emit("transfer_payload", map[string]any{"error": "Missing content hash"})
		return
	}
	filePath := s.server.ContentPath(contentHash)
	if _, err := os.Stat(filePath); err != nil {
		conn.Emit("transfer_payload", map[string]any{"error": "Transfer file not found"})
		return
	}
	content, err := s.server.ReadFile(filePath)
	if err != nil {
		conn.Emit("transfer_payload", map[string]any{"error": "Transfer file not found"})
		return
	}
	content, _ = core.ExtractContractFromContent(content)
	var title, description, mimeType string
	_ = s.server.DB.QueryRow(`SELECT title, description, mime_type FROM content WHERE content_hash = ?`, contentHash).Scan(&title, &description, &mimeType)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	conn.Emit("transfer_payload", map[string]any{
		"transfer_id":  transferID,
		"content_hash": contentHash,
		"title":        title,
		"description":  description,
		"mime_type":    mimeType,
		"content_b64":  base64.StdEncoding.EncodeToString(content),
	})
}

func (s *Server) handleSignTransfer(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("miner_signature_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	username := client.Username
	transferID := trim(asString(data["transfer_id"]))
	contractB64 := asString(data["contract_content"])
	reportB64 := asString(data["report_content"])
	if transferID == "" || contractB64 == "" || reportB64 == "" {
		conn.Emit("miner_signature_ack", map[string]any{"success": false, "error": "Missing signature data"})
		return
	}
	log.Printf("sign_transfer: received transfer=%s miner=%s contract_b64=%d report_b64=%d", transferID, username, len(contractB64), len(reportB64))
	conn.Emit("miner_signature_ack", map[string]any{
		"success":     true,
		"pending":     true,
		"queued":      true,
		"transfer_id": transferID,
		"message":     "Assinatura recebida pelo servidor. Processando.",
	})
	payload := map[string]any{
		"transfer_id":       transferID,
		"miner":             username,
		"contract_content":  contractB64,
		"report_content":    reportB64,
		"received_at":       nowSec(),
		"client_identifier": client.ClientIdentifier,
	}
	actionID := s.server.CreatePendingMonetaryAction(transferID, "settle_miner_signature", username, client.ClientIdentifier, payload, "miner_signature_ack")
	result, err := s.server.DB.Exec(`UPDATE monetary_transfers
		SET status = ?, miner_deadline = NULL
		WHERE transfer_id = ? AND assigned_miner = ? AND status = ?`, "signature_submitted", transferID, username, "pending_signature")
	if err != nil {
		s.server.UpdatePendingMonetaryActionStatus(actionID, "failed")
		conn.Emit("miner_signature_ack", map[string]any{"success": false, "transfer_id": transferID, "error": "Failed to queue signature"})
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		s.server.UpdatePendingMonetaryActionStatus(actionID, "failed")
		conn.Emit("miner_signature_ack", map[string]any{"success": false, "transfer_id": transferID, "error": "Transfer not signable"})
		return
	}
	s.schedulePendingSignaturePayload(transferID, actionID, payload)
	go s.notifyMonetaryTransferUpdate(transferID, "signature_submitted", "", nil)
}

func (s *Server) backgroundProcessPendingSignatureActions() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		rows, err := s.server.DB.Query(`SELECT transfer_id
			FROM pending_monetary_actions
			WHERE action_name = ? AND status IN (?, ?)
			ORDER BY created_at ASC LIMIT 50`, "settle_miner_signature", "pending", "processing")
		if err != nil {
			continue
		}
		transferIDs := make([]string, 0, 16)
		for rows.Next() {
			var transferID string
			if rows.Scan(&transferID) == nil && transferID != "" {
				transferIDs = append(transferIDs, transferID)
			}
		}
		rows.Close()
		for _, transferID := range transferIDs {
			s.schedulePendingSignatureAction(transferID)
		}
	}
}

func (s *Server) schedulePendingSignatureAction(transferID string) {
	if transferID == "" {
		return
	}
	s.signatureWorkerMu.Lock()
	if s.signatureWorkers[transferID] {
		s.signatureWorkerMu.Unlock()
		return
	}
	s.signatureWorkers[transferID] = true
	s.signatureWorkerMu.Unlock()
	go s.runPendingSignatureActionWorker(transferID)
}

func (s *Server) schedulePendingSignaturePayload(transferID, actionID string, payload map[string]any) {
	if transferID == "" {
		return
	}
	s.signatureWorkerMu.Lock()
	if s.signatureWorkers[transferID] {
		s.signatureWorkerMu.Unlock()
		return
	}
	s.signatureWorkers[transferID] = true
	s.signatureWorkerMu.Unlock()
	go s.runPendingSignatureActionWorkerPayload(transferID, actionID, payload)
}

func (s *Server) runPendingSignatureActionWorker(transferID string) {
	defer func() {
		s.signatureWorkerMu.Lock()
		delete(s.signatureWorkers, transferID)
		s.signatureWorkerMu.Unlock()
	}()
	s.processPendingSignatureAction(transferID)
}

func (s *Server) runPendingSignatureActionWorkerPayload(transferID, actionID string, payload map[string]any) {
	defer func() {
		s.signatureWorkerMu.Lock()
		delete(s.signatureWorkers, transferID)
		s.signatureWorkerMu.Unlock()
	}()
	log.Printf("sign_transfer: worker_started transfer=%s source=hot_path", transferID)
	s.processPendingSignatureActionPayload(transferID, actionID, payload)
}

func (s *Server) failPendingSignatureAction(actionID, transferID, miner, errorNote string, restorePending bool) {
	if actionID != "" {
		s.server.UpdatePendingMonetaryActionStatus(actionID, "failed")
	}
	if restorePending && transferID != "" {
		_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
			SET status = ?, miner_deadline = ?
			WHERE transfer_id = ? AND status = ?`, "pending_signature", nowSec()+60.0, transferID, "signature_submitted")
	}
	if miner != "" {
		s.emitToUser(miner, "miner_signature_ack", map[string]any{
			"success":     false,
			"transfer_id": transferID,
			"error":       errorNote,
		})
	}
}

func (s *Server) processPendingSignatureAction(transferID string) {
	action := s.server.GetPendingMonetaryAction(transferID)
	if action == nil || asString(action["action_name"]) != "settle_miner_signature" {
		return
	}
	status := asString(action["status"])
	if status != "pending" && status != "processing" {
		return
	}
	actionID := asString(action["action_id"])
	s.server.UpdatePendingMonetaryActionStatus(actionID, "processing")
	payload := castMap(action["payload"])
	log.Printf("sign_transfer: worker_started transfer=%s source=recovery", transferID)
	s.processPendingSignatureActionPayload(transferID, actionID, payload)
}

func (s *Server) processPendingSignatureActionPayload(transferID, actionID string, payload map[string]any) {
	miner := asString(payload["miner"])
	contractB64 := asString(payload["contract_content"])
	reportB64 := asString(payload["report_content"])
	stageLog := func(step string) {
		log.Printf("sign_transfer: stage transfer=%s miner=%s step=%s", transferID, miner, step)
	}

	transfer, ok := s.getMonetaryTransfer(transferID)
	if !ok {
		s.failPendingSignatureAction(actionID, transferID, miner, "Transfer not found", false)
		return
	}
	if asString(transfer["assigned_miner"]) != miner {
		s.failPendingSignatureAction(actionID, transferID, miner, "Miner not assigned", false)
		return
	}
	currentStatus := asString(transfer["status"])
	if currentStatus == "signed" || currentStatus == "completed" {
		s.server.CompletePendingMonetaryAction(transferID)
		s.emitToUser(miner, "miner_signature_ack", map[string]any{
			"success":     true,
			"transfer_id": transferID,
			"debt_status": s.server.SafeGetMinerDebtStatus(miner),
		})
		return
	}
	if currentStatus != "pending_signature" && currentStatus != "signature_submitted" {
		s.failPendingSignatureAction(actionID, transferID, miner, "Transfer not signable", false)
		return
	}
	stageLog("transfer_loaded")
	isExchangeIn := asString(transfer["transfer_type"]) == "exchange_in"
	expectedVouchers := toStringSlice(transfer["locked_voucher_ids"])
	if len(expectedVouchers) > 0 && !isExchangeIn {
		okV, failures := s.server.ValidateVouchers(expectedVouchers, false)
		if !okV {
			parts := make([]string, 0, len(failures))
			for voucherID, reason := range failures {
				if voucherID == "" {
					continue
				}
				if reason == "" {
					parts = append(parts, voucherID)
					continue
				}
				parts = append(parts, voucherID+":"+reason)
			}
			sort.Strings(parts)
			s.failPendingSignatureAction(actionID, transferID, miner, "Voucher validation failed: "+strings.Join(parts, ","), true)
			return
		}
	}

	reportContent, err := base64.StdEncoding.DecodeString(reportB64)
	if err != nil {
		s.failPendingSignatureAction(actionID, transferID, miner, "Invalid report: invalid base64", true)
		return
	}
	valid, errMsg, reportInfo := core.ValidateContractStructure(reportContent)
	if !valid || reportInfo == nil {
		s.failPendingSignatureAction(actionID, transferID, miner, "Invalid report: "+errMsg, true)
		return
	}
	if reportInfo.Action != "miner_signature_report" {
		s.failPendingSignatureAction(actionID, transferID, miner, "Invalid report action", true)
		return
	}
	if reportInfo.User != miner {
		s.failPendingSignatureAction(actionID, transferID, miner, "Report user mismatch", true)
		return
	}
	if !s.server.VerifyContractSignature(reportContent, miner, reportInfo.Signature, "") {
		s.failPendingSignatureAction(actionID, transferID, miner, "Invalid report signature", true)
		return
	}
	stageLog("report_verified")

	reportOK := true
	reportErrors := []string{}
	reportTransferID := core.ExtractContractDetail(reportInfo, "TRANSFER_ID")
	reportContractID := core.ExtractContractDetail(reportInfo, "CONTRACT_ID")
	reportTransferType := core.ExtractContractDetail(reportInfo, "TRANSFER_TYPE")
	reportSender := core.ExtractContractDetail(reportInfo, "SENDER")
	reportReceiver := core.ExtractContractDetail(reportInfo, "RECEIVER")
	reportAmount := core.ExtractContractDetail(reportInfo, "AMOUNT")
	reportFeeAmount := core.ExtractContractDetail(reportInfo, "FEE_AMOUNT")
	reportFeeSource := core.ExtractContractDetail(reportInfo, "FEE_SOURCE")
	reportVouchers := core.ExtractContractDetail(reportInfo, "LOCKED_VOUCHERS")
	reportIssuerVouchers := parseJSONStringSlice(core.ExtractContractDetail(reportInfo, "ISSUER_VOUCHER_IDS"))
	reportPowAudit := core.ExtractContractDetail(reportInfo, "VOUCHER_POW_AUDIT")
	reportTrace := core.ExtractContractDetail(reportInfo, "VOUCHER_TRACE")
	if reportTransferID == "" || reportTransferID != transferID {
		reportOK = false
		reportErrors = append(reportErrors, "transfer_id_mismatch")
	}
	if asString(transfer["contract_id"]) != "" && reportContractID != asString(transfer["contract_id"]) {
		reportOK = false
		reportErrors = append(reportErrors, "contract_id_mismatch")
	}
	if asString(transfer["contract_id"]) != "" {
		transferContractBytes := s.server.GetContractBytes(asString(transfer["contract_id"]))
		if len(transferContractBytes) == 0 {
			reportOK = false
			reportErrors = append(reportErrors, "contract_signature_invalid")
		} else {
			okContract, _, transferContractInfo := core.ValidateContractStructure(transferContractBytes)
			if !okContract || transferContractInfo == nil || !s.server.VerifyContractSignature(
				transferContractBytes, transferContractInfo.User, transferContractInfo.Signature, "",
			) {
				reportOK = false
				reportErrors = append(reportErrors, "contract_signature_invalid")
			}
		}
	}
	if reportTransferType == "" || reportTransferType != asString(transfer["transfer_type"]) {
		reportOK = false
		reportErrors = append(reportErrors, "transfer_type_mismatch")
	}
	if reportSender == "" || reportSender != asString(transfer["sender"]) {
		reportOK = false
		reportErrors = append(reportErrors, "sender_mismatch")
	}
	if reportReceiver == "" || reportReceiver != asString(transfer["receiver"]) {
		reportOK = false
		reportErrors = append(reportErrors, "receiver_mismatch")
	}
	if reportAmount == "" || asInt(reportAmount) != asInt(transfer["amount"]) {
		reportOK = false
		reportErrors = append(reportErrors, "amount_mismatch")
	}
	if reportFeeAmount == "" || asInt(reportFeeAmount) != asInt(transfer["fee_amount"]) {
		reportOK = false
		reportErrors = append(reportErrors, "fee_amount_mismatch")
	}
	if reportFeeSource != asString(transfer["fee_source"]) {
		reportOK = false
		reportErrors = append(reportErrors, "fee_source_mismatch")
	}
	reportVoucherList := parseJSONStringSlice(reportVouchers)
	if len(expectedVouchers) > 0 && strings.Join(sortedStrings(reportVoucherList), ",") != strings.Join(sortedStrings(expectedVouchers), ",") {
		reportOK = false
		reportErrors = append(reportErrors, "voucher_list_mismatch")
	}
	if !isExchangeIn {
		powEntries := []map[string]any{}
		traceEntries := []map[string]any{}
		usingComputedEvidence := reportPowAudit == "" || reportTrace == ""
		if !usingComputedEvidence {
			if err := json.Unmarshal([]byte(reportPowAudit), &powEntries); err != nil {
				reportOK = false
				reportErrors = append(reportErrors, "pow_or_trace_invalid")
			}
			if err := json.Unmarshal([]byte(reportTrace), &traceEntries); err != nil {
				reportOK = false
				reportErrors = append(reportErrors, "pow_or_trace_invalid")
			}
		}
		if usingComputedEvidence {
			for _, voucherID := range expectedVouchers {
				info := s.server.GetVoucherAuditInfo(voucherID)
				if info == nil {
					reportOK = false
					reportErrors = append(reportErrors, "voucher_missing:"+voucherID)
					break
				}
				payload := castMap(info["payload"])
				powOK, powReason, powDetails := s.server.VerifyVoucherPowPayload(payload)
				powEntries = append(powEntries, map[string]any{
					"voucher_id":  voucherID,
					"pow_ok":      powOK,
					"pow_reason":  powReason,
					"pow_details": powDetails,
				})
				expectedSources := []string{}
				powMintOK := powOK && asString(powDetails["action_type"]) == "hps_mint"
				traceOK := powMintOK
				if !powMintOK {
					expectedSources = s.server.GetTraceSourceVouchers(voucherID)
				}
				traceEntries = append(traceEntries, map[string]any{
					"voucher_id":      voucherID,
					"trace_ok":        traceOK,
					"source_vouchers": expectedSources,
				})
			}
		}
		if reportOK {
			powMap := map[string]map[string]any{}
			for _, entry := range powEntries {
				vid := asString(entry["voucher_id"])
				if vid != "" {
					powMap[vid] = entry
				}
			}
			traceMap := map[string]map[string]any{}
			for _, entry := range traceEntries {
				vid := asString(entry["voucher_id"])
				if vid != "" {
					traceMap[vid] = entry
				}
			}
			for _, voucherID := range expectedVouchers {
				powEntry := powMap[voucherID]
				traceEntry := traceMap[voucherID]
				if len(powEntry) == 0 || len(traceEntry) == 0 {
					reportOK = false
					reportErrors = append(reportErrors, "pow_trace_missing:"+voucherID)
					break
				}
				info := s.server.GetVoucherAuditInfo(voucherID)
				if info == nil {
					reportOK = false
					reportErrors = append(reportErrors, "voucher_missing:"+voucherID)
					break
				}
				payload := castMap(info["payload"])
				powOK, _, powDetails := s.server.VerifyVoucherPowPayload(payload)
				powMintOK := powOK && asString(powDetails["action_type"]) == "hps_mint"
				if asBool(powEntry["pow_ok"]) != powOK {
					reportOK = false
					reportErrors = append(reportErrors, "pow_mismatch:"+voucherID)
					break
				}
				if !powMintOK {
					expectedSources := s.server.GetTraceSourceVouchers(voucherID)
					if asString(transfer["transfer_type"]) == "exchange_in" {
						issuerIDs := toStringSlice(castMap(transfer["inter_server_payload"])["issuer_voucher_ids"])
						if len(issuerIDs) > 0 {
							expectedSources = issuerIDs
						}
					}
					traceSources := toStringSlice(traceEntry["source_vouchers"])
					if len(expectedSources) > 0 && strings.Join(sortedStrings(expectedSources), ",") != strings.Join(sortedStrings(traceSources), ",") {
						reportOK = false
						reportErrors = append(reportErrors, "trace_sources_mismatch:"+voucherID)
						break
					}
				}
			}
		}
	}
	stageLog("report_base_checks_done")
	if asString(transfer["transfer_type"]) == "exchange_in" {
		interServerPayload := castMap(transfer["inter_server_payload"])
		stageLog("exchange_checks_begin")
		reportReservedID := core.ExtractContractDetail(reportInfo, "ISSUER_RESERVED_CONTRACT_ID")
		reportOutID := core.ExtractContractDetail(reportInfo, "ISSUER_OUT_CONTRACT_ID")
		reportOwnerKeyID := core.ExtractContractDetail(reportInfo, "ISSUER_OWNER_KEY_CONTRACT_ID")
		reportLineageCloseID := core.ExtractContractDetail(reportInfo, "ISSUER_LINEAGE_CLOSE_CONTRACT_ID")
		reportExchangeContractID := core.ExtractContractDetail(reportInfo, "CLIENT_EXCHANGE_CONTRACT_ID")
		reportExchangeContractHash := core.ExtractContractDetail(reportInfo, "CLIENT_EXCHANGE_CONTRACT_HASH")
		expectedReservedID := asString(interServerPayload["issuer_reserved_contract_id"])
		expectedOutID := asString(interServerPayload["issuer_out_contract_id"])
		expectedOwnerKeyID := asString(interServerPayload["issuer_owner_key_contract_id"])
		expectedLineageCloseID := asString(interServerPayload["issuer_lineage_close_contract_id"])
		expectedExchangeContractID := asString(interServerPayload["exchange_contract_id"])
		expectedExchangeHash := asString(interServerPayload["exchange_contract_hash"])
		if expectedReservedID != "" && reportReservedID != "" && reportReservedID != expectedReservedID {
			reportOK = false
			reportErrors = append(reportErrors, "issuer_reserved_id_mismatch")
		}
		if expectedOutID != "" && reportOutID != "" && reportOutID != expectedOutID {
			reportOK = false
			reportErrors = append(reportErrors, "issuer_out_id_mismatch")
		}
		if expectedOwnerKeyID != "" && reportOwnerKeyID != "" && reportOwnerKeyID != expectedOwnerKeyID {
			reportOK = false
			reportErrors = append(reportErrors, "issuer_owner_key_id_mismatch")
		}
		if expectedLineageCloseID != "" && reportLineageCloseID != "" && reportLineageCloseID != expectedLineageCloseID {
			reportOK = false
			reportErrors = append(reportErrors, "issuer_lineage_close_id_mismatch")
		}
		if expectedExchangeContractID != "" && reportExchangeContractID != "" && reportExchangeContractID != expectedExchangeContractID {
			reportOK = false
			reportErrors = append(reportErrors, "exchange_contract_id_mismatch")
		}
		if expectedExchangeHash != "" && reportExchangeContractHash != "" && reportExchangeContractHash != expectedExchangeHash {
			reportOK = false
			reportErrors = append(reportErrors, "exchange_contract_hash_mismatch")
		}
		expectedIssuerVouchers := toStringSlice(interServerPayload["issuer_voucher_ids"])
		if len(expectedIssuerVouchers) > 0 && len(reportIssuerVouchers) > 0 && !sameStringSet(expectedIssuerVouchers, reportIssuerVouchers) {
			reportOK = false
			reportErrors = append(reportErrors, "issuer_voucher_list_mismatch")
		}
		stageLog("exchange_checks_light_done")
	}
	stageLog("report_validation_complete")
	if !reportOK {
		feeAmount := asInt(transfer["fee_amount"])
		if feeAmount > 0 {
			s.server.AddMinerDebtEntry(miner, "fine_report_invalid", feeAmount, map[string]any{"transfer_id": transferID})
			s.server.SyncMinerPendingCounts(miner)
			pending, _ := s.server.GetMinerPendingCounts(miner)
			s.emitToUser(miner, "miner_signature_update", map[string]any{
				"pending_signatures": pending,
				"debt_status":        s.server.SafeGetMinerDebtStatus(miner),
			})
		}
		errorNote := "Invalid signature report"
		if len(reportErrors) > 0 {
			maxItems := 6
			if len(reportErrors) < maxItems {
				maxItems = len(reportErrors)
			}
			errorNote += ": " + strings.Join(reportErrors[:maxItems], ",")
		}
		if isExchangeIn {
			_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
				SET status = ?, miner_deadline = NULL
				WHERE transfer_id = ?`, "rejected", transferID)
			s.rollbackExchangeTransfer(transfer, "invalid_report")
			s.server.SaveServerContract("exchange_review_rejected", []core.ContractDetail{
				{Key: "TRANSFER_ID", Value: transferID},
				{Key: "MINER", Value: miner},
				{Key: "ERRORS", Value: toJSONString(reportErrors)},
			}, transferID)
			s.notifyMonetaryTransferUpdate(transferID, "rejected", "invalid_report", map[string]any{
				"error":       errorNote,
				"transfer_id": transferID,
			})
			failPayload := map[string]any{
				"success":     false,
				"stage":       "failed",
				"transfer_id": transferID,
				"error":       errorNote,
			}
			s.emitToUser(asString(transfer["receiver"]), "exchange_complete", failPayload)
			s.relayExchangeEventToIssuer(transfer, "exchange_complete", failPayload)
			s.failPendingSignatureAction(actionID, transferID, miner, errorNote, false)
			return
		}
		log.Printf("sign_transfer: rejected transfer=%s miner=%s reason=%s", transferID, miner, errorNote)
		s.failPendingSignatureAction(actionID, transferID, miner, errorNote, true)
		return
	}

	contractContent, err := base64.StdEncoding.DecodeString(contractB64)
	if err != nil {
		s.failPendingSignatureAction(actionID, transferID, miner, "Invalid contract: invalid base64", true)
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		s.failPendingSignatureAction(actionID, transferID, miner, "Invalid contract: "+errMsg, true)
		return
	}
	if contractInfo.Action != "transfer_signature" {
		s.failPendingSignatureAction(actionID, transferID, miner, "Invalid contract action", true)
		return
	}
	if contractInfo.User != miner {
		s.failPendingSignatureAction(actionID, transferID, miner, "Contract user mismatch", true)
		return
	}
	contractTransferID := core.ExtractContractDetail(contractInfo, "TRANSFER_ID")
	if contractTransferID != "" && contractTransferID != transferID {
		s.failPendingSignatureAction(actionID, transferID, miner, "Transfer ID mismatch", true)
		return
	}
	if !s.server.VerifyContractSignature(contractContent, miner, contractInfo.Signature, "") {
		s.failPendingSignatureAction(actionID, transferID, miner, "Invalid contract signature", true)
		return
	}
	stageLog("transfer_contract_verified")

	s.server.SaveContract("miner_signature_report", transferID, "", miner, reportInfo.Signature, reportContent)
	s.server.SaveContract("transfer_signature", transferID, "", miner, contractInfo.Signature, contractContent)
	_ = s.server.SettleMinerSignature(transferID, miner, contractContent, contractInfo.Signature)
	stageLog("signature_settled")
	s.processPendingMonetaryAction(transferID)
	s.emitPendingVoucherOffers(miner)
	pendingSignatures, _ := s.server.SyncMinerPendingCounts(miner)
	s.emitToUser(miner, "miner_signature_update", map[string]any{
		"pending_signatures": pendingSignatures,
		"debt_status":        s.server.SafeGetMinerDebtStatus(miner),
	})
	s.notifyMonetaryTransferUpdate(transferID, "signed", "", nil)
	if asString(transfer["transfer_type"]) == "exchange_in" {
		s.server.SaveServerContract("exchange_review_approved", []core.ContractDetail{
			{Key: "TRANSFER_ID", Value: transferID},
			{Key: "MINER", Value: miner},
			{Key: "STATUS", Value: "approved"},
		}, transferID)
		interPayload := castMap(transfer["inter_server_payload"])
		offerID := asString(interPayload["exchange_offer_id"])
		offerVoucherID := asString(interPayload["exchange_offer_voucher_id"])
		var exchangeVoucherOffer map[string]any
		if offerID != "" {
			_, _ = s.server.DB.Exec(`UPDATE hps_voucher_offers SET status = ? WHERE offer_id = ? AND status = ?`, "pending", offerID, "withheld")
		}
		receiver := asString(transfer["receiver"])
		if receiver != "" && offerVoucherID != "" {
			var emitOfferID, emitPayloadText string
			var emitExpires float64
			err := s.server.DB.QueryRow(`SELECT offer_id, payload, expires_at FROM hps_voucher_offers
				WHERE voucher_id = ? AND owner = ? AND status = ?`, offerVoucherID, receiver, "pending").Scan(&emitOfferID, &emitPayloadText, &emitExpires)
			if err == nil && emitOfferID != "" && emitPayloadText != "" {
				offerPayload := map[string]any{}
				if json.Unmarshal([]byte(emitPayloadText), &offerPayload) == nil {
					exchangeVoucherOffer = map[string]any{
						"offer_id":          emitOfferID,
						"voucher_id":        offerVoucherID,
						"payload":           offerPayload,
						"payload_canonical": emitPayloadText,
						"expires_at":        emitExpires,
					}
					s.emitToUser(receiver, "hps_voucher_offer", map[string]any{
						"offer_id":          emitOfferID,
						"voucher_id":        offerVoucherID,
						"payload":           offerPayload,
						"payload_canonical": emitPayloadText,
						"expires_at":        emitExpires,
					})
				}
			}
		}
		finalPayload := map[string]any{
			"success":        true,
			"stage":          "finalized",
			"transfer_id":    transferID,
			"status":         "completed",
			"new_voucher_id": offerVoucherID,
		}
		if exchangeVoucherOffer != nil {
			finalPayload["voucher_offer"] = exchangeVoucherOffer
		}
		issuerAddress := asString(interPayload["issuer_address"])
		if issuerAddress == "" {
			issuerAddress = asString(interPayload["issuer"])
		}
		tokenID := asString(interPayload["issuer_token_id"])
		if issuerAddress != "" && tokenID != "" {
			okComplete, completePayload, errMsg := s.server.MakeRemoteRequestJSON(issuerAddress, "/exchange/complete", http.MethodPost, map[string]any{
				"token_id":    tokenID,
				"transfer_id": transferID,
			})
			if errMsg != "" {
				log.Printf("exchange complete settlement failed issuer=%s transfer=%s token=%s err=%s", issuerAddress, transferID, tokenID, errMsg)
			} else if okComplete && completePayload != nil {
				lineageCloseID := asString(completePayload["lineage_close_contract_id"])
				lineageCloseContract := asString(completePayload["lineage_close_contract"])
				if lineageCloseID != "" || lineageCloseContract != "" {
					interPayload["issuer_lineage_close_contract_id"] = lineageCloseID
					interPayload["issuer_lineage_close_contract"] = lineageCloseContract
					_, _ = s.server.DB.Exec(`UPDATE monetary_transfers SET inter_server_payload = ? WHERE transfer_id = ?`,
						toJSONString(interPayload), transferID)
					finalPayload["issuer_lineage_close_contract_id"] = lineageCloseID
				}
			}
		}
		_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
			SET status = ?, miner_deadline = NULL
			WHERE transfer_id = ?`, "completed", transferID)
		s.notifyMonetaryTransferUpdate(transferID, "completed", "", nil)
		s.emitToUser(asString(transfer["receiver"]), "exchange_complete", finalPayload)
		s.relayExchangeEventToIssuer(transfer, "exchange_complete", finalPayload)
	}
	s.server.CompletePendingMonetaryAction(transferID)
	log.Printf("sign_transfer: accepted transfer=%s miner=%s type=%s", transferID, miner, asString(transfer["transfer_type"]))
	s.emitToUser(miner, "miner_signature_ack", map[string]any{
		"success":     true,
		"transfer_id": transferID,
		"debt_status": s.server.SafeGetMinerDebtStatus(miner),
	})
}

func (s *Server) handleRequestExchangeTrace(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("exchange_trace", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	voucherIDs := toStringSlice(data["voucher_ids"])
	requestID := asString(data["request_id"])
	if requestID == "" {
		requestID = core.NewUUID()
	}
	traces := []map[string]any{}
	for _, voucherID := range voucherIDs {
		if voucherID == "" {
			continue
		}
		var transferID, interPayloadText string
		err := s.server.DB.QueryRow(`SELECT transfer_id, inter_server_payload
			FROM monetary_transfers
			WHERE transfer_type = ? AND locked_voucher_ids LIKE ?
			ORDER BY created_at DESC LIMIT 1`, "exchange_in", "%"+voucherID+"%").Scan(&transferID, &interPayloadText)
		if err != nil {
			continue
		}
		interPayload := parseJSONMap(interPayloadText)
		reportContractID := ""
		reportContractHash := ""
		reportTrace := []any{}
		var contractID, reportB64 string
		err = s.server.DB.QueryRow(`SELECT contract_id, contract_content FROM contracts
			WHERE action_type = ? AND content_hash = ?
			ORDER BY timestamp DESC LIMIT 1`, "miner_signature_report", transferID).Scan(&contractID, &reportB64)
		if err == nil {
			reportContractID = contractID
			if reportBytes, decErr := base64.StdEncoding.DecodeString(reportB64); decErr == nil {
				sum := sha256.Sum256(reportBytes)
				reportContractHash = hex.EncodeToString(sum[:])
				valid, _, reportInfo := core.ValidateContractStructure(reportBytes)
				if valid && reportInfo != nil {
					raw := core.ExtractContractDetail(reportInfo, "VOUCHER_TRACE")
					reportTrace = parseJSONArray(raw)
				}
			}
		}
		traces = append(traces, map[string]any{
			"voucher_id":           voucherID,
			"transfer_id":          transferID,
			"inter_server_payload": interPayload,
			"report_contract_id":   reportContractID,
			"report_contract_hash": reportContractHash,
			"report_trace":         reportTrace,
		})
	}
	conn.Emit("exchange_trace", map[string]any{"success": true, "request_id": requestID, "traces": traces})
}

func (s *Server) getTransferByExchangeOfferVoucherID(voucherID string) (map[string]any, bool) {
	if voucherID == "" {
		return nil, false
	}
	var transferID string
	err := s.server.DB.QueryRow(`SELECT transfer_id
		FROM monetary_transfers
		WHERE transfer_type = ? AND locked_voucher_ids LIKE ?
		ORDER BY created_at DESC LIMIT 1`, "exchange_in", "%"+voucherID+"%").Scan(&transferID)
	if err != nil || transferID == "" {
		return nil, false
	}
	return s.getMonetaryTransfer(transferID)
}

func (s *Server) handleInvalidateVouchers(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	username := client.Username
	contractB64 := asString(data["contract_content"])
	if contractB64 == "" {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Missing contract content"})
		return
	}
	contractContent, err := base64.StdEncoding.DecodeString(contractB64)
	if err != nil {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Invalid contract: invalid base64"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Invalid contract: " + errMsg})
		return
	}
	if contractInfo.Action != "voucher_invalidate" {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Invalid contract action"})
		return
	}
	if contractInfo.User != username {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Contract user mismatch"})
		return
	}
	if !s.server.VerifyContractSignature(contractContent, username, contractInfo.Signature, "") {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Invalid contract signature"})
		return
	}
	transferID := core.ExtractContractDetail(contractInfo, "TRANSFER_ID")
	reason := core.ExtractContractDetail(contractInfo, "REASON")
	rawVouchers := core.ExtractContractDetail(contractInfo, "VOUCHERS")
	if reason == "" {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Missing invalidation reason", "transfer_id": transferID})
		return
	}
	if rawVouchers == "" {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Missing vouchers list", "transfer_id": transferID})
		return
	}
	voucherIDs := parseJSONStringSlice(rawVouchers)
	if len(voucherIDs) == 0 {
		conn.Emit("voucher_invalidate_ack", map[string]any{"success": false, "error": "Invalid vouchers list", "transfer_id": transferID})
		return
	}
	okVouchers, failuresRaw := s.server.ValidateVouchers(voucherIDs, true)
	failures := map[string]any{}
	for k, v := range failuresRaw {
		failures[k] = v
	}
	if okVouchers && transferID != "" {
		_, _ = s.server.DB.Exec(`UPDATE monetary_transfers SET status = ? WHERE transfer_id = ?`, "invalidated", transferID)
		_, _ = s.server.DB.Exec(`UPDATE pending_transfers SET status = ? WHERE transfer_id = ?`, "invalidated", transferID)
		s.server.SaveServerContract("transfer_rejected", []core.ContractDetail{
			{Key: "TRANSFER_ID", Value: transferID},
			{Key: "REASON", Value: reason},
			{Key: "MINER", Value: username},
		}, transferID)
		s.notifyMonetaryTransferUpdate(transferID, "invalidated", defaultStr(reason, "miner_invalidated"), map[string]any{
			"message": "Transacao recusada pelo minerador.",
		})
		s.server.CancelPendingMonetaryAction(transferID, "miner_invalidated")
		conn.Emit("voucher_invalidate_ack", map[string]any{
			"success":     true,
			"failures":    failures,
			"transfer_id": transferID,
			"note":        "transfer_rejected_only",
		})
		return
	}
	invalidIDs := []string{}
	for voucherID := range failures {
		invalidIDs = append(invalidIDs, voucherID)
		_, _ = s.server.DB.Exec(`UPDATE hps_vouchers
			SET invalidated = 1, status = ?, last_updated = ?
			WHERE voucher_id = ?`, "invalid", nowSec(), voucherID)
	}
	if len(invalidIDs) > 0 {
		owners := map[string]map[string]any{}
		for _, voucherID := range invalidIDs {
			var owner string
			var value int
			if err := s.server.DB.QueryRow(`SELECT owner, value FROM hps_vouchers WHERE voucher_id = ?`, voucherID).Scan(&owner, &value); err != nil || owner == "" {
				continue
			}
			info, ok := owners[owner]
			if !ok {
				info = map[string]any{"total": 0, "vouchers": []string{}}
				owners[owner] = info
			}
			info["total"] = asInt(info["total"]) + value
			info["vouchers"] = append(toStringSlice(info["vouchers"]), voucherID)
		}
		for owner, info := range owners {
			s.server.AdjustReputation(owner, -20)
			s.server.SaveServerContract("burn_money", []core.ContractDetail{
				{Key: "OWNER", Value: owner},
				{Key: "VOUCHERS", Value: toJSONString(info["vouchers"])},
				{Key: "TOTAL_VALUE", Value: asInt(info["total"])},
				{Key: "REASON", Value: defaultStr(reason, "voucher_invalidated")},
				{Key: "MINER", Value: username},
			}, core.NewUUID())
			s.emitWalletSyncToUser(owner)
		}
		rows, err := s.server.DB.Query(`SELECT transfer_id, locked_voucher_ids FROM monetary_transfers WHERE status = ? AND locked_voucher_ids != ''`, "pending_signature")
		if err == nil {
			defer rows.Close()
			invalidSet := map[string]struct{}{}
			for _, id := range invalidIDs {
				invalidSet[id] = struct{}{}
			}
			for rows.Next() {
				var rowTransferID, rawLocked string
				if rows.Scan(&rowTransferID, &rawLocked) != nil {
					continue
				}
				locked := parseJSONStringSlice(rawLocked)
				hit := false
				for _, lockedID := range locked {
					if _, exists := invalidSet[lockedID]; exists {
						hit = true
						break
					}
				}
				if !hit {
					continue
				}
				_, _ = s.server.DB.Exec(`UPDATE monetary_transfers SET status = ? WHERE transfer_id = ?`, "invalidated", rowTransferID)
				s.notifyMonetaryTransferUpdate(rowTransferID, "invalidated", defaultStr(reason, "voucher_invalidated"), map[string]any{
					"invalid_vouchers": failures,
				})
				s.server.CancelPendingMonetaryAction(rowTransferID, "voucher_invalidated")
			}
		}
		pendingRows, err := s.server.DB.Query(`SELECT transfer_id, original_owner, hps_voucher_ids FROM pending_transfers WHERE transfer_type = ? AND hps_voucher_ids IS NOT NULL`, "hps_transfer")
		if err == nil {
			defer pendingRows.Close()
			invalidSet := map[string]struct{}{}
			for _, id := range invalidIDs {
				invalidSet[id] = struct{}{}
			}
			for pendingRows.Next() {
				var rowTransferID, owner string
				var voucherList sql.NullString
				if pendingRows.Scan(&rowTransferID, &owner, &voucherList) != nil {
					continue
				}
				ids := parseJSONStringSlice(voucherList.String)
				hit := false
				for _, id := range ids {
					if _, exists := invalidSet[id]; exists {
						hit = true
						break
					}
				}
				if !hit {
					continue
				}
				_, _ = s.server.DB.Exec(`UPDATE pending_transfers SET status = ? WHERE transfer_id = ?`, "invalidated", rowTransferID)
				if owner != "" {
					s.emitPendingTransferNotice(owner)
				}
			}
		}
	}
	if len(voucherIDs) > 0 {
		s.server.SaveContract("voucher_invalidate", voucherIDs[0], "", username, contractInfo.Signature, contractContent)
	}
	conn.Emit("voucher_invalidate_ack", map[string]any{
		"success":     true,
		"failures":    failures,
		"transfer_id": transferID,
	})
}

func (s *Server) handleSubmitFraudReport(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("fraud_report_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	_ = client
	reports := castSliceMap(data["reports"])
	confirmed := []map[string]any{}
	for _, report := range reports {
		issuer := trim(asString(report["server_address"]))
		contractB64 := asString(report["contract_content"])
		if issuer == "" || contractB64 == "" {
			continue
		}
		contractBytes, err := base64.StdEncoding.DecodeString(contractB64)
		if err != nil {
			continue
		}
		valid, _, contractInfo := core.ValidateContractStructure(contractBytes)
		if !valid || contractInfo == nil || contractInfo.Action != "voucher_invalidate" {
			continue
		}
		if !s.server.VerifyContractSignature(contractBytes, contractInfo.User, contractInfo.Signature, "") {
			continue
		}
		contractID := s.server.RegisterFraudulentIssuer(issuer, report)
		confirmed = append(confirmed, map[string]any{"issuer": issuer, "contract_id": contractID})
		alertPayload := map[string]any{
			"issuer":     issuer,
			"reason":     "fraud_report",
			"session_id": asString(report["contract_id"]),
		}
		s.broadcastToAuthenticated("hps_issuer_invalidated", alertPayload)
		s.broadcastToAuthenticated("economy_alert", map[string]any{
			"issuer": issuer,
			"reason": "fraud_report",
		})
	}
	conn.Emit("fraud_report_ack", map[string]any{"success": true, "confirmed": confirmed})
}

func (s *Server) handleRequestMinerFine(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("miner_fine_quote", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	username := client.Username
	debtStatus := s.server.SafeGetMinerDebtStatus(username)
	pendingSignatures := asInt(debtStatus["pending_signatures"])
	debtLimit := asInt(debtStatus["debt_limit"])
	allowLastResort := pendingSignatures >= debtLimit
	quote := s.server.GetMinerFineQuote(username, allowLastResort)
	var minedBalance int
	_ = s.server.DB.QueryRow(`SELECT COALESCE(SUM(value), 0) FROM hps_vouchers WHERE owner = ? AND status = ? AND invalidated = 0`, username, "valid").Scan(&minedBalance)
	fineCount := asInt(quote["fine_count"])
	signatureCount := asInt(quote["signature_count"])
	signatureAmount := asInt(quote["signature_amount"])
	totalAmount := asInt(quote["total_amount"])
	conn.Emit("miner_fine_quote", map[string]any{
		"success":               true,
		"fine_amount":           totalAmount,
		"pending_fines":         fineCount,
		"signature_fines":       signatureCount,
		"signature_amount":      signatureAmount,
		"signature_immediate":   asInt(quote["signature_immediate"]),
		"signature_last_resort": asInt(quote["signature_last_resort"]),
		"pending_total":         fineCount + signatureCount,
		"mined_balance":         minedBalance,
		"debt_status":           debtStatus,
	})
}

func (s *Server) handlePayMinerFine(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	username := client.Username
	voucherIDs := toStringSlice(data["voucher_ids"])
	useWithheld := asBool(data["use_withheld"])
	promise := asBool(data["promise"])
	contractB64 := asString(data["contract_content"])
	if (!useWithheld && !promise && len(voucherIDs) == 0) || contractB64 == "" {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Missing fine payment data"})
		return
	}
	contractContent, err := base64.StdEncoding.DecodeString(contractB64)
	if err != nil {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Invalid contract: invalid base64"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Invalid contract: " + errMsg})
		return
	}
	if contractInfo.Action != "miner_fine" {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Invalid contract action"})
		return
	}
	if contractInfo.User != username {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Contract user mismatch"})
		return
	}
	if !s.server.VerifyContractSignature(contractContent, username, contractInfo.Signature, "") {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Invalid contract signature"})
		return
	}
	amountValue := core.ExtractContractDetail(contractInfo, "AMOUNT")
	if amountValue == "" {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Missing fine amount"})
		return
	}
	fineAmount := int(asFloat(amountValue))
	if fineAmount <= 0 {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "No pending fines"})
		return
	}
	debtStatus := s.server.SafeGetMinerDebtStatus(username)
	pendingSignatures := asInt(debtStatus["pending_signatures"])
	debtLimit := asInt(debtStatus["debt_limit"])
	allowLastResort := pendingSignatures >= debtLimit
	quote := s.server.GetMinerFineQuote(username, allowLastResort)
	expectedFine := asInt(quote["total_amount"])
	if expectedFine <= 0 {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "No pending fines"})
		return
	}
	if s.server.HasPendingSignatureTransfers(username) && asInt(quote["signature_count"]) <= 0 {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Existem assinaturas pendentes disponiveis"})
		return
	}
	if fineAmount != expectedFine {
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Fine amount mismatch"})
		return
	}
	contractID := s.server.SaveContract("miner_fine", "", "", username, contractInfo.Signature, contractContent)
	signatureTypes := []string{"signature_immediate"}
	if allowLastResort {
		signatureTypes = append(signatureTypes, "signature_last_resort")
	}
	if promise {
		withheldUsed, _, _ := s.server.ConsumeWithheldOffersDetailed(username, fineAmount)
		remaining := fineAmount - withheldUsed
		if remaining < 0 {
			remaining = 0
		}
		s.server.ResolveMinerDebtEntries(username, []string{"fine_delay", "fine_report_invalid"})
		s.server.ResolveMinerDebtEntries(username, signatureTypes)
		_, _ = s.server.DB.Exec(`INSERT INTO miner_stats
			(username, fine_promise_amount, fine_promise_active, last_updated)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(username) DO UPDATE SET
				fine_promise_amount = excluded.fine_promise_amount,
				fine_promise_active = excluded.fine_promise_active,
				last_updated = excluded.last_updated`,
			username, remaining, intFromBool(remaining > 0), nowSec())
		s.server.SyncMinerPendingCounts(username)
		s.server.ReleaseWithheldOffersForMiner(username)
		s.emitPendingVoucherOffers(username)
		pending, _ := s.server.GetMinerPendingCounts(username)
		s.emitToUser(username, "miner_signature_update", map[string]any{
			"pending_signatures": pending,
			"debt_status":        s.server.SafeGetMinerDebtStatus(username),
		})
		s.emitWalletSyncToUser(username)
		conn.Emit("economy_report", s.server.BuildEconomyReport())
		conn.Emit("hps_economy_status", s.getHpsEconomyStatusPayload())
		conn.Emit("miner_fine_ack", map[string]any{"success": true, "amount": fineAmount, "mode": "promise", "debt_status": s.server.SafeGetMinerDebtStatus(username)})
		return
	}
	sessionID := "fine-" + core.NewUUID()
	totalValue := 0
	if len(voucherIDs) > 0 {
		okReserve, sum, reserveErr := s.server.ReserveVouchersForSession(username, sessionID, voucherIDs)
		if !okReserve {
			conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": reserveErr})
			return
		}
		totalValue = sum
	}
	if useWithheld {
		remaining := fineAmount - totalValue
		if remaining < 0 {
			remaining = 0
		}
		withheldUsed, _, _ := s.server.ConsumeWithheldOffersDetailed(username, remaining)
		totalValue += withheldUsed
	}
	if totalValue < fineAmount {
		s.server.ReleaseVouchersForSession(sessionID)
		conn.Emit("miner_fine_ack", map[string]any{"success": false, "error": "Insufficient balance"})
		return
	}
	s.server.MarkVouchersSpent(sessionID)
	s.server.AddCustodyFunds(fineAmount, "miner_fine")
	changeValue := totalValue - fineAmount
	if changeValue > 0 {
		s.server.IssueChangeOffer(
			username,
			changeValue,
			"miner_fine_change",
			sessionID,
			"miner_fine_refund",
			[]core.ContractDetail{
				{Key: "MINER", Value: username},
				{Key: "FINE_AMOUNT", Value: fineAmount},
				{Key: "VOUCHERS", Value: toJSONString(voucherIDs)},
			},
		)
		s.emitPendingVoucherOffers(username)
	}
	s.server.SaveServerContract("miner_fine_receipt", []core.ContractDetail{
		{Key: "MINER", Value: username},
		{Key: "AMOUNT", Value: fineAmount},
		{Key: "CONTRACT_ID", Value: contractID},
		{Key: "VOUCHERS", Value: toJSONString(voucherIDs)},
	}, sessionID)
	s.server.ResolveMinerDebtEntries(username, []string{"fine_delay", "fine_report_invalid"})
	s.server.ResolveMinerDebtEntries(username, signatureTypes)
	_, _ = s.server.DB.Exec(`INSERT INTO miner_stats
		(username, fine_promise_amount, fine_promise_active, last_updated)
		VALUES (?, 0, 0, ?)
		ON CONFLICT(username) DO UPDATE SET
			fine_promise_amount = 0,
			fine_promise_active = 0,
			last_updated = excluded.last_updated`, username, nowSec())
	s.server.SyncMinerPendingCounts(username)
	s.server.ReleaseWithheldOffersForMiner(username)
	s.emitPendingVoucherOffers(username)
	pendingSignatures, _ = s.server.GetMinerPendingCounts(username)
	s.emitToUser(username, "miner_signature_update", map[string]any{
		"pending_signatures": pendingSignatures,
		"debt_status":        s.server.SafeGetMinerDebtStatus(username),
	})
	s.emitWalletSyncToUser(username)
	conn.Emit("economy_report", s.server.BuildEconomyReport())
	conn.Emit("hps_economy_status", s.getHpsEconomyStatusPayload())
	conn.Emit("miner_fine_ack", map[string]any{"success": true, "amount": fineAmount, "debt_status": s.server.SafeGetMinerDebtStatus(username)})
}

func (s *Server) handleRequestExchangeQuote(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	if s.server.IsUserFraudRestricted(client.Username) {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "User blocked for exchange"})
		conn.Emit("hps_issuer_invalidated", map[string]any{"issuer": s.server.Address, "reason": "user_blocked_for_exchange", "session_id": ""})
		return
	}
	vouchers := castSliceMap(data["vouchers"])
	clientSignature := asString(data["client_signature"])
	clientPublicKey := asString(data["client_public_key"])
	timestamp := asFloat(data["timestamp"])
	fallbackReport := castMap(data["fallback_report"])
	contractB64 := asString(data["contract_content"])
	if len(vouchers) == 0 || clientSignature == "" || clientPublicKey == "" {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Missing exchange data"})
		return
	}
	if math.Abs(nowSec()-timestamp) > 600 {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Timestamp out of range"})
		return
	}
	firstPayload := castMap(vouchers[0]["payload"])
	issuer := asString(firstPayload["issuer"])
	if issuer == "" || s.server.IsLocalIssuer(issuer) {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Invalid issuer"})
		return
	}
	if s.isExchangeBlocked(issuer) {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Issuer blocked for exchange"})
		conn.Emit("hps_issuer_invalidated", map[string]any{"issuer": issuer, "reason": "issuer_blocked_for_exchange", "session_id": ""})
		conn.Emit("economy_alert", map[string]any{"issuer": issuer, "reason": "issuer_blocked_for_exchange"})
		return
	}
	voucherIDs := []string{}
	totalValue := 0
	owner := ""
	ownerKey := ""
	issuerKey := ""
	for _, voucher := range vouchers {
		voucherMap := castMap(voucher)
		payload := castMap(voucherMap["payload"])
		signatures := castMap(voucherMap["signatures"])
		if len(payload) == 0 || len(signatures) == 0 {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Voucher payload/signatures missing"})
			return
		}
		if asString(signatures["owner"]) == "" || asString(signatures["issuer"]) == "" {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Voucher signatures missing"})
			return
		}
		if asString(payload["owner_public_key"]) == "" || asString(payload["issuer_public_key"]) == "" {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Voucher public keys missing"})
			return
		}
		if asString(payload["issuer"]) != issuer {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Mixed issuers not supported"})
			return
		}
		if owner == "" {
			owner = asString(payload["owner"])
			ownerKey = asString(payload["owner_public_key"])
			issuerKey = asString(payload["issuer_public_key"])
		}
		if asString(payload["owner"]) != owner {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Voucher owner mismatch"})
			return
		}
		if ownerKey != clientPublicKey {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Owner key mismatch"})
			return
		}
		if issuerKey != "" && asString(payload["issuer_public_key"]) != issuerKey {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Issuer key mismatch"})
			return
		}
		voucherIDs = append(voucherIDs, asString(payload["voucher_id"]))
		totalValue += asInt(payload["value"])
	}
	targetServer := asString(data["target_server"])
	if targetServer == "" {
		targetServer = s.server.Address
	}
	proofPayload := map[string]any{
		"issuer":        issuer,
		"target_server": targetServer,
		"voucher_ids":   sortedStrings(voucherIDs),
		"timestamp":     timestamp,
	}
	if !core.VerifyPayloadSignature(proofPayload, clientSignature, clientPublicKey) {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Client proof invalid"})
		return
	}
	clientContractID := ""
	if contractB64 != "" {
		contractContent, err := base64.StdEncoding.DecodeString(contractB64)
		if err != nil {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Invalid contract: invalid base64"})
			return
		}
		valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
		if !valid || contractInfo == nil {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Invalid contract: " + errMsg})
			return
		}
		if contractInfo.Action != "exchange_hps" {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Invalid contract action"})
			return
		}
		if contractInfo.User != client.Username {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Contract user mismatch"})
			return
		}
		if !s.server.VerifyContractSignature(contractContent, client.Username, contractInfo.Signature, clientPublicKey) {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Invalid contract signature"})
			return
		}
		disclosureRaw := core.ExtractContractDetail(contractInfo, "DKVHPS_DISCLOSURE_HPS_B64")
		if strings.TrimSpace(disclosureRaw) != "" {
			if decoded, err := base64.StdEncoding.DecodeString(disclosureRaw); err == nil {
				disclosureRaw = string(decoded)
			}
		}
		if strings.TrimSpace(disclosureRaw) == "" {
			disclosureRaw = core.ExtractContractDetail(contractInfo, "DKVHPS_DISCLOSURE_HPS")
		}
		if strings.TrimSpace(disclosureRaw) == "" {
			disclosureRaw = core.ExtractContractDetail(contractInfo, "DKVHPS_DISCLOSURE_JSON")
		}
		if okDisclosure, disclosureErr := validateExchangeDkvhpsDisclosure(disclosureRaw, vouchers); !okDisclosure {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": disclosureErr})
			return
		}
		clientContractID = s.server.SaveContract("exchange_hps", "", "", client.Username, contractInfo.Signature, contractContent)
	}
	issuerAddress := asString(data["issuer_address"])
	if issuerAddress == "" {
		issuerAddress = issuer
	}
	var economyReport map[string]any
	okReport, remoteReport, _ := s.server.MakeRemoteRequestJSON(issuerAddress, "/economy_report", "GET", nil)
	if okReport && s.server.VerifyEconomyReport(remoteReport) {
		economyReport = remoteReport
	} else if len(fallbackReport) > 0 && s.server.VerifyEconomyReport(fallbackReport) {
		reportTs := asFloat(castMap(fallbackReport["payload"])["timestamp"])
		if math.Abs(nowSec()-reportTs) <= 600 {
			economyReport = fallbackReport
		} else {
			conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Issuer economy report expired"})
			return
		}
	} else {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Issuer economy report invalid"})
		return
	}
	reportPayload := castMap(economyReport["payload"])
	reportKey := asString(reportPayload["issuer_public_key"])
	if issuerKey != "" && reportKey != "" && reportKey != issuerKey {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Issuer report key mismatch"})
		return
	}
	requestID := core.NewUUID()
	okValidate, validation, validationErr := s.server.MakeRemoteRequestJSON(issuerAddress, "/exchange/validate", "POST", map[string]any{
		"voucher_ids":       voucherIDs,
		"target_server":     targetServer,
		"client_signature":  clientSignature,
		"client_public_key": clientPublicKey,
		"timestamp":         timestamp,
		"request_id":        requestID,
	})
	if !okValidate || !asBool(validation["success"]) {
		errorMsg := asString(validation["error"])
		if errorMsg == "" {
			errorMsg = "Issuer validation failed: " + validationErr
		}
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": errorMsg})
		return
	}
	issuerMultiplier := asFloat(reportPayload["multiplier"])
	if issuerMultiplier <= 0 {
		issuerMultiplier = 1.0
	}
	localMultiplier := s.server.GetEconomyMultiplier()
	rate := localMultiplier / math.Max(issuerMultiplier, 0.0001)
	convertedValue := int(math.Floor(float64(totalValue) * rate))
	if convertedValue <= 0 {
		conn.Emit("exchange_quote", map[string]any{"success": false, "error": "Conversion result too small"})
		return
	}
	feeAmount := int(math.Max(float64(s.server.ExchangeFeeMin), math.Ceil(float64(convertedValue)*s.server.ExchangeFeeRate)))
	receiveAmount := convertedValue - feeAmount
	if receiveAmount < 0 {
		receiveAmount = 0
	}
	quoteID := core.NewUUID()
	expiresAt := nowSec() + 600
	s.mu.Lock()
	s.exchangeQuotes[quoteID] = map[string]any{
		"issuer":                       issuer,
		"issuer_address":               issuerAddress,
		"issuer_public_key":            defaultStr(reportKey, issuerKey),
		"owner":                        owner,
		"client_username":              client.Username,
		"voucher_ids":                  voucherIDs,
		"total_value":                  totalValue,
		"rate":                         rate,
		"converted_value":              convertedValue,
		"fee_amount":                   feeAmount,
		"receive_amount":               receiveAmount,
		"exchange_token":               castMap(validation["token"]),
		"exchange_signature":           asString(validation["signature"]),
		"issuer_reserved_contract_id":  asString(validation["contract_id"]),
		"issuer_owner_key_contract_id": asString(validation["owner_key_contract_id"]),
		"expires_at":                   expiresAt,
		"client_contract_id":           clientContractID,
	}
	s.mu.Unlock()
	conn.Emit("exchange_quote", map[string]any{
		"success":            true,
		"quote_id":           quoteID,
		"issuer":             issuer,
		"rate":               rate,
		"converted_value":    convertedValue,
		"fee_amount":         feeAmount,
		"receive_amount":     receiveAmount,
		"expires_at":         expiresAt,
		"client_contract_id": clientContractID,
	})
}

func (s *Server) handleConfirmExchange(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("exchange_complete", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	quoteID := asString(data["quote_id"])
	if quoteID == "" {
		conn.Emit("exchange_complete", map[string]any{"success": false, "error": "Quote not found"})
		return
	}
	s.mu.Lock()
	quote := s.exchangeQuotes[quoteID]
	s.mu.Unlock()
	if quote == nil {
		conn.Emit("exchange_complete", map[string]any{"success": false, "error": "Quote not found"})
		return
	}
	if quoteUser := asString(quote["client_username"]); quoteUser != "" && quoteUser != client.Username {
		conn.Emit("exchange_complete", map[string]any{"success": false, "error": "Quote does not belong to authenticated user"})
		return
	}
	if nowSec() > asFloat(quote["expires_at"]) {
		conn.Emit("exchange_complete", map[string]any{"success": false, "error": "Quote expired"})
		return
	}
	issuer := asString(quote["issuer"])
	issuerAddress := asString(quote["issuer_address"])
	if issuerAddress == "" {
		issuerAddress = issuer
	}
	tokenPayload := castMap(quote["exchange_token"])
	tokenSignature := asString(quote["exchange_signature"])
	okConfirm, confirmData, _ := s.server.MakeRemoteRequestJSON(issuerAddress, "/exchange/confirm", "POST", map[string]any{
		"token":     tokenPayload,
		"signature": tokenSignature,
	})
	if !okConfirm || !asBool(confirmData["success"]) {
		errorMsg := asString(confirmData["error"])
		if errorMsg == "" {
			errorMsg = "Issuer confirmation failed"
		}
		conn.Emit("exchange_complete", map[string]any{"success": false, "error": errorMsg})
		return
	}
	issuerContractID := asString(castMap(confirmData["payload"])["contract_id"])
	issuerReservedContractID := asString(quote["issuer_reserved_contract_id"])
	issuerOwnerKeyContractID := asString(quote["issuer_owner_key_contract_id"])
	if issuerReservedContractID != "" {
		_, _ = s.server.SyncContractWithServer(issuerAddress, issuerReservedContractID)
	}
	if issuerOwnerKeyContractID != "" {
		_, _ = s.server.SyncContractWithServer(issuerAddress, issuerOwnerKeyContractID)
	}
	if issuerContractID != "" {
		_, _ = s.server.SyncContractWithServer(issuerAddress, issuerContractID)
	}
	encodeContractBase64 := func(contractID string) string {
		if contractID == "" {
			return ""
		}
		contractBytes := s.server.GetContractBytes(contractID)
		if len(contractBytes) == 0 && issuerAddress != "" {
			okRaw, rawContract, _ := s.server.MakeRemoteRequestBytes(issuerAddress, "/contract/"+url.PathEscape(contractID), http.MethodGet)
			if okRaw && len(rawContract) > 0 {
				contractBytes = rawContract
			}
		}
		if len(contractBytes) == 0 {
			return ""
		}
		return base64.StdEncoding.EncodeToString(contractBytes)
	}
	clientContractID := asString(quote["client_contract_id"])
	exchangeContractBytes := s.server.GetContractBytes(clientContractID)
	exchangeHash := ""
	exchangeB64 := ""
	if len(exchangeContractBytes) > 0 {
		sum := sha256.Sum256(exchangeContractBytes)
		exchangeHash = hex.EncodeToString(sum[:])
		exchangeB64 = base64.StdEncoding.EncodeToString(exchangeContractBytes)
	}
	receiveAmount := asInt(quote["receive_amount"])
	ownerKey := client.PublicKey
	feeAmount, selectorFee, feeSource, adjustedReceive := s.server.AllocateSignatureFees(receiveAmount)
	offer := s.server.CreateVoucherOfferWithStatus(
		client.Username,
		ownerKey,
		adjustedReceive,
		"exchange_from:"+issuer,
		nil,
		map[string]any{
			"type":                            "exchange",
			"issuer":                          issuer,
			"rate":                            asFloat(quote["rate"]),
			"fee":                             asInt(quote["fee_amount"]),
			"issuer_voucher_ids":              quote["voucher_ids"],
			"lineage_origin":                  "exchange_in",
			"exchange_contract_id":            issuerContractID,
			"dkvhps_disclosure_contract_id":   clientContractID,
			"dkvhps_disclosure_contract_hash": exchangeHash,
		},
		"",
		"withheld",
	)
	s.server.AllocateExchangeFee(asInt(quote["fee_amount"]))
	var persistedOfferStatus string
	if err := s.server.DB.QueryRow(`SELECT status FROM hps_voucher_offers WHERE offer_id = ?`, asString(offer["offer_id"])).Scan(&persistedOfferStatus); err != nil || persistedOfferStatus != "withheld" {
		s.rollbackConfirmedExchange(
			issuerAddress,
			issuer,
			asString(tokenPayload["token_id"]),
			asString(quote["owner"]),
			asInt(quote["total_value"]),
			asInt(quote["fee_amount"]),
			asString(offer["offer_id"]),
			"target_offer_persist_failed",
		)
		conn.Emit("exchange_complete", map[string]any{
			"success": false,
			"error":   "Falha ao registrar o voucher local do cÃƒÂ¢mbio. O valor original foi devolvido.",
		})
		s.mu.Lock()
		delete(s.exchangeQuotes, quoteID)
		s.mu.Unlock()
		return
	}
	interServerPayload := map[string]any{
		"issuer":                          issuer,
		"issuer_address":                  issuerAddress,
		"issuer_public_key":               asString(quote["issuer_public_key"]),
		"exchange_token":                  quote["exchange_token"],
		"exchange_signature":              asString(quote["exchange_signature"]),
		"issuer_token_id":                 asString(tokenPayload["token_id"]),
		"issuer_owner":                    asString(quote["owner"]),
		"issuer_total_value":              asInt(quote["total_value"]),
		"origin_username":                 asString(quote["client_username"]),
		"issuer_voucher_ids":              quote["voucher_ids"],
		"issuer_reserved_contract_id":     issuerReservedContractID,
		"issuer_reserved_contract":        encodeContractBase64(issuerReservedContractID),
		"issuer_out_contract_id":          issuerContractID,
		"issuer_out_contract":             encodeContractBase64(issuerContractID),
		"issuer_owner_key_contract_id":    issuerOwnerKeyContractID,
		"issuer_owner_key_contract":       encodeContractBase64(issuerOwnerKeyContractID),
		"exchange_contract_id":            clientContractID,
		"exchange_contract_hash":          exchangeHash,
		"exchange_contract_content":       exchangeB64,
		"dkvhps_disclosure_contract_id":   clientContractID,
		"dkvhps_disclosure_contract_hash": exchangeHash,
		"exchange_offer_id":               asString(offer["offer_id"]),
		"exchange_offer_voucher_id":       asString(offer["voucher_id"]),
		"exchange_fee_amount":             asInt(quote["fee_amount"]),
	}
	transferID := core.NewUUID()
	nowTs := nowSec()
	lockedVoucherIDs := []string{asString(offer["voucher_id"])}
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO monetary_transfers
		(transfer_id, transfer_type, sender, receiver, amount, created_at, status, contract_id, locked_voucher_ids, fee_amount, selector_fee_amount, fee_source, inter_server_payload, deadline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transferID, "exchange_in", issuer, client.Username, adjustedReceive, nowTs, "awaiting_selector", nil,
		toJSONString(lockedVoucherIDs), feeAmount, selectorFee, feeSource, toJSONString(interServerPayload), nowTs+60.0)
	if _, ok := s.getMonetaryTransfer(transferID); !ok {
		s.rollbackConfirmedExchange(
			issuerAddress,
			issuer,
			asString(tokenPayload["token_id"]),
			asString(quote["owner"]),
			asInt(quote["total_value"]),
			asInt(quote["fee_amount"]),
			asString(offer["offer_id"]),
			"target_transfer_persist_failed",
		)
		conn.Emit("exchange_complete", map[string]any{
			"success": false,
			"error":   "Falha ao registrar a transferÃƒÂªncia local do cÃƒÂ¢mbio. O valor original foi devolvido.",
		})
		s.mu.Lock()
		delete(s.exchangeQuotes, quoteID)
		s.mu.Unlock()
		return
	}
	s.requestSelectorForTransfer(transferID, issuer, client.Username)
	currentStatus := "awaiting_selector"
	currentAssignedMiner := ""
	if transferNow, okNow := s.getMonetaryTransfer(transferID); okNow {
		currentStatus = asString(transferNow["status"])
		currentAssignedMiner = asString(transferNow["assigned_miner"])
	}
	if currentStatus == "" {
		currentStatus = "awaiting_selector"
	}
	s.emitToUser(client.Username, "monetary_transfer_pending", map[string]any{
		"transfer_id":    transferID,
		"transfer_type":  "exchange_in",
		"sender":         issuer,
		"receiver":       client.Username,
		"amount":         adjustedReceive,
		"assigned_miner": currentAssignedMiner,
		"status":         currentStatus,
	})
	contractID := s.server.SaveServerContract("hps_exchange_in", []core.ContractDetail{
		{Key: "CLIENT", Value: client.Username},
		{Key: "ISSUER", Value: issuer},
		{Key: "TOTAL_VALUE", Value: asInt(quote["total_value"])},
		{Key: "RATE", Value: asFloat(quote["rate"])},
		{Key: "FEE", Value: asInt(quote["fee_amount"])},
		{Key: "RECEIVED", Value: adjustedReceive},
		{Key: "MINER_FEE", Value: feeAmount},
		{Key: "SELECTOR_FEE", Value: selectorFee},
		{Key: "FEE_SOURCE", Value: feeSource},
		{Key: "VOUCHERS", Value: toJSONString(quote["voucher_ids"])},
		{Key: "DKVHPS_DISCLOSURE_CONTRACT_ID", Value: clientContractID},
		{Key: "DKVHPS_DISCLOSURE_CONTRACT_HASH", Value: exchangeHash},
		{Key: "CLIENT_CONTRACT_ID", Value: clientContractID},
		{Key: "ISSUER_CONTRACT_ID", Value: issuerContractID},
	}, asString(offer["voucher_id"]))
	conn.Emit("exchange_pending", map[string]any{
		"success":         true,
		"stage":           currentStatus,
		"quote_id":        quoteID,
		"contract_id":     contractID,
		"new_voucher_id":  offer["voucher_id"],
		"received_amount": adjustedReceive,
		"transfer_id":     transferID,
		"status":          currentStatus,
		"assigned_miner":  currentAssignedMiner,
	})
	s.mu.Lock()
	delete(s.exchangeQuotes, quoteID)
	s.mu.Unlock()
}

func (s *Server) handleRequestLiveSessionQuote(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("live_session_quote", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}

	appName := strings.TrimSpace(asString(data["app_name"]))
	if appName == "" {
		conn.Emit("live_session_quote", map[string]any{"success": false, "error": "Missing app_name"})
		return
	}
	if !strings.HasPrefix(appName, "live:") {
		appName = "live:" + appName
	}

	duration := asFloat(data["duration"])
	if duration <= 0 {
		duration = 60
	}
	if duration > 3600 {
		duration = 3600
	}
	maxSegmentSize := asInt(data["max_segment_size"])
	if maxSegmentSize <= 0 {
		maxSegmentSize = 1_048_576
	}
	if maxSegmentSize > maxUploadContentBytes {
		maxSegmentSize = maxUploadContentBytes
	}
	desiredInterval := asFloat(data["interval"])
	if desiredInterval <= 0 {
		desiredInterval = 5
	}
	if desiredInterval < 0.5 {
		desiredInterval = 0.5
	}

	segments := int(math.Ceil(duration / desiredInterval))
	if segments < 1 {
		segments = 1
	}
	baseCost := 1
	totalCost := segments * baseCost

	sessionID := "live-" + core.NewUUID()
	expiresAt := nowSec() + 120.0
	quote := map[string]any{
		"session_id":       sessionID,
		"app_name":         appName,
		"duration":         duration,
		"max_segment_size": maxSegmentSize,
		"desired_interval": desiredInterval,
		"total_cost":       totalCost,
		"owner":            client.Username,
		"created_at":       nowSec(),
		"expires_at":       expiresAt,
	}
	s.mu.Lock()
	s.liveSessionQuotes[sessionID] = quote
	s.mu.Unlock()

	conn.Emit("live_session_quote", map[string]any{
		"success":          true,
		"session_id":       sessionID,
		"app_name":         appName,
		"duration":         duration,
		"max_segment_size": maxSegmentSize,
		"desired_interval": desiredInterval,
		"total_cost":       totalCost,
		"expires_at":       expiresAt,
	})
}

func (s *Server) handlePayLiveSession(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("live_session_paid", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}

	sessionID := asString(data["session_id"])
	if sessionID == "" {
		conn.Emit("live_session_paid", map[string]any{"success": false, "error": "Missing session_id"})
		return
	}

	s.mu.Lock()
	quote := s.liveSessionQuotes[sessionID]
	s.mu.Unlock()
	if quote == nil {
		conn.Emit("live_session_paid", map[string]any{"success": false, "error": "Live quote not found"})
		return
	}
	if asString(quote["owner"]) != client.Username {
		conn.Emit("live_session_paid", map[string]any{"success": false, "error": "Quote owner mismatch"})
		return
	}
	if nowSec() > asFloat(quote["expires_at"]) {
		conn.Emit("live_session_paid", map[string]any{"success": false, "error": "Live quote expired"})
		return
	}

	totalCost := asInt(quote["total_cost"])
	voucherIDs := toStringSlice(data["voucher_ids"])
	if totalCost > 0 {
		if len(voucherIDs) == 0 {
			conn.Emit("live_session_paid", map[string]any{"success": false, "error": "Missing voucher_ids"})
			return
		}
		paymentSessionID := "livepay-" + sessionID
		okReserve, totalValue, reserveErr := s.server.ReserveVouchersForSession(client.Username, paymentSessionID, voucherIDs)
		if !okReserve {
			conn.Emit("live_session_paid", map[string]any{"success": false, "error": reserveErr})
			return
		}
		if totalValue < totalCost {
			s.server.ReleaseVouchersForSession(paymentSessionID)
			conn.Emit("live_session_paid", map[string]any{"success": false, "error": "Insufficient balance"})
			return
		}
		s.server.MarkVouchersSpent(paymentSessionID)
		changeValue := totalValue - totalCost
		if changeValue > 0 {
			s.server.IssueChangeOffer(
				client.Username,
				changeValue,
				"live_session_change",
				paymentSessionID,
				"hps_spend_refund",
				[]core.ContractDetail{
					{Key: "TYPE", Value: "live_session"},
					{Key: "APP", Value: asString(quote["app_name"])},
					{Key: "SESSION_ID", Value: sessionID},
					{Key: "TOTAL_COST", Value: totalCost},
				},
			)
			s.emitPendingVoucherOffers(client.Username)
		}
	}

	s.server.SaveServerContract("live_session_paid", []core.ContractDetail{
		{Key: "USER", Value: client.Username},
		{Key: "APP", Value: asString(quote["app_name"])},
		{Key: "SESSION_ID", Value: sessionID},
		{Key: "TOTAL_COST", Value: totalCost},
		{Key: "DURATION", Value: asFloat(quote["duration"])},
		{Key: "MAX_SEGMENT_SIZE", Value: asInt(quote["max_segment_size"])},
		{Key: "INTERVAL", Value: asFloat(quote["desired_interval"])},
		{Key: "VOUCHERS", Value: toJSONString(voucherIDs)},
	}, sessionID)

	liveSession := map[string]any{
		"session_id":       sessionID,
		"owner":            client.Username,
		"app_name":         asString(quote["app_name"]),
		"duration":         asFloat(quote["duration"]),
		"max_segment_size": asInt(quote["max_segment_size"]),
		"desired_interval": asFloat(quote["desired_interval"]),
		"total_cost":       totalCost,
		"voucher_ids":      voucherIDs,
		"start_time":       nowSec(),
		"expires_at":       nowSec() + asFloat(quote["duration"]),
	}

	s.mu.Lock()
	delete(s.liveSessionQuotes, sessionID)
	s.liveSessions[sessionID] = liveSession
	s.mu.Unlock()

	conn.Emit("live_session_paid", map[string]any{
		"success":    true,
		"session_id": sessionID,
		"app_name":   asString(quote["app_name"]),
		"total_cost": totalCost,
	})
	conn.Emit("live_upload_receipt", map[string]any{
		"session_id": sessionID,
		"status":     "prepaid_active",
		"cost":       totalCost,
	})
	s.emitWalletSyncToConn(conn, client.Username)
	conn.Emit("economy_report", s.server.BuildEconomyReport())

	duration := asFloat(quote["duration"])
	if duration > 0 {
		go func(session string, owner string, spent int, wait float64) {
			time.Sleep(time.Duration(wait * float64(time.Second)))
			s.mu.Lock()
			_, exists := s.liveSessions[session]
			if exists {
				delete(s.liveSessions, session)
			}
			s.mu.Unlock()
			if exists {
				s.emitToUser(owner, "live_session_settlement", map[string]any{
					"session_id":    session,
					"spent_value":   spent,
					"refund_value":  0,
					"settled_at":    nowSec(),
					"settled_final": true,
				})
			}
		}(sessionID, client.Username, totalCost, duration)
	}
}

func (s *Server) assignMinerForTransfer(transferID, sender, receiver string, allowPartiesFallback bool) string {
	return s.assignMinerForTransferExcluding(transferID, sender, receiver, allowPartiesFallback, nil)
}

func (s *Server) assignMinerForTransferExcluding(transferID, sender, receiver string, allowPartiesFallback bool, excluded map[string]struct{}) string {
	if transferID == "" {
		return ""
	}
	nowTs := nowSec()
	transfer, _ := s.getMonetaryTransfer(transferID)
	miner := ""
	candidates := s.listEligibleMiners(sender, receiver, false)
	if len(candidates) == 0 && allowPartiesFallback {
		candidates = s.listEligibleMiners(sender, receiver, true)
	}
	for _, candidate := range candidates {
		if excluded != nil {
			if _, skip := excluded[strings.ToLower(strings.TrimSpace(candidate))]; skip {
				continue
			}
		}
		miner = candidate
		break
	}
	if miner == "" {
		return ""
	}
	minerDeadline := nowTs + minerSignatureWindowSeconds(transfer)
	_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
		SET assigned_miner = ?, miner_deadline = ?, deadline = COALESCE(deadline, ?), status = ?
		WHERE transfer_id = ?`, miner, minerDeadline, nowTs+60.0, "pending_signature", transferID)
	return miner
}

func (s *Server) retryExchangeMinerAssignment(transfer map[string]any, failedMiner, reason string) bool {
	if transfer == nil || !strings.EqualFold(asString(transfer["transfer_type"]), "exchange_in") {
		return false
	}
	transferID := asString(transfer["transfer_id"])
	sender := asString(transfer["sender"])
	receiver := asString(transfer["receiver"])
	if transferID == "" {
		return false
	}
	var attempts int
	_ = s.server.DB.QueryRow(`SELECT COALESCE(selector_attempts, 0) FROM monetary_transfers WHERE transfer_id = ?`, transferID).Scan(&attempts)
	if attempts >= 3 {
		log.Printf("selector flow: exchange retry limit reached transfer=%s failed_miner=%s reason=%s attempts=%d",
			transferID, failedMiner, reason, attempts)
		return false
	}
	excluded := map[string]struct{}{}
	if failedMiner = strings.ToLower(strings.TrimSpace(failedMiner)); failedMiner != "" {
		excluded[failedMiner] = struct{}{}
	}
	nextMiner := s.assignMinerForTransferExcluding(transferID, sender, receiver, false, excluded)
	if nextMiner == "" {
		log.Printf("selector flow: exchange retry no alternative miner transfer=%s failed_miner=%s reason=%s attempts=%d",
			transferID, failedMiner, reason, attempts)
		return false
	}
	_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
		SET selector_attempts = COALESCE(selector_attempts, 0) + 1
		WHERE transfer_id = ?`, transferID)
	log.Printf("selector flow: exchange retry reassigned transfer=%s failed_miner=%s next_miner=%s reason=%s previous_attempts=%d",
		transferID, failedMiner, nextMiner, reason, attempts)
	s.server.SaveServerContract("exchange_miner_reassigned", []core.ContractDetail{
		{Key: "TRANSFER_ID", Value: transferID},
		{Key: "FAILED_MINER", Value: failedMiner},
		{Key: "NEXT_MINER", Value: nextMiner},
		{Key: "REASON", Value: reason},
		{Key: "ATTEMPTS", Value: attempts + 1},
	}, transferID)
	s.emitAssignedMiner(transferID, nextMiner)
	return true
}

func minerSignatureWindowSeconds(transfer map[string]any) float64 {
	if strings.EqualFold(asString(transfer["transfer_type"]), "exchange_in") {
		return 30.0
	}
	return 5.0
}

func (s *Server) requestSelectorForTransfer(transferID, sender, receiver string) {
	if transferID == "" {
		return
	}
	log.Printf("selector flow: request transfer=%s sender=%s receiver=%s", transferID, sender, receiver)
	transfer, okTransfer := s.getMonetaryTransfer(transferID)
	if okTransfer && asString(transfer["transfer_type"]) == "exchange_in" {
		// Modo deterministico para cambio: elimina espera por seletor e parte
		// diretamente para atribuicao de minerador elegivel.
		log.Printf("selector flow: exchange direct assignment transfer=%s", transferID)
		s.assignMinerFallback(transferID, sender, receiver, "exchange_direct_assignment")
		return
	}
	var attempts int
	_ = s.server.DB.QueryRow(`SELECT selector_attempts FROM monetary_transfers WHERE transfer_id = ?`, transferID).Scan(&attempts)
	if attempts >= 3 {
		log.Printf("selector flow: fallback by attempts transfer=%s attempts=%d", transferID, attempts)
		s.assignMinerFallback(transferID, sender, receiver, "selector_timeout")
		return
	}
	selectors := s.listEligibleSelectors(sender, receiver, false)
	if len(selectors) == 0 {
		log.Printf("selector flow: no selectors transfer=%s", transferID)
		s.assignMinerFallback(transferID, sender, receiver, "no_selectors")
		return
	}
	miners := s.listEligibleMiners(sender, receiver, false)
	if len(miners) == 0 {
		miners = s.listEligibleMiners(sender, receiver, true)
	}
	if len(miners) == 0 {
		log.Printf("selector flow: no miners transfer=%s", transferID)
		s.assignMinerFallback(transferID, sender, receiver, "no_miners")
		return
	}
	// Evita sobreposicao entre papeis: seletor e candidato a minerador nao
	// devem ser a mesma pessoa no fluxo normal.
	minerSet := make(map[string]struct{}, len(miners))
	for _, m := range miners {
		minerSet[strings.ToLower(strings.TrimSpace(m))] = struct{}{}
	}
	disjointSelectors := make([]string, 0, len(selectors))
	for _, sel := range selectors {
		key := strings.ToLower(strings.TrimSpace(sel))
		if _, overlap := minerSet[key]; overlap {
			continue
		}
		disjointSelectors = append(disjointSelectors, sel)
	}
	if len(disjointSelectors) == 0 {
		log.Printf("selector flow: selector/miner overlap transfer=%s selectors=%d miners=%d -> fallback",
			transferID, len(selectors), len(miners))
		s.assignMinerFallback(transferID, sender, receiver, "selector_miner_overlap")
		return
	}
	selectors = disjointSelectors
	transfer, okTransfer = s.getMonetaryTransfer(transferID)
	if okTransfer && asString(transfer["transfer_type"]) == "exchange_in" {
		if len(selectors) <= 1 || len(miners) <= 1 {
			log.Printf("selector flow: exchange immediate fallback transfer=%s selectors=%d miners=%d", transferID, len(selectors), len(miners))
			s.assignMinerFallback(transferID, sender, receiver, "exchange_low_population")
			return
		}
	}
	// Precaucao probabilistica: decide imediatamente quando a chance de concluir
	// com seletor eh baixa, evitando espera longa sem progresso.
	confidence := estimateSelectorFlowConfidence(len(selectors), len(miners), attempts)
	if confidence < 0.60 {
		log.Printf("selector flow: precaution fallback transfer=%s confidence=%.3f selectors=%d miners=%d attempts=%d",
			transferID, confidence, len(selectors), len(miners), attempts)
		s.server.SaveServerContract("miner_selector_precaution", []core.ContractDetail{
			{Key: "TRANSFER_ID", Value: transferID},
			{Key: "REASON", Value: "low_confidence"},
			{Key: "CONFIDENCE", Value: confidence},
			{Key: "SELECTORS", Value: len(selectors)},
			{Key: "MINERS", Value: len(miners)},
			{Key: "ATTEMPTS", Value: attempts},
		}, transferID)
		s.assignMinerFallback(transferID, sender, receiver, "precaution_low_confidence")
		return
	}
	selectorListJSON := toJSONString(selectors)
	minerListJSON := toJSONString(miners)
	selectorListHash := sha256HexString(selectorListJSON)
	minerListHash := sha256HexString(minerListJSON)
	seed := sha256.Sum256([]byte("selector:" + transferID))
	baseIndex := int(binary.BigEndian.Uint64(seed[:8]) % uint64(len(selectors)))
	index := (baseIndex + attempts) % len(selectors)
	selector := selectors[index]
	serverNonce := randomHex(32)
	commit := sha256HexString(serverNonce)
	deadline := nowSec() + 30.0
	_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
		SET selector_username = ?, selector_status = ?, selector_deadline = ?, selector_commit = ?, selector_nonce = ?,
		    selector_seed = ?, selector_list_json = ?, miner_list_json = ?, selector_attempts = selector_attempts + 1
		WHERE transfer_id = ?`,
		selector, "requested", deadline, commit, serverNonce, hex.EncodeToString(seed[:]), selectorListJSON, minerListJSON, transferID)
	s.server.SaveServerContract("miner_selector_assignment", []core.ContractDetail{
		{Key: "TRANSFER_ID", Value: transferID},
		{Key: "SELECTOR", Value: selector},
		{Key: "SELECTOR_LIST_HASH", Value: selectorListHash},
		{Key: "SELECTOR_INDEX", Value: index},
		{Key: "SELECTOR_COUNT", Value: len(selectors)},
		{Key: "COMMIT", Value: commit},
	}, transferID)
	transfer, ok := s.getMonetaryTransfer(transferID)
	if ok {
		s.emitToUser(selector, "miner_selector_request", map[string]any{
			"transfer_id":       transferID,
			"transfer_type":     asString(transfer["transfer_type"]),
			"sender":            sender,
			"receiver":          receiver,
			"amount":            asInt(transfer["amount"]),
			"fee_amount":        asInt(transfer["fee_amount"]),
			"selector_fee":      asInt(transfer["selector_fee_amount"]),
			"fee_source":        asString(transfer["fee_source"]),
			"selector_commit":   commit,
			"selector_seed":     hex.EncodeToString(seed[:]),
			"selector_deadline": deadline,
			"miner_list":        miners,
			"miner_list_hash":   minerListHash,
			"reward":            asInt(transfer["selector_fee_amount"]),
			"reputation_bonus":  10,
		})
	}
	s.notifyMonetaryTransferUpdate(transferID, "awaiting_selector", "", nil)
	go s.enforceSelectorDecisionDeadline(transferID, sender, receiver, deadline)
}

func (s *Server) assignMinerFallback(transferID, sender, receiver, reason string) {
	log.Printf("selector flow: assignMinerFallback transfer=%s reason=%s sender=%s receiver=%s", transferID, reason, sender, receiver)
	// Safety rule: never assign sender/receiver as miner in fallback mode.
	miner := s.assignMinerForTransfer(transferID, sender, receiver, false)
	if miner == "" {
		log.Printf("selector flow: fallback failed (no miner) transfer=%s reason=%s", transferID, reason)
		_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
			SET status = ?, selector_status = ?, selector_deadline = NULL
			WHERE transfer_id = ?`, "expired", "failed", transferID)
		s.rollbackSpendHpsTransfer(transferID, reason)
		if transfer, ok := s.getMonetaryTransfer(transferID); ok && asString(transfer["transfer_type"]) == "exchange_in" {
			s.rollbackExchangeTransfer(transfer, reason)
		}
		s.notifyMonetaryTransferUpdate(transferID, "expired", reason, map[string]any{
			"reason":      reason,
			"transfer_id": transferID,
		})
		if transfer, ok := s.getMonetaryTransfer(transferID); ok && asString(transfer["transfer_type"]) == "exchange_in" {
			payload := map[string]any{
				"success":     false,
				"stage":       "failed",
				"transfer_id": transferID,
				"error":       "Nenhum minerador elegÃ­vel disponÃ­vel para finalizar o cÃ¢mbio.",
			}
			s.emitToUser(asString(transfer["receiver"]), "exchange_complete", payload)
			s.relayExchangeEventToIssuer(transfer, "exchange_complete", payload)
		}
		return
	}
	log.Printf("selector flow: fallback assigned miner transfer=%s miner=%s reason=%s", transferID, miner, reason)
	s.emitAssignedMiner(transferID, miner)
	s.server.SaveServerContract("miner_selector_fallback", []core.ContractDetail{
		{Key: "TRANSFER_ID", Value: transferID},
		{Key: "MINER", Value: miner},
		{Key: "REASON", Value: reason},
	}, transferID)
}

func (s *Server) emitAssignedMiner(transferID, miner string) {
	transfer, ok := s.getMonetaryTransfer(transferID)
	if !ok {
		return
	}
	sender := asString(transfer["sender"])
	receiver := asString(transfer["receiver"])
	interServerPayload := castMap(transfer["inter_server_payload"])
	exchangeOfferVoucherID := asString(interServerPayload["exchange_offer_voucher_id"])
	isExchangeIn := strings.EqualFold(asString(transfer["transfer_type"]), "exchange_in") || exchangeOfferVoucherID != ""
	log.Printf("selector flow: emitAssignedMiner transfer=%s sender=%s receiver=%s miner=%s status=%s",
		transferID, sender, receiver, miner, asString(transfer["status"]))
	log.Printf("selector flow: emitAssignedMiner metadata transfer=%s type=%s exchange=%t offer_voucher=%s",
		transferID, asString(transfer["transfer_type"]), isExchangeIn, exchangeOfferVoucherID)
	log.Printf("selector flow: emitAssignedMiner notify transfer=%s miner=%s", transferID, miner)
	minerTargets := s.emitToUserCount(miner, "miner_signature_request", map[string]any{
		"transfer_id":        transferID,
		"transfer_type":      asString(transfer["transfer_type"]),
		"sender":             sender,
		"receiver":           receiver,
		"amount":             asInt(transfer["amount"]),
		"fee_amount":         asInt(transfer["fee_amount"]),
		"selector_fee":       asInt(transfer["selector_fee_amount"]),
		"fee_source":         asString(transfer["fee_source"]),
		"contract_id":        asString(transfer["contract_id"]),
		"locked_voucher_ids": transfer["locked_voucher_ids"],
		"deadline":           asFloat(transfer["deadline"]),
		"miner_deadline":     asFloat(transfer["miner_deadline"]),
		"inter_server":       transfer["inter_server_payload"],
		"pending_signatures": asInt(s.server.GetMinerStats(miner)["pending_signatures"]),
	})
	log.Printf("selector flow: miner_signature_request targets transfer=%s miner=%s targets=%d", transferID, miner, minerTargets)
	if minerTargets == 0 {
		log.Printf("selector flow: miner unreachable transfer=%s miner=%s exchange=%t", transferID, miner, isExchangeIn)
		if isExchangeIn && s.retryExchangeMinerAssignment(transfer, miner, "miner_unreachable") {
			return
		}
		_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
			SET status = ?, miner_deadline = NULL
			WHERE transfer_id = ?`, "expired", transferID)
		s.rollbackSpendHpsTransfer(transferID, "miner_unreachable")
		s.rollbackExchangeTransfer(transfer, "miner_unreachable")
		s.notifyMonetaryTransferUpdate(transferID, "expired", "miner_unreachable", map[string]any{
			"miner":       miner,
			"transfer_id": transferID,
		})
		if isExchangeIn {
			payload := map[string]any{
				"success":     false,
				"stage":       "failed",
				"transfer_id": transferID,
				"error":       "Minerador atribuÃ­do indisponÃ­vel para assinatura.",
			}
			s.emitToUser(receiver, "exchange_complete", payload)
			s.relayExchangeEventToIssuer(transfer, "exchange_complete", payload)
		}
		return
	}
	pendingPayload := map[string]any{
		"transfer_id":    transferID,
		"transfer_type":  asString(transfer["transfer_type"]),
		"sender":         sender,
		"receiver":       receiver,
		"amount":         asInt(transfer["amount"]),
		"assigned_miner": miner,
		"status":         "pending_signature",
	}
	s.emitToUser(sender, "monetary_transfer_pending", pendingPayload)
	s.emitToUser(receiver, "monetary_transfer_pending", pendingPayload)
	s.notifyMonetaryTransferUpdate(transferID, "pending_signature", "", nil)
	if isExchangeIn {
		exchangePendingPayload := map[string]any{
			"success":        true,
			"stage":          "assigned",
			"transfer_id":    transferID,
			"status":         "pending_signature",
			"assigned_miner": miner,
			"new_voucher_id": exchangeOfferVoucherID,
		}
		log.Printf("selector flow: exchange_pending transfer=%s receiver=%s miner=%s offer_voucher=%s",
			transferID, receiver, miner, exchangeOfferVoucherID)
		s.emitToUser(receiver, "exchange_pending", exchangePendingPayload)
		s.relayExchangeEventToIssuer(transfer, "monetary_transfer_pending", pendingPayload)
		s.relayExchangeEventToIssuer(transfer, "exchange_pending", exchangePendingPayload)
	}
	if asFloat(transfer["miner_deadline"]) > 0 {
		go s.enforceMinerSignatureDeadline(transferID, miner, asFloat(transfer["miner_deadline"]))
	}
}

func (s *Server) listEligibleSelectors(sender, receiver string, allowParties bool) []string {
	targets := make([]string, 0)
	s.mu.Lock()
	for _, state := range s.clients {
		if state == nil || !state.Authenticated {
			continue
		}
		username := trim(state.Username)
		if username == "" {
			continue
		}
		if !allowParties && (strings.EqualFold(username, sender) || strings.EqualFold(username, receiver)) {
			continue
		}
		targets = append(targets, username)
	}
	s.mu.Unlock()
	sort.Strings(targets)
	return targets
}

func (s *Server) listEligibleMiners(sender, receiver string, allowParties bool) []string {
	nowTs := nowSec()
	onlineUsers := map[string]struct{}{}
	s.mu.Lock()
	for _, state := range s.clients {
		if state == nil || !state.Authenticated {
			continue
		}
		username := trim(state.Username)
		if username == "" {
			continue
		}
		onlineUsers[strings.ToLower(username)] = struct{}{}
	}
	s.mu.Unlock()
	seen := map[string]struct{}{}
	rows, err := s.server.DB.Query(`SELECT username FROM miner_stats
		WHERE username NOT IN (?, ?)
		  AND (banned_until IS NULL OR banned_until < ?)
		ORDER BY pending_signatures ASC, last_updated ASC`, sender, receiver, nowTs)
	if err != nil {
		rows = nil
	}
	miners := make([]string, 0)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var username string
			if rows.Scan(&username) != nil || username == "" {
				continue
			}
			username = trim(username)
			if username == "" || (!allowParties && (strings.EqualFold(username, sender) || strings.EqualFold(username, receiver))) {
				continue
			}
			if _, online := onlineUsers[strings.ToLower(username)]; !online {
				continue
			}
			if _, exists := seen[username]; exists {
				continue
			}
			seen[username] = struct{}{}
			miners = append(miners, username)
		}
	}

	// Fallback: online nodes marked as miner in socket state.
	s.mu.Lock()
	for _, state := range s.clients {
		if state == nil || !state.Authenticated {
			continue
		}
		username := trim(state.Username)
		if username == "" || (!allowParties && (strings.EqualFold(username, sender) || strings.EqualFold(username, receiver))) {
			continue
		}
		if !strings.EqualFold(trim(state.NodeType), "miner") {
			continue
		}
		if _, exists := seen[username]; exists {
			continue
		}
		seen[username] = struct{}{}
		miners = append(miners, username)
	}
	s.mu.Unlock()

	sort.Strings(miners)
	return miners
}

func sha256HexString(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func estimateSelectorFlowConfidence(selectors, miners, attempts int) float64 {
	if selectors <= 0 || miners <= 0 {
		return 0
	}
	selectorScore := 0.25 + (0.22 * float64(selectors))
	if selectorScore > 0.95 {
		selectorScore = 0.95
	}
	minerScore := 0.30 + (0.18 * float64(miners))
	if minerScore > 0.95 {
		minerScore = 0.95
	}
	attemptPenalty := 1.0 - (0.18 * float64(attempts))
	if attemptPenalty < 0.20 {
		attemptPenalty = 0.20
	}
	return selectorScore * minerScore * attemptPenalty
}

func randomHex(size int) string {
	if size <= 0 {
		return ""
	}
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func (s *Server) handleSyncClientFiles(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	clientIdentifier := client.ClientIdentifier
	files := castSliceMap(data["files"])
	indexed := 0
	for _, fileInfo := range files {
		contentHash := asString(fileInfo["content_hash"])
		fileName := asString(fileInfo["file_name"])
		fileSize := asInt(fileInfo["file_size"])
		published := asBool(fileInfo["published"])
		if contentHash == "" || fileName == "" {
			continue
		}
		publishedInt := 0
		if published {
			publishedInt = 1
		}
		_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO client_files
			(client_identifier, content_hash, file_name, file_size, published, last_sync)
			VALUES (?, ?, ?, ?, ?, ?)`, clientIdentifier, contentHash, fileName, fileSize, publishedInt, nowSec())
		indexed++
	}
	log.Printf("sync_client_files: client=%s user=%s files=%d indexed=%d", clientIdentifier, client.Username, len(files), indexed)
}

func (s *Server) handleSyncClientDNSFiles(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	clientIdentifier := client.ClientIdentifier
	files := castSliceMap(data["dns_files"])
	for _, dnsFile := range files {
		domain := asString(dnsFile["domain"])
		ddnsHash := asString(dnsFile["ddns_hash"])
		if domain == "" || ddnsHash == "" {
			continue
		}
		_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO client_dns_files
			(client_identifier, domain, ddns_hash, last_sync)
			VALUES (?, ?, ?, ?)`, clientIdentifier, domain, ddnsHash, nowSec())
	}
}

func (s *Server) handleSyncClientContracts(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	clientIdentifier := client.ClientIdentifier
	contracts := castSliceMap(data["contracts"])
	for _, contractInfo := range contracts {
		contractID := asString(contractInfo["contract_id"])
		if contractID == "" {
			continue
		}
		contentHash := trim(asString(contractInfo["content_hash"]))
		domain := strings.ToLower(trim(asString(contractInfo["domain"])))
		_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO client_contracts
			(client_identifier, contract_id, content_hash, domain, last_sync)
			VALUES (?, ?, ?, ?, ?)`, clientIdentifier, contractID, contentHash, domain, nowSec())
	}
}

func (s *Server) handleRequestClientFiles(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	_ = client
	contentHashes := toStringSlice(data["content_hashes"])
	missing := []string{}
	for _, contentHash := range contentHashes {
		var exists int
		_ = s.server.DB.QueryRow(`SELECT 1 FROM content WHERE content_hash = ?`, contentHash).Scan(&exists)
		if exists == 0 {
			missing = append(missing, contentHash)
		}
	}
	conn.Emit("client_files_response", map[string]any{"missing_files": missing})
}

func (s *Server) handleRequestClientDNSFiles(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	_ = client
	domains := toStringSlice(data["domains"])
	missing := []string{}
	for _, domain := range domains {
		var exists int
		_ = s.server.DB.QueryRow(`SELECT 1 FROM dns_records WHERE domain = ?`, domain).Scan(&exists)
		if exists == 0 {
			missing = append(missing, domain)
		}
	}
	conn.Emit("client_dns_files_response", map[string]any{"missing_dns": missing})
}

func (s *Server) handleRequestClientContracts(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	_ = client
	contractIDs := toStringSlice(data["contract_ids"])
	contracts := castSliceMap(data["contracts"])
	missing := []string{}
	if len(contracts) > 0 {
		for _, contractInfo := range contracts {
			contractID := asString(contractInfo["contract_id"])
			if contractID == "" {
				continue
			}
			var exists int
			_ = s.server.DB.QueryRow(`SELECT 1 FROM contracts WHERE contract_id = ?`, contractID).Scan(&exists)
			if exists == 0 {
				missing = append(missing, contractID)
			}
		}
	} else {
		for _, contractID := range contractIDs {
			var exists int
			_ = s.server.DB.QueryRow(`SELECT 1 FROM contracts WHERE contract_id = ?`, contractID).Scan(&exists)
			if exists == 0 {
				missing = append(missing, contractID)
			}
		}
	}
	conn.Emit("client_contracts_response", map[string]any{"missing_contracts": missing})
}

func (s *Server) handleRequestContentFromClient(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	contentHash := asString(data["content_hash"])
	if contentHash == "" {
		return
	}
	filePath := s.server.ContentPath(contentHash)
	if _, err := os.Stat(filePath); err != nil {
		return
	}
	var exists int
	_ = s.server.DB.QueryRow(`SELECT 1 FROM content WHERE content_hash = ?`, contentHash).Scan(&exists)
	if exists != 0 {
		return
	}
	content, err := s.server.ReadEncryptedFile(filePath)
	if err != nil {
		return
	}
	content, _ = core.ExtractContractFromContent(content)
	var title, description, mimeType, username, signature, publicKey string
	var verified int
	err = s.server.DB.QueryRow(`SELECT title, description, mime_type, username, signature, public_key, verified
		FROM content WHERE content_hash = ?`, contentHash).Scan(&title, &description, &mimeType, &username, &signature, &publicKey, &verified)
	if err != nil {
		return
	}
	conn.Emit("content_from_client", map[string]any{
		"content_hash": contentHash,
		"content":      base64.StdEncoding.EncodeToString(content),
		"title":        title,
		"description":  description,
		"mime_type":    mimeType,
		"username":     username,
		"signature":    signature,
		"public_key":   publicKey,
		"verified":     verified,
	})
}

func (s *Server) handleRequestDDNSFromClient(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	domain := asString(data["domain"])
	if domain == "" {
		return
	}
	var ddnsHash string
	_ = s.server.DB.QueryRow(`SELECT ddns_hash FROM dns_records WHERE domain = ?`, domain).Scan(&ddnsHash)
	if ddnsHash == "" {
		return
	}
	ddnsPath := s.server.DdnsPath(ddnsHash)
	ddnsContent, err := s.server.ReadEncryptedFile(ddnsPath)
	if err != nil {
		return
	}
	var contentHash, username, signature, publicKey string
	var verified int
	err = s.server.DB.QueryRow(`SELECT d.content_hash, d.username, d.signature, COALESCE(u.public_key, ''), d.verified
		FROM dns_records d LEFT JOIN users u ON u.username = d.username WHERE d.domain = ?`, domain).Scan(&contentHash, &username, &signature, &publicKey, &verified)
	if err != nil {
		return
	}
	conn.Emit("ddns_from_client", map[string]any{
		"domain":       domain,
		"ddns_content": base64.StdEncoding.EncodeToString(ddnsContent),
		"content_hash": contentHash,
		"username":     username,
		"signature":    signature,
		"public_key":   publicKey,
		"verified":     verified,
	})
}

func (s *Server) handleRequestContractFromClient(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	contractID := asString(data["contract_id"])
	if contractID == "" {
		return
	}
	contractPath := filepath.Join(s.server.FilesDir, "contracts", contractID+".contract")
	contractContent, err := s.server.ReadEncryptedFile(contractPath)
	if err != nil {
		return
	}
	var actionType, username, signature string
	var contentHash, domain sql.NullString
	var verified int
	err = s.server.DB.QueryRow(`SELECT action_type, content_hash, domain, username, signature, verified
		FROM contracts WHERE contract_id = ?`, contractID).Scan(&actionType, &contentHash, &domain, &username, &signature, &verified)
	if err != nil {
		return
	}
	conn.Emit("contract_from_client", map[string]any{
		"contract_id":      contractID,
		"contract_content": base64.StdEncoding.EncodeToString(contractContent),
		"action_type":      actionType,
		"content_hash":     nullableString(contentHash),
		"domain":           nullableString(domain),
		"username":         username,
		"signature":        signature,
		"verified":         verified,
	})
}

func (s *Server) handleContentFromClient(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	contentHash := asString(data["content_hash"])
	contentB64 := asString(data["content"])
	title := asString(data["title"])
	description := asString(data["description"])
	mimeType := asString(data["mime_type"])
	username := asString(data["username"])
	signature := asString(data["signature"])
	publicKey := asString(data["public_key"])
	verified := asInt(data["verified"])
	if contentHash == "" || contentB64 == "" || mimeType == "" || username == "" || signature == "" || publicKey == "" {
		return
	}
	if title == "" {
		title = contentHash
	}
	content, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		return
	}
	sum := sha256.Sum256(content)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), contentHash) {
		s.server.RegisterContractViolation("content", "system", contentHash, "", "content_tampered", false)
		return
	}
	var exists int
	_ = s.server.DB.QueryRow(`SELECT 1 FROM content WHERE content_hash = ?`, contentHash).Scan(&exists)
	if exists != 0 {
		storedContracts := s.storeClientContractPayloads(contentHash, castSliceMap(data["contracts"]))
		var storedUsername, storedSignature, storedPublicKey string
		var storedIssuerServer, storedIssuerContractID string
		_ = s.server.DB.QueryRow(`SELECT COALESCE(username, ''), COALESCE(signature, ''), COALESCE(public_key, ''), COALESCE(issuer_server, ''), COALESCE(issuer_contract_id, '')
			FROM content WHERE content_hash = ?`, contentHash).Scan(&storedUsername, &storedSignature, &storedPublicKey, &storedIssuerServer, &storedIssuerContractID)
		if strings.EqualFold(storedUsername, "system") || trim(storedSignature) == "" || trim(storedPublicKey) == "" || trim(storedIssuerServer) != "" || trim(storedIssuerContractID) != "" {
			filePath := s.server.ContentPath(contentHash)
			_ = s.server.WriteEncryptedFile(filePath, content, 0o644)
			_, _ = s.server.DB.Exec(`UPDATE content
				SET title = ?, description = ?, mime_type = ?, size = ?, username = ?, signature = ?, public_key = ?, verified = ?, file_path = ?, last_accessed = ?,
				    issuer_server = '', issuer_public_key = '', issuer_contract_id = '', issuer_issued_at = 0
				WHERE content_hash = ?`,
				title, description, mimeType, len(content), username, signature, publicKey, verified, filePath, nowSec(), contentHash)
			log.Printf("content propagation: repaired incomplete client payload hash=%s client=%s user=%s", contentHash, client.ClientIdentifier, client.Username)
		}
		if storedContracts == 0 {
			_ = s.requestContractsForContentFromClients(contentHash)
		}
		s.dispatchInventoryDeliveries(contentHash)
		return
	}
	var published int
	_ = s.server.DB.QueryRow(`SELECT COALESCE(published, 0) FROM client_files
		WHERE client_identifier = ? AND content_hash = ?`, client.ClientIdentifier, contentHash).Scan(&published)
	var hasFile int
	_ = s.server.DB.QueryRow(`SELECT 1 FROM client_files WHERE client_identifier = ? AND content_hash = ? LIMIT 1`,
		client.ClientIdentifier, contentHash).Scan(&hasFile)
	var hasContract int
	_ = s.server.DB.QueryRow(`SELECT 1 FROM client_contracts WHERE client_identifier = ? AND content_hash = ? LIMIT 1`,
		client.ClientIdentifier, contentHash).Scan(&hasContract)
	if published == 0 && hasFile == 0 && hasContract == 0 {
		log.Printf("content propagation: rejected client payload hash=%s client=%s user=%s reason=unindexed_client_content", contentHash, client.ClientIdentifier, client.Username)
		return
	}
	filePath := s.server.ContentPath(contentHash)
	if _, err := os.Stat(filePath); err != nil {
		_ = s.server.WriteEncryptedFile(filePath, content, 0o644)
	}
	_, _ = s.server.DB.Exec(`INSERT INTO content
		(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, last_accessed, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', 0)`,
		contentHash, title, description, mimeType, len(content), username, signature, publicKey, nowSec(), filePath, verified, nowSec())
	log.Printf("content propagation: accepted client payload hash=%s client=%s user=%s", contentHash, client.ClientIdentifier, client.Username)
	if stored := s.storeClientContractPayloads(contentHash, castSliceMap(data["contracts"])); stored == 0 {
		_ = s.requestContractsForContentFromClients(contentHash)
	}
	s.dispatchInventoryDeliveries(contentHash)
}

func (s *Server) handleContentFromClientFailure(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	contentHash := trim(asString(data["content_hash"]))
	reason := trim(asString(data["reason"]))
	log.Printf("content propagation: client failed to supply hash=%s client=%s user=%s reason=%s", contentHash, client.ClientIdentifier, client.Username, reason)
}

func (s *Server) handleDDNSFromClient(conn socketio.Conn, data map[string]any) {
	domain := asString(data["domain"])
	ddnsContentB64 := asString(data["ddns_content"])
	contentHash := asString(data["content_hash"])
	username := asString(data["username"])
	signature := asString(data["signature"])
	publicKey := asString(data["public_key"])
	verified := asInt(data["verified"])
	if domain == "" || ddnsContentB64 == "" || contentHash == "" || username == "" || signature == "" || publicKey == "" {
		return
	}
	ddnsContent, err := base64.StdEncoding.DecodeString(ddnsContentB64)
	if err != nil {
		return
	}
	sum := sha256.Sum256(ddnsContent)
	ddnsHash := hex.EncodeToString(sum[:])
	filePath := s.server.DdnsPath(ddnsHash)
	if _, err := os.Stat(filePath); err != nil {
		_ = s.server.WriteEncryptedFile(filePath, ddnsContent, 0o644)
	}
	var exists int
	_ = s.server.DB.QueryRow(`SELECT 1 FROM dns_records WHERE domain = ?`, domain).Scan(&exists)
	if exists != 0 {
		return
	}
	_, _ = s.server.DB.Exec(`INSERT INTO dns_records
		(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, contentHash, username, username, nowSec(), signature, verified, nowSec(), ddnsHash)
	go s.requestContractsForDomainFromClients(domain)
}

func (s *Server) handleContractFromClient(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		return
	}
	_ = s.storeClientContractPayload("", data)
}

func (s *Server) storeClientContractPayloads(defaultContentHash string, contracts []map[string]any) int {
	stored := 0
	for _, contract := range contracts {
		if s.storeClientContractPayload(defaultContentHash, contract) {
			stored++
		}
	}
	if stored > 0 {
		log.Printf("content propagation: stored client contracts hash=%s count=%d", defaultContentHash, stored)
	}
	return stored
}

func (s *Server) storeClientContractPayload(defaultContentHash string, data map[string]any) bool {
	contractID := asString(data["contract_id"])
	contractB64 := asString(data["contract_content"])
	actionType := asString(data["action_type"])
	contentHash := asString(data["content_hash"])
	domain := asString(data["domain"])
	username := asString(data["username"])
	signature := asString(data["signature"])
	verified := asInt(data["verified"])
	if trim(contentHash) == "" {
		contentHash = trim(defaultContentHash)
	}
	if contractID == "" || contractB64 == "" || actionType == "" || username == "" || signature == "" {
		return false
	}
	contractContent, err := base64.StdEncoding.DecodeString(contractB64)
	if err != nil {
		return false
	}
	valid, _, info := core.ValidateContractStructure(contractContent)
	if !valid || info == nil {
		return false
	}
	if info.Action != "" {
		actionType = info.Action
	}
	if info.User != "" {
		username = info.User
	}
	if info.Signature != "" {
		signature = info.Signature
	}
	if extractedHash := core.ExtractContractDetail(info, "FILE_HASH"); extractedHash != "" {
		contentHash = extractedHash
	} else if extractedHash := core.ExtractContractDetail(info, "CONTENT_HASH"); extractedHash != "" {
		contentHash = extractedHash
	}
	if extractedDomain := core.ExtractContractDetail(info, "DOMAIN"); extractedDomain != "" {
		domain = extractedDomain
	} else if extractedDomain := core.ExtractContractDetail(info, "DNAME"); extractedDomain != "" {
		domain = extractedDomain
	}
	if trim(contentHash) == "" {
		contentHash = trim(defaultContentHash)
	}
	if core.IsForbiddenReplicatedContractUser(username) || !s.server.HasContractReplicationTarget(contractID, contentHash, domain) {
		return false
	}
	if !s.server.VerifyContractSignature(contractContent, username, signature, "") {
		return false
	}
	verified = 1
	contractPath := filepath.Join(s.server.FilesDir, "contracts", contractID+".contract")
	if _, err := os.Stat(contractPath); err != nil {
		_ = s.server.WriteEncryptedFile(contractPath, contractContent, 0o644)
	}
	var exists int
	_ = s.server.DB.QueryRow(`SELECT 1 FROM contracts WHERE contract_id = ?`, contractID).Scan(&exists)
	if exists != 0 {
		return true
	}
	if _, err := s.server.DB.Exec(`INSERT INTO contracts
		(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		contractID, actionType, nullIfEmpty(contentHash), nullIfEmpty(domain), username, signature, nowSec(), verified, contractB64); err != nil {
		return false
	}
	return true
}

func (s *Server) handleGetApiAppVersions(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("api_app_versions", map[string]any{"error": "Not authenticated"})
		return
	}
	title := trim(asString(data["title"]))
	appName := trim(asString(data["app_name"]))
	requestID := asString(data["request_id"])
	var rows *sql.Rows
	var err error
	if appName != "" {
		rows, err = s.server.DB.Query(`SELECT app_name, content_hash, username, timestamp, version_number
			FROM api_app_versions WHERE app_name = ? ORDER BY timestamp ASC`, appName)
	} else {
		rows, err = s.server.DB.Query(`SELECT app_name, content_hash, username, timestamp, version_number
			FROM api_app_versions ORDER BY timestamp ASC`)
	}
	if err != nil {
		conn.Emit("api_app_versions", map[string]any{"success": false, "error": err.Error()})
		return
	}
	defer rows.Close()
	versions := []map[string]any{}
	i := 0
	for rows.Next() {
		var app, contentHash, username string
		var timestamp float64
		var versionNum int
		if scanErr := rows.Scan(&app, &contentHash, &username, &timestamp, &versionNum); scanErr != nil {
			continue
		}
		i++
		versions = append(versions, map[string]any{
			"app_name":       app,
			"content_hash":   contentHash,
			"username":       username,
			"timestamp":      timestamp,
			"version_number": versionNum,
			"version_label":  fmt.Sprintf("Upload %d", i),
		})
	}
	latestHash := any(nil)
	if len(versions) > 0 {
		latestHash = versions[len(versions)-1]["content_hash"]
	}
	conn.Emit("api_app_versions", map[string]any{
		"success":     true,
		"request_id":  requestID,
		"title":       title,
		"app_name":    appName,
		"latest_hash": latestHash,
		"versions":    versions,
	})
}

func (s *Server) handleContractViolation(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("contract_violation_ack", map[string]any{"success": false, "error": "Not authenticated"})
		return
	}
	violationType := asString(data["violation_type"])
	contentHash := asString(data["content_hash"])
	domain := asString(data["domain"])
	reason := asString(data["reason"])
	if reason == "" {
		reason = "missing_contract"
	}
	if violationType == "" {
		violationType = "content"
		if domain != "" {
			violationType = "domain"
		}
	}
	owner := ""
	if domain != "" {
		_ = s.server.DB.QueryRow(`SELECT username FROM dns_records WHERE domain = ? LIMIT 1`, domain).Scan(&owner)
	} else if contentHash != "" {
		_ = s.server.DB.QueryRow(`SELECT username FROM content WHERE content_hash = ? LIMIT 1`, contentHash).Scan(&owner)
	}
	if owner == "" {
		owner = client.Username
	}
	violationID := core.NewUUID()
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO contract_violations
		(violation_id, violation_type, content_hash, domain, owner_username, reported_by, timestamp, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		violationID, violationType, nullIfEmpty(contentHash), nullIfEmpty(domain), owner, client.Username, nowSec(), reason)
	s.server.AdjustReputation(owner, -20)
	conn.Emit("contract_violation_ack", map[string]any{"success": true, "violation_id": violationID})
}

func (s *Server) handleAcceptHpsTransfer(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "accept_hps_transfer_ack")
	if !ok {
		return
	}
	transferID := asString(data["transfer_id"])
	if transferID == "" {
		conn.Emit("accept_hps_transfer_ack", map[string]any{"success": false, "error": "Missing transfer ID"})
		return
	}
	var transferType, targetUser, originalOwner, status, sessionID, contractID string
	var amount sql.NullInt64
	err := s.server.DB.QueryRow(`SELECT transfer_type, target_user, original_owner, status, hps_session_id, hps_amount, contract_id
		FROM pending_transfers WHERE transfer_id = ?`, transferID).Scan(&transferType, &targetUser, &originalOwner, &status, &sessionID, &amount, &contractID)
	if err != nil || status != "pending" {
		conn.Emit("accept_hps_transfer_ack", map[string]any{"success": false, "error": "Transfer not found"})
		return
	}
	if targetUser != actx.Username {
		conn.Emit("accept_hps_transfer_ack", map[string]any{"success": false, "error": "Unauthorized"})
		return
	}
	if transferType != "hps_transfer" {
		conn.Emit("accept_hps_transfer_ack", map[string]any{"success": false, "error": "Invalid transfer type"})
		return
	}
	session := s.server.GetHpsTransferSession(sessionID)
	if session == nil || (asString(session["status"]) != "pending_confirmation" && asString(session["status"]) != "pending") {
		conn.Emit("accept_hps_transfer_ack", map[string]any{"success": false, "error": "Transfer session unavailable"})
		return
	}
	if asString(session["target"]) != "" && asString(session["target"]) != actx.Username {
		s.server.UpdateHpsTransferSessionTarget(sessionID, actx.Username)
	}
	transferAmount := int(amount.Int64)
	if transferAmount <= 0 {
		transferAmount = asInt(session["amount"])
	}
	if transferAmount <= 0 {
		conn.Emit("accept_hps_transfer_ack", map[string]any{"success": false, "error": "Invalid transfer amount"})
		return
	}
	targetKey := actx.PublicKey
	if targetKey == "" {
		_ = s.server.DB.QueryRow(`SELECT public_key FROM users WHERE username = ?`, actx.Username).Scan(&targetKey)
	}
	if targetKey == "" {
		conn.Emit("accept_hps_transfer_ack", map[string]any{"success": false, "error": "Target public key not available"})
		return
	}
	if !actx.Deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			actx.ClientIdentifier, actx.Username, "contract_transfer",
			asString(data["pow_nonce"]), asFloat(data["hashrate_observed"]), castMap(data["hps_payment"]),
		)
		if !okAuth {
			conn.Emit("accept_hps_transfer_ack", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(actx.ClientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{"data": data, "payment": pendingInfo, "public_key": actx.PublicKey}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "accept_hps_transfer", actx.Username, actx.ClientIdentifier, payload, "accept_hps_transfer_ack")
			return
		}
	}
	payer := asString(session["payer"])
	if payer == "" {
		payer = originalOwner
	}
	offer := s.server.CreateVoucherOffer(actx.Username, targetKey, transferAmount, "transfer_from:"+payer, nil, map[string]any{
		"source_voucher_ids": toStringSlice(session["voucher_ids"]),
	}, "")
	s.server.UpdateHpsTransferSessionOffer(sessionID, asString(offer["offer_id"]), asString(offer["voucher_id"]), asFloat(offer["expires_at"]))
	_, _ = s.server.DB.Exec(`UPDATE pending_transfers SET status = ? WHERE transfer_id = ?`, "accepted", transferID)
	if contractRecord := s.server.GetMonetaryTransferByContract(contractID, "hps_transfer"); contractRecord != nil {
		s.server.UpdateTransferLockedVouchers(asString(contractRecord["transfer_id"]), []string{asString(offer["voucher_id"])})
	}
	_, _ = s.server.DB.Exec(`DELETE FROM pending_transfers WHERE transfer_id = ?`, transferID)
	conn.Emit("hps_voucher_offer", map[string]any{
		"offer_id":          offer["offer_id"],
		"voucher_id":        offer["voucher_id"],
		"payload":           offer["payload"],
		"payload_canonical": offer["payload_canonical"],
		"expires_at":        offer["expires_at"],
	})
	s.emitWalletSyncToUser(originalOwner)
	s.emitWalletSyncToUser(actx.Username)
	conn.Emit("pending_transfer_notice", map[string]any{"count": countPendingForUser(s.server.DB, actx.Username)})
	conn.Emit("accept_hps_transfer_ack", map[string]any{
		"success":    true,
		"amount":     transferAmount,
		"voucher_id": offer["voucher_id"],
		"session_id": sessionID,
	})
}

func (s *Server) handleGetContractCanonical(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("contract_canonical", map[string]any{"error": "Not authenticated"})
		return
	}
	contractID := asString(data["contract_id"])
	if contractID == "" {
		conn.Emit("contract_canonical", map[string]any{"error": "Missing contract ID"})
		return
	}
	var contentHash, domain sql.NullString
	err := s.server.DB.QueryRow(`SELECT content_hash, domain FROM contracts WHERE contract_id = ?`, contractID).Scan(&contentHash, &domain)
	if err != nil {
		conn.Emit("contract_canonical", map[string]any{"error": "Contract not found"})
		return
	}
	targetType := "content"
	targetID := nullableString(contentHash)
	if nullableString(domain) != nil {
		targetType = "domain"
		targetID = nullableString(domain)
	}
	if targetID == nil {
		conn.Emit("contract_canonical", map[string]any{"error": "No valid contract found"})
		return
	}
	contractBytes := s.getContractArchiveBytes(targetType, asString(targetID))
	if len(contractBytes) == 0 {
		var contentB64 string
		if targetType == "domain" {
			_ = s.server.DB.QueryRow(`SELECT contract_content FROM contracts WHERE domain = ? AND verified = 1 ORDER BY timestamp DESC LIMIT 1`,
				asString(targetID)).Scan(&contentB64)
		} else {
			_ = s.server.DB.QueryRow(`SELECT contract_content FROM contracts WHERE content_hash = ? AND verified = 1 ORDER BY timestamp DESC LIMIT 1`,
				asString(targetID)).Scan(&contentB64)
		}
		contractBytes, _ = base64.StdEncoding.DecodeString(contentB64)
	}
	if len(contractBytes) == 0 {
		conn.Emit("contract_canonical", map[string]any{"error": "No valid contract found"})
		return
	}
	conn.Emit("contract_canonical", map[string]any{"contract_text": string(contractBytes)})
}

func (s *Server) handleRejectTransfer(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "reject_transfer_ack")
	if !ok {
		return
	}
	transferID := asString(data["transfer_id"])
	if transferID == "" {
		conn.Emit("reject_transfer_ack", map[string]any{"success": false, "error": "Missing transfer ID"})
		return
	}
	transfer, ok := s.getPendingTransfer(transferID)
	if !ok || asString(transfer["status"]) != "pending" {
		conn.Emit("reject_transfer_ack", map[string]any{"success": false, "error": "Transfer not found"})
		return
	}
	if asString(transfer["target_user"]) != actx.Username {
		conn.Emit("reject_transfer_ack", map[string]any{"success": false, "error": "Unauthorized"})
		return
	}
	if !actx.Deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			actx.ClientIdentifier, actx.Username, "contract_transfer",
			asString(data["pow_nonce"]), asFloat(data["hashrate_observed"]), castMap(data["hps_payment"]),
		)
		if !okAuth {
			conn.Emit("reject_transfer_ack", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(actx.ClientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{"data": data, "payment": pendingInfo, "public_key": actx.PublicKey}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "reject_transfer", actx.Username, actx.ClientIdentifier, payload, "reject_transfer_ack")
			return
		}
	}
	_, _ = s.server.DB.Exec(`UPDATE pending_transfers SET status = ? WHERE transfer_id = ?`, "rejected", transferID)
	transferType := asString(transfer["transfer_type"])
	originalOwner := asString(transfer["original_owner"])
	custodyUser := asString(transfer["custody_user"])
	newID := ""
	if transferType == "hps_transfer" {
		if (custodyUser == core.CustodyUsername || custodyUser == "system") && asString(transfer["target_user"]) == originalOwner {
			s.server.MoveHpsTransferSessionToCustody(asString(transfer["hps_session_id"]))
			s.server.MoveHpsTransferToCustody(transferID)
			conn.Emit("pending_transfers", map[string]any{"transfers": listPendingTransfersForUser(s.server.DB, actx.Username)})
			s.emitPendingTransferNotice(actx.Username)
			conn.Emit("reject_transfer_ack", map[string]any{"success": true, "moved_to_custody": true})
			return
		}
		s.server.UpdateHpsTransferSessionTarget(asString(transfer["hps_session_id"]), originalOwner)
		newID = core.NewUUID()
		_, _ = s.server.DB.Exec(`INSERT INTO pending_transfers
			(transfer_id, transfer_type, target_user, original_owner, custody_user, content_hash, domain, app_name, contract_id, status, timestamp, hps_amount, hps_total_value, hps_voucher_ids, hps_session_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			newID, transferType, originalOwner, originalOwner, custodyUser,
			nil, nil, nil, asString(transfer["contract_id"]), "pending", nowSec(),
			transfer["hps_amount"], transfer["hps_total_value"], transfer["hps_voucher_ids"], transfer["hps_session_id"])
		s.emitPendingTransferNotice(originalOwner)
		conn.Emit("pending_transfers", map[string]any{"transfers": listPendingTransfersForUser(s.server.DB, actx.Username)})
		s.emitPendingTransferNotice(actx.Username)
		conn.Emit("reject_transfer_ack", map[string]any{"success": true, "new_transfer_id": newID})
		return
	}
	if (custodyUser == core.CustodyUsername || custodyUser == "system") && asString(transfer["target_user"]) == originalOwner {
		s.server.MoveTransferToCustody(transferID)
		conn.Emit("pending_transfers", map[string]any{"transfers": listPendingTransfersForUser(s.server.DB, actx.Username)})
		s.emitPendingTransferNotice(actx.Username)
		conn.Emit("reject_transfer_ack", map[string]any{"success": true, "moved_to_custody": true})
		return
	}
	if transferType == "domain" {
		if d, ok := transfer["domain"].(string); ok && d != "" {
			s.server.SetContractCertification("domain", d, originalOwner, core.CustodyUsername)
		}
	} else if ch, ok := transfer["content_hash"].(string); ok && ch != "" {
		s.server.SetContractCertification("content", ch, originalOwner, core.CustodyUsername)
	}
	newID = core.NewUUID()
	_, _ = s.server.DB.Exec(`INSERT INTO pending_transfers
		(transfer_id, transfer_type, target_user, original_owner, custody_user, content_hash, domain, app_name, contract_id, status, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newID, transferType, originalOwner, originalOwner, custodyUser,
		nullIfEmpty(asString(transfer["content_hash"])),
		nullIfEmpty(asString(transfer["domain"])),
		nullIfEmpty(asString(transfer["app_name"])),
		asString(transfer["contract_id"]),
		"pending", nowSec())
	s.emitPendingTransferNotice(originalOwner)
	conn.Emit("pending_transfers", map[string]any{"transfers": listPendingTransfersForUser(s.server.DB, actx.Username)})
	s.emitPendingTransferNotice(actx.Username)
	conn.Emit("reject_transfer_ack", map[string]any{"success": true, "new_transfer_id": newID})
}

func (s *Server) handleRenounceTransfer(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "renounce_transfer_ack")
	if !ok {
		return
	}
	transferID := asString(data["transfer_id"])
	if transferID == "" {
		conn.Emit("renounce_transfer_ack", map[string]any{"success": false, "error": "Missing transfer ID"})
		return
	}
	transfer, ok := s.getPendingTransfer(transferID)
	if !ok || asString(transfer["status"]) != "pending" {
		conn.Emit("renounce_transfer_ack", map[string]any{"success": false, "error": "Transfer not found"})
		return
	}
	if asString(transfer["target_user"]) != actx.Username {
		conn.Emit("renounce_transfer_ack", map[string]any{"success": false, "error": "Unauthorized"})
		return
	}
	if !actx.Deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			actx.ClientIdentifier, actx.Username, "contract_transfer",
			asString(data["pow_nonce"]), asFloat(data["hashrate_observed"]), castMap(data["hps_payment"]),
		)
		if !okAuth {
			conn.Emit("renounce_transfer_ack", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(actx.ClientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{"data": data, "payment": pendingInfo, "public_key": actx.PublicKey}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "renounce_transfer", actx.Username, actx.ClientIdentifier, payload, "renounce_transfer_ack")
			return
		}
	}
	if asString(transfer["transfer_type"]) == "hps_transfer" {
		s.server.MoveHpsTransferSessionToCustody(asString(transfer["hps_session_id"]))
		s.server.MoveHpsTransferToCustody(transferID)
	} else {
		s.server.MoveTransferToCustody(transferID)
	}
	_, _ = s.server.DB.Exec(`UPDATE pending_transfers SET status = ? WHERE transfer_id = ?`, "renounced", transferID)
	conn.Emit("pending_transfers", map[string]any{"transfers": listPendingTransfersForUser(s.server.DB, actx.Username)})
	s.emitPendingTransferNotice(actx.Username)
	conn.Emit("renounce_transfer_ack", map[string]any{"success": true, "moved_to_custody": true})
}

func (s *Server) handleInvalidateContract(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "invalidate_contract_ack")
	if !ok {
		return
	}
	contractID := asString(data["contract_id"])
	if contractID == "" {
		conn.Emit("invalidate_contract_ack", map[string]any{"success": false, "error": "Missing contract ID"})
		return
	}
	var actionType, owner string
	var contentHash, domain sql.NullString
	err := s.server.DB.QueryRow(`SELECT action_type, content_hash, domain, username FROM contracts WHERE contract_id = ?`,
		contractID).Scan(&actionType, &contentHash, &domain, &owner)
	if err != nil {
		conn.Emit("invalidate_contract_ack", map[string]any{"success": false, "error": "Contract not found"})
		return
	}
	if owner != actx.Username {
		conn.Emit("invalidate_contract_ack", map[string]any{"success": false, "error": "Not contract owner"})
		return
	}
	if !actx.Deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			actx.ClientIdentifier, actx.Username, "contract_reset",
			asString(data["pow_nonce"]), asFloat(data["hashrate_observed"]), castMap(data["hps_payment"]),
		)
		if !okAuth {
			conn.Emit("invalidate_contract_ack", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(actx.ClientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{"data": data, "payment": pendingInfo, "public_key": actx.PublicKey}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "invalidate_contract", actx.Username, actx.ClientIdentifier, payload, "invalidate_contract_ack")
			return
		}
	}
	if domain.Valid && domain.String != "" {
		s.registerContractViolation("domain", "", domain.String, "missing_contract", "system", owner, false)
		s.server.InvalidateDomain(domain.String, true)
	} else if contentHash.Valid && contentHash.String != "" {
		s.registerContractViolation("content", contentHash.String, "", "missing_contract", "system", owner, false)
		s.server.InvalidateContent(contentHash.String, true)
	}
	conn.Emit("invalidate_contract_ack", map[string]any{
		"success":      true,
		"action_type":  actionType,
		"content_hash": nullableString(contentHash),
		"domain":       nullableString(domain),
	})
	if len(castMap(data["hps_payment"])) > 0 {
		s.emitWalletSyncToUser(actx.Username)
	}
}

func (s *Server) handleCertifyContract(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "certify_contract_ack")
	if !ok {
		return
	}
	contractID := asString(data["contract_id"])
	contractB64 := asString(data["contract_content"])
	if contractID == "" || contractB64 == "" {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "Missing data"})
		return
	}
	contractContent, err := base64.StdEncoding.DecodeString(contractB64)
	if err != nil {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "Invalid contract: invalid base64"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "Invalid contract: " + errMsg})
		return
	}
	if contractInfo.User != actx.Username {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "Contract user mismatch"})
		return
	}
	if !s.server.VerifyContractSignature(contractContent, actx.Username, contractInfo.Signature, "") {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "Invalid contract signature"})
		return
	}
	var actionType, owner string
	var contentHash, domain sql.NullString
	err = s.server.DB.QueryRow(`SELECT action_type, content_hash, domain, username FROM contracts WHERE contract_id = ?`,
		contractID).Scan(&actionType, &contentHash, &domain, &owner)
	if err != nil {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "Contract not found"})
		return
	}
	if strings.HasPrefix(actionType, "voucher_") {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "Voucher contracts cannot be certified"})
		return
	}
	if owner == actx.Username {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "Owner cannot certify own contract"})
		return
	}
	targetType := "content"
	targetID := nullableString(contentHash)
	if domain.Valid && domain.String != "" {
		targetType = "domain"
		targetID = nullableString(domain)
	}
	if targetID == nil {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "No violation to certify"})
		return
	}
	if !s.hasContractViolation(targetType, asString(targetID)) {
		conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": "No violation to certify"})
		return
	}
	if !actx.Deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			actx.ClientIdentifier, actx.Username, "contract_certify",
			asString(data["pow_nonce"]), asFloat(data["hashrate_observed"]), castMap(data["hps_payment"]),
		)
		if !okAuth {
			conn.Emit("certify_contract_ack", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(actx.ClientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{"data": data, "payment": pendingInfo, "public_key": actx.PublicKey}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "certify_contract", actx.Username, actx.ClientIdentifier, payload, "certify_contract_ack")
			return
		}
	}
	if targetType == "domain" {
		s.server.RemoveInvalidContracts("", asString(targetID))
	} else {
		s.server.RemoveInvalidContracts(asString(targetID), "")
	}
	s.clearContractViolation(targetType, asString(targetID))
	conn.Emit("contract_violation_cleared", map[string]any{
		"violation_type": targetType,
		"content_hash": func() any {
			if targetType == "content" {
				return asString(targetID)
			}
			return nil
		}(),
		"domain": func() any {
			if targetType == "domain" {
				return asString(targetID)
			}
			return nil
		}(),
	})
	s.server.SetContractCertification(targetType, asString(targetID), owner, actx.Username)
	s.server.SaveContract("certify_contract",
		func() string {
			if targetType == "content" {
				return asString(targetID)
			}
			return ""
		}(),
		func() string {
			if targetType == "domain" {
				return asString(targetID)
			}
			return ""
		}(),
		actx.Username, contractInfo.Signature, contractContent)
	s.server.AdjustReputation(actx.Username, 80)
	s.emitToUser(actx.Username, "reputation_update", map[string]any{"reputation": s.getUserReputation(actx.Username)})
	if len(castMap(data["hps_payment"])) > 0 {
		s.emitWalletSyncToUser(actx.Username)
	}
	conn.Emit("certify_contract_ack", map[string]any{"success": true})
}

func (s *Server) handleGetContractCanonicalByTarget(conn socketio.Conn, data map[string]any) {
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit("contract_canonical", map[string]any{"error": "Not authenticated"})
		return
	}
	targetType := asString(data["target_type"])
	targetID := asString(data["target_id"])
	if (targetType != "content" && targetType != "domain") || targetID == "" {
		conn.Emit("contract_canonical", map[string]any{"error": "Missing target"})
		return
	}
	contractBytes := s.getContractArchiveBytes(targetType, targetID)
	if len(contractBytes) == 0 {
		conn.Emit("contract_canonical", map[string]any{"error": "No valid contract found"})
		return
	}
	conn.Emit("contract_canonical", map[string]any{"contract_text": string(contractBytes)})
}

func (s *Server) handleCertifyMissingContract(conn socketio.Conn, data map[string]any) {
	actx, ok := s.getActionContext(conn, data, "certify_missing_contract_ack")
	if !ok {
		return
	}
	targetType := asString(data["target_type"])
	targetID := asString(data["target_id"])
	contractB64 := asString(data["contract_content"])
	if (targetType != "content" && targetType != "domain") || targetID == "" || contractB64 == "" {
		conn.Emit("certify_missing_contract_ack", map[string]any{"success": false, "error": "Missing data"})
		return
	}
	contractContent, err := base64.StdEncoding.DecodeString(contractB64)
	if err != nil {
		conn.Emit("certify_missing_contract_ack", map[string]any{"success": false, "error": "Invalid contract: invalid base64"})
		return
	}
	valid, errMsg, contractInfo := core.ValidateContractStructure(contractContent)
	if !valid || contractInfo == nil {
		conn.Emit("certify_missing_contract_ack", map[string]any{"success": false, "error": "Invalid contract: " + errMsg})
		return
	}
	if contractInfo.User != actx.Username {
		conn.Emit("certify_missing_contract_ack", map[string]any{"success": false, "error": "Contract user mismatch"})
		return
	}
	if !s.server.VerifyContractSignature(contractContent, actx.Username, contractInfo.Signature, "") {
		conn.Emit("certify_missing_contract_ack", map[string]any{"success": false, "error": "Invalid contract signature"})
		return
	}
	if !s.hasContractViolation(targetType, targetID) {
		conn.Emit("certify_missing_contract_ack", map[string]any{"success": false, "error": "No contract violation to certify"})
		return
	}
	owner := s.getViolationOwner(targetType, targetID)
	if !actx.Deferred {
		okAuth, authErr, shouldBan, pendingInfo := s.server.AuthorizePowOrHPS(
			actx.ClientIdentifier, actx.Username, "contract_certify",
			asString(data["pow_nonce"]), asFloat(data["hashrate_observed"]), castMap(data["hps_payment"]),
		)
		if !okAuth {
			conn.Emit("certify_missing_contract_ack", map[string]any{"success": false, "error": defaultStr(authErr, "Invalid PoW solution")})
			if shouldBan {
				s.banClientAndNotify(actx.ClientIdentifier, 300, "Invalid PoW solution")
			}
			return
		}
		if pendingInfo != nil {
			payload := map[string]any{"data": data, "payment": pendingInfo, "public_key": actx.PublicKey}
			transferID := asString(pendingInfo["transfer_id"])
			s.queuePendingMonetaryAction(conn, transferID, "certify_missing_contract", actx.Username, actx.ClientIdentifier, payload, "certify_missing_contract_ack")
			return
		}
	}
	if targetType == "domain" {
		s.server.RemoveInvalidContracts("", targetID)
	} else {
		s.server.RemoveInvalidContracts(targetID, "")
	}
	s.clearContractViolation(targetType, targetID)
	conn.Emit("contract_violation_cleared", map[string]any{
		"violation_type": targetType,
		"content_hash": func() any {
			if targetType == "content" {
				return targetID
			}
			return nil
		}(),
		"domain": func() any {
			if targetType == "domain" {
				return targetID
			}
			return nil
		}(),
	})
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO contract_certifications
		(cert_id, target_type, target_id, original_owner, certifier, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)`, core.NewUUID(), targetType, targetID, defaultStr(owner, actx.Username), actx.Username, nowSec())
	contentHash := ""
	domain := ""
	if targetType == "content" {
		contentHash = targetID
	} else {
		domain = targetID
	}
	s.server.SaveContract("certify_contract", contentHash, domain, actx.Username, contractInfo.Signature, contractContent)
	s.server.AdjustReputation(actx.Username, 40)
	s.emitToUser(actx.Username, "reputation_update", map[string]any{"reputation": s.getUserReputation(actx.Username)})
	if len(castMap(data["hps_payment"])) > 0 {
		s.emitWalletSyncToUser(actx.Username)
	}
	conn.Emit("certify_missing_contract_ack", map[string]any{"success": true})
}

type actionContext struct {
	Username         string
	ClientIdentifier string
	PublicKey        string
	Deferred         bool
}

func (s *Server) getActionContext(conn socketio.Conn, data map[string]any, ackEvent string) (*actionContext, bool) {
	if asBool(data["_deferred_payment"]) {
		return &actionContext{
			Username:         asString(data["_deferred_username"]),
			ClientIdentifier: asString(data["_deferred_client_identifier"]),
			PublicKey:        asString(data["_deferred_public_key"]),
			Deferred:         true,
		}, true
	}
	client, ok := s.getClient(conn.ID())
	if !ok || !client.Authenticated {
		conn.Emit(ackEvent, map[string]any{"success": false, "error": "Not authenticated"})
		return nil, false
	}
	return &actionContext{
		Username:         client.Username,
		ClientIdentifier: client.ClientIdentifier,
		PublicKey:        client.PublicKey,
		Deferred:         false,
	}, true
}

func (s *Server) getAuthenticatedConnByUsername(username string) (socketio.Conn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sid, client := range s.clients {
		if client != nil && client.Authenticated && strings.EqualFold(client.Username, username) {
			conn, ok := s.conns[sid]
			if ok && conn != nil {
				return conn, true
			}
		}
	}
	return nil, false
}

func (s *Server) processPendingMonetaryAction(transferID string) {
	action := s.server.GetPendingMonetaryAction(transferID)
	if action == nil || asString(action["status"]) != "pending" {
		return
	}
	actionID := asString(action["action_id"])
	actionName := asString(action["action_name"])
	username := asString(action["username"])
	responseEvent := asString(action["response_event"])
	payload := castMap(action["payload"])
	paymentInfo := castMap(payload["payment"])
	data := castMap(payload["data"])
	s.server.UpdatePendingMonetaryActionStatus(actionID, "processing")
	if err := s.server.FinalizeSpendHPSPayment(paymentInfo); err != nil {
		s.server.UpdatePendingMonetaryActionStatus(actionID, "failed")
		if responseEvent != "" && username != "" {
			s.emitToUser(username, responseEvent, map[string]any{"success": false, "error": err.Error()})
		}
		return
	}
	data["_deferred_payment"] = true
	data["_deferred_username"] = username
	data["_deferred_client_identifier"] = asString(action["client_identifier"])
	publicKey := asString(payload["public_key"])
	if publicKey == "" && username != "" {
		_ = s.server.DB.QueryRow(`SELECT public_key FROM users WHERE username = ?`, username).Scan(&publicKey)
	}
	if publicKey != "" {
		data["_deferred_public_key"] = publicKey
	}
	conn, ok := s.getAuthenticatedConnByUsername(username)
	if !ok {
		s.server.UpdatePendingMonetaryActionStatus(actionID, "failed")
		if responseEvent != "" && username != "" {
			s.emitToUser(username, responseEvent, map[string]any{"success": false, "error": "User not connected"})
		}
		return
	}
	s.emitWalletSyncToUser(username)
	conn.Emit("economy_report", s.server.BuildEconomyReport())
	conn.Emit("hps_economy_status", s.getHpsEconomyStatusPayload())
	switch actionName {
	case "transfer_hps":
		s.handleTransferHPSQueued(conn, data)
	case "publish_content":
		s.handlePublishContentQueued(conn, data)
	case "register_dns":
		s.handleRegisterDNSQueued(conn, data)
	case "report_content":
		s.handleReportContent(conn, data)
	case "accept_usage_contract":
		s.handleAcceptUsageContractQueued(conn, data)
	case "accept_hps_transfer":
		s.handleAcceptHpsTransfer(conn, data)
	case "reject_transfer":
		s.handleRejectTransfer(conn, data)
	case "renounce_transfer":
		s.handleRenounceTransfer(conn, data)
	case "invalidate_contract":
		s.handleInvalidateContract(conn, data)
	case "certify_contract":
		s.handleCertifyContract(conn, data)
	case "certify_missing_contract":
		s.handleCertifyMissingContract(conn, data)
	case "request_inventory_transfer":
		s.handleRequestInventoryTransfer(conn, data)
	default:
		s.server.UpdatePendingMonetaryActionStatus(actionID, "failed")
		if responseEvent != "" && username != "" {
			s.emitToUser(username, responseEvent, map[string]any{"success": false, "error": "AÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§ÃƒÆ’Ã†â€™Ãƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â£o pendente sem handler"})
		}
		return
	}
	s.server.UpdatePendingMonetaryActionStatus(actionID, "completed")
}

func (s *Server) queuePendingMonetaryAction(
	conn socketio.Conn,
	transferID, actionName, username, clientIdentifier string,
	payload map[string]any,
	responseEvent string,
) {
	s.server.CreatePendingMonetaryAction(transferID, actionName, username, clientIdentifier, payload, responseEvent)
	if username != "" {
		s.emitWalletSyncToUser(username)
	}
	if transfer, ok := s.getMonetaryTransfer(transferID); ok {
		s.requestSelectorForTransfer(transferID, asString(transfer["sender"]), asString(transfer["receiver"]))
	}
	if conn != nil && responseEvent != "" {
		conn.Emit(responseEvent, s.server.BuildPendingMonetaryAck(transferID))
	}
}

func (s *Server) getMonetaryTransfer(transferID string) (map[string]any, bool) {
	var transferType, sender, receiver, status string
	var contractID, lockedVoucherIDs, assignedMiner, feeSource, interPayload sql.NullString
	var amount, feeAmount, selectorFeeAmount int
	var createdAt, signedAt, deadline, minerDeadline sql.NullFloat64
	err := s.server.DB.QueryRow(`SELECT transfer_type, sender, receiver, amount, status, contract_id, locked_voucher_ids,
		assigned_miner, fee_amount, selector_fee_amount, fee_source, inter_server_payload, created_at, signed_at, deadline, miner_deadline
		FROM monetary_transfers WHERE transfer_id = ?`, transferID).
		Scan(&transferType, &sender, &receiver, &amount, &status, &contractID, &lockedVoucherIDs,
			&assignedMiner, &feeAmount, &selectorFeeAmount, &feeSource, &interPayload, &createdAt, &signedAt, &deadline, &minerDeadline)
	if err != nil {
		return nil, false
	}
	return map[string]any{
		"transfer_id":          transferID,
		"transfer_type":        transferType,
		"sender":               sender,
		"receiver":             receiver,
		"amount":               amount,
		"status":               status,
		"contract_id":          nullableString(contractID),
		"locked_voucher_ids":   parseJSONStringSlice(asString(nullableString(lockedVoucherIDs))),
		"assigned_miner":       nullableString(assignedMiner),
		"fee_amount":           feeAmount,
		"selector_fee_amount":  selectorFeeAmount,
		"fee_source":           nullableString(feeSource),
		"inter_server_payload": parseJSONMap(asString(nullableString(interPayload))),
		"created_at":           nullableFloat(createdAt),
		"signed_at":            nullableFloat(signedAt),
		"deadline":             nullableFloat(deadline),
		"miner_deadline":       nullableFloat(minerDeadline),
	}, true
}

func (s *Server) getPendingTransfer(transferID string) (map[string]any, bool) {
	var transferType, targetUser, originalOwner, custodyUser, contractID, status string
	var contentHash, domain, appName, voucherIDs, sessionID, requesterUser, requestPayload sql.NullString
	var timestamp float64
	var amount, totalValue sql.NullInt64
	err := s.server.DB.QueryRow(`SELECT transfer_type, target_user, original_owner, custody_user, content_hash, domain, app_name,
		contract_id, status, timestamp, hps_amount, hps_total_value, hps_voucher_ids, hps_session_id, requester_user, request_payload
		FROM pending_transfers WHERE transfer_id = ?`, transferID).
		Scan(&transferType, &targetUser, &originalOwner, &custodyUser, &contentHash, &domain, &appName,
			&contractID, &status, &timestamp, &amount, &totalValue, &voucherIDs, &sessionID, &requesterUser, &requestPayload)
	if err != nil {
		return nil, false
	}
	return map[string]any{
		"transfer_id":     transferID,
		"transfer_type":   transferType,
		"target_user":     targetUser,
		"original_owner":  originalOwner,
		"custody_user":    custodyUser,
		"content_hash":    nullableString(contentHash),
		"domain":          nullableString(domain),
		"app_name":        nullableString(appName),
		"contract_id":     contractID,
		"status":          status,
		"timestamp":       timestamp,
		"hps_amount":      nullableInt(amount),
		"hps_total_value": nullableInt(totalValue),
		"hps_voucher_ids": parseJSONStringSlice(voucherIDs.String),
		"hps_session_id":  nullableString(sessionID),
		"requester_user":  nullableString(requesterUser),
		"request_payload": parseJSONMap(requestPayload.String),
	}, true
}

func (s *Server) getMinerDebtStatus(username string) map[string]any {
	var pendingSignatures, pendingFines int
	_ = s.server.DB.QueryRow(`SELECT COALESCE(pending_signatures, 0), COALESCE(pending_fines, 0)
		FROM miner_stats WHERE username = ?`, username).Scan(&pendingSignatures, &pendingFines)
	return map[string]any{
		"pending_signatures": pendingSignatures,
		"pending_fines":      pendingFines,
		"debt_limit":         3,
	}
}

func (s *Server) isExchangeBlocked(issuer string) bool {
	var count int
	_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM hps_issuer_invalidations WHERE issuer = ?`, issuer).Scan(&count)
	if count > 0 {
		return true
	}
	rows, err := s.server.DB.Query(`SELECT contract_content, timestamp FROM contracts
		WHERE action_type = ? ORDER BY timestamp DESC LIMIT 50`, "economy_alert")
	if err != nil {
		return false
	}
	defer rows.Close()
	nowTs := nowSec()
	for rows.Next() {
		var contentB64 string
		var ts float64
		if rows.Scan(&contentB64, &ts) != nil || contentB64 == "" {
			continue
		}
		if nowTs-ts >= 86400 {
			continue
		}
		contractBytes, err := base64.StdEncoding.DecodeString(contentB64)
		if err != nil {
			continue
		}
		valid, _, info := core.ValidateContractStructure(contractBytes)
		if !valid || info == nil {
			continue
		}
		if core.ExtractContractDetail(info, "ISSUER") == issuer {
			return true
		}
	}
	return false
}

func (s *Server) getContractArchiveBytes(targetType, targetID string) []byte {
	var content []byte
	err := s.server.DB.QueryRow(`SELECT contract_content FROM contract_valid_archive
		WHERE target_type = ? AND target_id = ?`, targetType, targetID).Scan(&content)
	if err == nil && len(content) > 0 {
		return content
	}
	return nil
}

func (s *Server) registerContractViolation(violationType, contentHash, domain, reason, reportedBy, owner string, applyPenalty bool) {
	if reason == "" {
		reason = "missing_contract"
	}
	_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO contract_violations
		(violation_id, violation_type, content_hash, domain, owner_username, reported_by, timestamp, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		core.NewUUID(), violationType, nullIfEmpty(contentHash), nullIfEmpty(domain), owner, reportedBy, nowSec(), reason)
	if applyPenalty {
		s.server.AdjustReputation(owner, -20)
	}
}

func (s *Server) hasContractViolation(targetType, targetID string) bool {
	var count int
	if targetType == "domain" {
		_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM contract_violations WHERE violation_type = ? AND domain = ?`,
			targetType, targetID).Scan(&count)
	} else {
		_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM contract_violations WHERE violation_type = ? AND content_hash = ?`,
			targetType, targetID).Scan(&count)
	}
	return count > 0
}

func (s *Server) hasMissingContractViolation(targetType, targetID string) bool {
	var count int
	if targetType == "domain" {
		_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM contract_violations WHERE violation_type = ? AND domain = ? AND reason = ?`,
			targetType, targetID, "missing_contract").Scan(&count)
	} else {
		_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM contract_violations WHERE violation_type = ? AND content_hash = ? AND reason = ?`,
			targetType, targetID, "missing_contract").Scan(&count)
	}
	return count > 0
}

func (s *Server) getViolationOwner(targetType, targetID string) string {
	var owner string
	if targetType == "domain" {
		_ = s.server.DB.QueryRow(`SELECT owner_username FROM contract_violations WHERE violation_type = ? AND domain = ? LIMIT 1`,
			targetType, targetID).Scan(&owner)
	} else {
		_ = s.server.DB.QueryRow(`SELECT owner_username FROM contract_violations WHERE violation_type = ? AND content_hash = ? LIMIT 1`,
			targetType, targetID).Scan(&owner)
	}
	return owner
}

func (s *Server) clearContractViolation(targetType, targetID string) {
	if targetType == "domain" {
		_, _ = s.server.DB.Exec(`DELETE FROM contract_violations WHERE violation_type = ? AND domain = ?`, targetType, targetID)
	} else {
		_, _ = s.server.DB.Exec(`DELETE FROM contract_violations WHERE violation_type = ? AND content_hash = ?`, targetType, targetID)
	}
}

func (s *Server) emitPendingVoucherOffers(username string) {
	offers := s.server.ListPendingVoucherOffers(username)
	for _, offer := range offers {
		s.emitToUser(username, "hps_voucher_offer", map[string]any{
			"offer_id":          offer["offer_id"],
			"voucher_id":        offer["voucher_id"],
			"payload":           offer["payload"],
			"payload_canonical": offer["payload_canonical"],
			"expires_at":        offer["expires_at"],
		})
	}
}

func (s *Server) emitPendingTransferNotice(username string) {
	if username == "" {
		return
	}
	s.emitToUser(username, "pending_transfer_notice", map[string]any{
		"count": countPendingForUser(s.server.DB, username),
	})
}

func (s *Server) notifyMonetaryTransferUpdate(transferID, status, reason string, details map[string]any) {
	transfer, ok := s.getMonetaryTransfer(transferID)
	if !ok {
		return
	}
	payload := map[string]any{
		"transfer_id":    transferID,
		"transfer_type":  asString(transfer["transfer_type"]),
		"sender":         asString(transfer["sender"]),
		"receiver":       asString(transfer["receiver"]),
		"status":         status,
		"assigned_miner": asString(transfer["assigned_miner"]),
		"reason":         reason,
	}
	if details != nil {
		payload["details"] = details
	}
	s.emitToUser(asString(transfer["sender"]), "monetary_transfer_update", payload)
	s.emitToUser(asString(transfer["receiver"]), "monetary_transfer_update", payload)
	s.relayExchangeEventToIssuer(transfer, "monetary_transfer_update", payload)
}

func (s *Server) rollbackSpendHpsTransfer(transferID, reason string) {
	if transferID == "" {
		return
	}
	transfer, ok := s.getMonetaryTransfer(transferID)
	if !ok {
		return
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(asString(transfer["transfer_type"]))), "spend_hps:") {
		return
	}

	action := s.server.GetPendingMonetaryAction(transferID)
	payload := map[string]any{}
	responseEvent := ""
	username := asString(transfer["sender"])
	if action != nil {
		payload = castMap(action["payload"])
		responseEvent = asString(action["response_event"])
		if actionUser := asString(action["username"]); actionUser != "" {
			username = actionUser
		}
		if actionID := asString(action["action_id"]); actionID != "" {
			s.server.UpdatePendingMonetaryActionStatus(actionID, "failed:"+defaultStr(reason, "transfer_expired"))
		}
	}

	sessionID := asString(castMap(payload["payment"])["session_id"])
	if sessionID != "" {
		s.server.ReleaseVouchersForSession(sessionID)
	} else {
		for _, voucherID := range toStringSlice(transfer["locked_voucher_ids"]) {
			if voucherID == "" {
				continue
			}
			_, _ = s.server.DB.Exec(`UPDATE hps_vouchers
				SET status = ?, session_id = NULL, last_updated = ?
				WHERE voucher_id = ? AND status = ?`, "valid", nowSec(), voucherID, "reserved")
		}
	}

	if username != "" {
		s.emitWalletSyncToUser(username)
		if responseEvent != "" {
			errorText := "Transacao HPS expirada antes da finalizacao."
			switch defaultStr(reason, "") {
			case "no_miners":
				errorText = "Nenhum minerador elegivel disponivel para finalizar o pagamento HPS."
			case "miner_unreachable":
				errorText = "O minerador atribuido ficou indisponivel antes de finalizar o pagamento HPS."
			case "miner_deadline_expired":
				errorText = "O prazo do minerador expirou antes de finalizar o pagamento HPS."
			case "selector_timeout", "selector_deadline_expired":
				errorText = "A selecao de minerador expirou antes de finalizar o pagamento HPS."
			}
			s.emitToUser(username, responseEvent, map[string]any{
				"success":     false,
				"transfer_id": transferID,
				"error":       errorText,
			})
		}
	}
}

func (s *Server) relayExchangeEventToIssuer(transfer map[string]any, event string, payload map[string]any) {
	if transfer == nil || !strings.EqualFold(asString(transfer["transfer_type"]), "exchange_in") {
		return
	}
	interPayload := castMap(transfer["inter_server_payload"])
	issuerAddress := asString(interPayload["issuer_address"])
	if issuerAddress == "" {
		issuerAddress = asString(interPayload["issuer"])
	}
	originUsername := asString(interPayload["origin_username"])
	if issuerAddress == "" || originUsername == "" || event == "" || payload == nil {
		return
	}
	relayPayload := cloneMap(payload)
	ok, _, errMsg := s.server.MakeRemoteRequestJSON(issuerAddress, "/exchange/relay", http.MethodPost, map[string]any{
		"username": originUsername,
		"event":    event,
		"payload":  relayPayload,
	})
	if !ok {
		log.Printf("exchange relay failed issuer=%s user=%s event=%s err=%s", issuerAddress, originUsername, event, errMsg)
	}
}

func (s *Server) rollbackConfirmedExchange(issuerAddress, issuer, tokenID, owner string, totalValue, feeAmount int, offerID, reason string) {
	if tokenID == "" || s.hasContractActionForOp("hps_exchange_target_confirm_rollback", tokenID) {
		return
	}
	if offerID != "" {
		_, _ = s.server.DB.Exec(`UPDATE hps_voucher_offers
			SET status = ?
			WHERE offer_id = ? AND (status = ? OR status = ?)`, "expired", offerID, "withheld", "pending")
	}
	if feeAmount > 0 {
		balance := s.server.GetEconomyStat("custody_balance", 0.0)
		s.server.SetEconomyStat("custody_balance", balance-float64(feeAmount))
		s.server.RecordEconomyEvent("exchange_fee_rollback")
		s.server.RecordEconomyContract("exchange_fee_rollback")
	}
	s.server.SaveServerContract("hps_exchange_target_confirm_rollback", []core.ContractDetail{
		{Key: "TOKEN_ID", Value: tokenID},
		{Key: "OWNER", Value: owner},
		{Key: "TOTAL_VALUE", Value: totalValue},
		{Key: "REASON", Value: defaultStr(reason, "exchange_confirm_failed")},
		{Key: "EXCHANGE_OFFER_ID", Value: offerID},
		{Key: "EXCHANGE_FEE", Value: feeAmount},
	}, tokenID)

	if issuerAddress == "" {
		issuerAddress = issuer
	}
	if issuerAddress == "" || owner == "" || totalValue <= 0 {
		return
	}
	_, _, errMsg := s.server.MakeRemoteRequestJSON(issuerAddress, "/exchange/rollback", http.MethodPost, map[string]any{
		"token_id":    tokenID,
		"owner":       owner,
		"total_value": totalValue,
		"reason":      defaultStr(reason, "exchange_confirm_failed"),
	})
	if errMsg != "" {
		log.Printf("exchange confirm rollback failed issuer=%s token=%s err=%s", issuerAddress, tokenID, errMsg)
	}
}

func (s *Server) hasContractActionForOp(actionType, opID string) bool {
	if actionType == "" || opID == "" {
		return false
	}
	var count int
	_ = s.server.DB.QueryRow(`SELECT COUNT(1) FROM contracts WHERE action_type = ? AND content_hash = ?`, actionType, opID).Scan(&count)
	return count > 0
}

func (s *Server) rollbackExchangeTransfer(transfer map[string]any, reason string) {
	if transfer == nil || !strings.EqualFold(asString(transfer["transfer_type"]), "exchange_in") {
		return
	}
	transferID := asString(transfer["transfer_id"])
	if transferID == "" || s.hasContractActionForOp("hps_exchange_target_rollback", transferID) {
		return
	}
	interPayload := castMap(transfer["inter_server_payload"])
	exchangeOfferID := asString(interPayload["exchange_offer_id"])
	if exchangeOfferID != "" {
		_, _ = s.server.DB.Exec(`UPDATE hps_voucher_offers
			SET status = ?
			WHERE offer_id = ? AND (status = ? OR status = ?)`, "expired", exchangeOfferID, "withheld", "pending")
	}
	exchangeFeeAmount := asInt(interPayload["exchange_fee_amount"])
	if exchangeFeeAmount > 0 {
		balance := s.server.GetEconomyStat("custody_balance", 0.0)
		s.server.SetEconomyStat("custody_balance", balance-float64(exchangeFeeAmount))
		s.server.RecordEconomyEvent("exchange_fee_rollback")
		s.server.RecordEconomyContract("exchange_fee_rollback")
	}
	s.server.SaveServerContract("hps_exchange_target_rollback", []core.ContractDetail{
		{Key: "TRANSFER_ID", Value: transferID},
		{Key: "REASON", Value: defaultStr(reason, "exchange_failed")},
		{Key: "EXCHANGE_OFFER_ID", Value: exchangeOfferID},
		{Key: "EXCHANGE_FEE", Value: exchangeFeeAmount},
	}, transferID)

	issuerAddress := asString(interPayload["issuer_address"])
	if issuerAddress == "" {
		issuerAddress = asString(interPayload["issuer"])
	}
	tokenID := asString(interPayload["issuer_token_id"])
	owner := asString(interPayload["issuer_owner"])
	totalValue := asInt(interPayload["issuer_total_value"])
	if issuerAddress == "" || tokenID == "" || owner == "" || totalValue <= 0 {
		return
	}
	go func(issuerAddress, tokenID, transferID, owner string, totalValue int, reason string) {
		_, _, errMsg := s.server.MakeRemoteRequestJSON(issuerAddress, "/exchange/rollback", http.MethodPost, map[string]any{
			"token_id":    tokenID,
			"transfer_id": transferID,
			"owner":       owner,
			"total_value": totalValue,
			"reason":      defaultStr(reason, "exchange_failed"),
		})
		if errMsg != "" {
			log.Printf("exchange rollback failed issuer=%s transfer=%s token=%s err=%s", issuerAddress, transferID, tokenID, errMsg)
		}
	}(issuerAddress, tokenID, transferID, owner, totalValue, reason)
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func (s *Server) enforceMinerSignatureDeadline(transferID, miner string, deadline float64) {
	waitSec := deadline - nowSec()
	if waitSec > 0 {
		time.Sleep(time.Duration(waitSec * float64(time.Second)))
	}
	transfer, ok := s.getMonetaryTransfer(transferID)
	if !ok {
		return
	}
	currentDeadline := asFloat(transfer["miner_deadline"])
	if currentDeadline > deadline+0.5 {
		go s.enforceMinerSignatureDeadline(transferID, miner, currentDeadline)
		return
	}
	if asString(transfer["status"]) == "signed" {
		return
	}
	if asString(transfer["status"]) != "pending_signature" {
		return
	}
	if !strings.EqualFold(asString(transfer["assigned_miner"]), miner) {
		return
	}
	log.Printf("selector flow: miner deadline expired transfer=%s miner=%s type=%s", transferID, miner, asString(transfer["transfer_type"]))
	if strings.EqualFold(asString(transfer["transfer_type"]), "exchange_in") {
		if s.retryExchangeMinerAssignment(transfer, miner, "miner_deadline_expired") {
			return
		}
	}
	feeAmount := asInt(transfer["fee_amount"])
	s.server.AddMinerDebtEntry(miner, "fine_delay", 0, map[string]any{
		"transfer_id": transferID,
		"deadline":    deadline,
		"fee_amount":  feeAmount,
	})
	s.server.SyncMinerPendingCounts(miner)
	pending, _ := s.server.GetMinerPendingCounts(miner)
	s.emitToUser(miner, "miner_signature_update", map[string]any{
		"pending_signatures": pending,
		"debt_status":        s.server.SafeGetMinerDebtStatus(miner),
	})
	_, _ = s.server.DB.Exec(`UPDATE monetary_transfers
		SET status = ?, miner_deadline = NULL
		WHERE transfer_id = ?`, "expired", transferID)
	s.rollbackSpendHpsTransfer(transferID, "miner_deadline_expired")
	s.rollbackExchangeTransfer(transfer, "miner_deadline_expired")
	s.notifyMonetaryTransferUpdate(transferID, "expired", "miner_deadline_expired", map[string]any{
		"miner":       miner,
		"transfer_id": transferID,
	})
}

func (s *Server) enforceSelectorDecisionDeadline(transferID, sender, receiver string, deadline float64) {
	waitSec := deadline - nowSec()
	if waitSec > 0 {
		time.Sleep(time.Duration(waitSec * float64(time.Second)))
	}
	transfer, ok := s.getMonetaryTransfer(transferID)
	if !ok {
		return
	}
	if asString(transfer["assigned_miner"]) != "" {
		log.Printf("selector flow: selector deadline reached but miner already assigned transfer=%s", transferID)
		return
	}
	if asString(transfer["status"]) != "awaiting_selector" {
		log.Printf("selector flow: selector deadline reached but status=%s transfer=%s", asString(transfer["status"]), transferID)
		return
	}
	log.Printf("selector flow: selector deadline expired -> fallback transfer=%s", transferID)
	s.assignMinerFallback(transferID, sender, receiver, "selector_deadline_expired")
}

func (s *Server) emitToUser(username, event string, payload map[string]any) {
	_ = s.emitToUserCount(username, event, payload)
}

func (s *Server) emitToUserCount(username, event string, payload map[string]any) int {
	username = trim(username)
	if username == "" {
		return 0
	}
	s.mu.Lock()
	conns := []socketio.Conn{}
	for sid, c := range s.clients {
		if c != nil && c.Authenticated && strings.EqualFold(trim(c.Username), username) {
			if conn, ok := s.conns[sid]; ok && conn != nil {
				conns = append(conns, conn)
			}
		}
	}
	s.mu.Unlock()
	if event == "monetary_transfer_pending" || event == "monetary_transfer_update" || event == "miner_signature_request" || event == "exchange_pending" || event == "exchange_complete" || event == "hps_wallet_sync" {
		log.Printf("emitToUser event=%s user=%s targets=%d", event, username, len(conns))
	}
	for _, conn := range conns {
		conn.Emit(event, payload)
	}
	return len(conns)
}

func (s *Server) incrementViolation(clientIdentifier string) int {
	clientIdentifier = trim(clientIdentifier)
	if clientIdentifier == "" {
		return 0
	}
	_, _ = s.server.DB.Exec(`UPDATE user_reputations SET violation_count = COALESCE(violation_count, 0) + 1 WHERE client_identifier = ?`,
		clientIdentifier)
	var count int
	_ = s.server.DB.QueryRow(`SELECT COALESCE(MAX(violation_count), 0) FROM user_reputations WHERE client_identifier = ?`, clientIdentifier).Scan(&count)
	if count <= 0 {
		var attempts int
		_ = s.server.DB.QueryRow(`SELECT COALESCE(MAX(attempt_count), 0) FROM rate_limits WHERE client_identifier = ?`, clientIdentifier).Scan(&attempts)
		if attempts > 0 {
			count = attempts
		}
	}
	return count
}

func (s *Server) banClientAndNotify(clientIdentifier string, duration int, reason string) {
	clientIdentifier = trim(clientIdentifier)
	if clientIdentifier == "" {
		return
	}
	if duration <= 0 {
		duration = 300
	}
	s.server.BanClient(clientIdentifier, float64(duration), reason)
	_, _ = s.server.DB.Exec(`UPDATE user_reputations SET reputation = 1 WHERE client_identifier = ?`, clientIdentifier)
	_, _ = s.server.DB.Exec(`UPDATE users SET reputation = 1 WHERE client_identifier = ?`, clientIdentifier)
	s.mu.Lock()
	targets := []string{}
	for sid, c := range s.clients {
		if c != nil && trim(c.ClientIdentifier) == clientIdentifier {
			c.Authenticated = false
			c.Username = ""
			targets = append(targets, sid)
		}
	}
	s.mu.Unlock()
	for _, sid := range targets {
		if conn, ok := s.conns[sid]; ok && conn != nil {
			conn.Emit("ban_notification", map[string]any{"duration": duration, "reason": reason})
		}
	}
}

func (s *Server) processContentReport(reportID, contentHash, reportedUser, reporter string) {
	if trim(reportID) == "" || trim(contentHash) == "" || trim(reportedUser) == "" || trim(reporter) == "" {
		return
	}
	var otherReports int
	_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM content_reports
		WHERE content_hash = ? AND reporter != ? AND resolved = 0`, contentHash, reporter).Scan(&otherReports)
	if otherReports < 2 {
		return
	}
	s.server.AdjustReputation(reportedUser, -20)
	s.server.AdjustReputation(reporter, 5)
	_, _ = s.server.DB.Exec(`UPDATE content_reports SET resolved = 1, resolution_type = ? WHERE report_id = ?`, "auto_warn", reportID)
	rep := s.getUserReputation(reportedUser)
	s.emitToUser(reportedUser, "reputation_update", map[string]any{"reputation": rep})
	s.emitToUser(reportedUser, "notification", map[string]any{"message": "Your reputation was reduced due to content reports."})
}

func (s *Server) listRemoteServersByReputation() []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)

	appendAddress := func(addr string) {
		addr = trim(addr)
		if addr == "" || core.MessageServerAddressesEqual(addr, s.server.Address, s.server.BindAddress) {
			return
		}
		normalized := core.NormalizeMessageServerAddress(addr)
		if normalized == "" {
			return
		}
		if _, exists := seen[normalized]; exists {
			return
		}
		seen[normalized] = struct{}{}
		out = append(out, addr)
	}

	rows, err := s.server.DB.Query(`SELECT address FROM server_nodes WHERE is_active = 1 AND address != ? ORDER BY reputation DESC`, s.server.Address)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var addr string
			if rows.Scan(&addr) != nil {
				continue
			}
			appendAddress(addr)
		}
	}

	knownRows, err := s.server.DB.Query(`SELECT address FROM known_servers WHERE is_active = 1 ORDER BY last_connected DESC`)
	if err == nil {
		defer knownRows.Close()
		for knownRows.Next() {
			var addr string
			if knownRows.Scan(&addr) != nil {
				continue
			}
			appendAddress(addr)
		}
	}

	return out
}

func (s *Server) fetchContentFromNetwork(contentHash string) bool {
	contentHash = trim(contentHash)
	if contentHash == "" {
		return false
	}
	clientResult := make(chan bool, 1)
	go func() {
		clientResult <- s.requestContentFromClients(contentHash)
	}()
	select {
	case ok := <-clientResult:
		if ok {
			log.Printf("content propagation: client supplied hash=%s", contentHash)
			return true
		}
		clientResult = nil
	case <-time.After(2 * time.Second):
	}
	servers := s.listRemoteServersByReputation()
	log.Printf("content propagation: search start hash=%s remote_servers=%d", contentHash, len(servers))
	for _, serverAddr := range servers {
		select {
		case ok := <-clientResult:
			if ok {
				log.Printf("content propagation: client supplied hash=%s", contentHash)
				return true
			}
			clientResult = nil
		default:
		}
		okMeta, payload, metaErr := s.server.MakeRemoteRequestJSON(serverAddr, "/sync/content?content_hash="+url.QueryEscape(contentHash), http.MethodGet, nil)
		items := []map[string]any{}
		if okMeta {
			items = castSliceMap(payload["items"])
		} else if metaErr != "" {
			log.Printf("content propagation: metadata fetch failed hash=%s server=%s err=%s", contentHash, serverAddr, metaErr)
		}
		okRaw, raw, rawErr := s.server.MakeRemoteRequestBytes(serverAddr, "/content/"+url.PathEscape(contentHash), http.MethodGet)
		if !okRaw || len(raw) == 0 {
			log.Printf("content propagation: raw fetch failed hash=%s server=%s err=%s", contentHash, serverAddr, rawErr)
			continue
		}
		if len(items) == 0 {
			log.Printf("content propagation: raw fetch ignored hash=%s server=%s reason=missing_metadata", contentHash, serverAddr)
			continue
		}
		filePath := s.server.ContentPath(contentHash)
		if err := s.server.WriteEncryptedFile(filePath, raw, 0o644); err != nil {
			log.Printf("content propagation: write failed hash=%s server=%s err=%v", contentHash, serverAddr, err)
			continue
		}
		if len(items) > 0 {
			meta := items[0]
			_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO content
					(content_hash, title, description, mime_type, size, username, signature, public_key, timestamp, file_path, verified, replication_count, last_accessed, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				contentHash,
				asString(meta["title"]),
				asString(meta["description"]),
				asString(meta["mime_type"]),
				asInt(meta["size"]),
				asString(meta["username"]),
				asString(meta["signature"]),
				asString(meta["public_key"]),
				asFloat(meta["timestamp"]),
				filePath,
				intFromBool(asBool(meta["verified"])),
				asInt(meta["replication_count"]),
				nowSec(),
				asString(meta["issuer_server"]),
				asString(meta["issuer_public_key"]),
				asString(meta["issuer_contract_id"]),
				asFloat(meta["issuer_issued_at"]),
			)
			for _, contractMeta := range castSliceMap(meta["contracts"]) {
				contractID := asString(contractMeta["contract_id"])
				if contractID == "" {
					continue
				}
				contractText := asString(contractMeta["contract_content"])
				if contractText == "" {
					_ = s.fetchContractFromNetwork(contractID)
					continue
				}
				contractBytes := []byte(contractText)
				valid, _, info := core.ValidateContractStructure(contractBytes)
				if !valid || info == nil {
					log.Printf("content propagation: rejected remote contract hash=%s contract=%s server=%s reason=invalid_contract", contentHash, contractID, serverAddr)
					continue
				}
				publicKey := core.ExtractContractDetail(info, "PUBLIC_KEY")
				if publicKey == "" {
					publicKey = s.server.GetRegisteredPublicKey(info.User)
				}
				if !s.server.VerifyContractSignature(contractBytes, info.User, info.Signature, publicKey) {
					log.Printf("content propagation: rejected remote contract hash=%s contract=%s server=%s reason=invalid_signature user=%s", contentHash, contractID, serverAddr, info.User)
					continue
				}
				domain := defaultStr(core.ExtractContractDetail(info, "DOMAIN"), core.ExtractContractDetail(info, "DNAME"))
				if domain == "" {
					domain = asString(contractMeta["domain"])
				}
				contractPath := filepath.Join(s.server.FilesDir, "contracts", contractID+".contract")
				_ = s.server.WriteEncryptedFile(contractPath, contractBytes, 0o644)
				_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO contracts
						(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
						VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					contractID,
					info.Action,
					contentHash,
					nullIfEmpty(domain),
					info.User,
					info.Signature,
					asFloat(contractMeta["timestamp"]),
					1,
					base64.StdEncoding.EncodeToString(contractBytes),
				)
				_ = s.server.SaveContractArchiveByContract(contractID, contractBytes)
			}
			log.Printf("content propagation: fetched hash=%s from server=%s with metadata contracts=%d", contentHash, serverAddr, len(castSliceMap(meta["contracts"])))
			return true
		}
	}
	if clientResult != nil {
		ok := <-clientResult
		if ok {
			log.Printf("content propagation: client supplied hash=%s after server search", contentHash)
		} else {
			log.Printf("content propagation: search exhausted hash=%s", contentHash)
		}
		return ok
	}
	log.Printf("content propagation: search exhausted hash=%s", contentHash)
	return false
}

func (s *Server) resolveDNSFromNetwork(domain string) bool {
	domain = strings.ToLower(trim(domain))
	if domain == "" {
		return false
	}
	servers := s.listRemoteServersByReputation()
	for _, serverAddr := range servers {
		okDNS, dnsData, _ := s.server.MakeRemoteRequestJSON(serverAddr, "/dns/"+url.PathEscape(domain), http.MethodGet, nil)
		if !okDNS || !asBool(dnsData["success"]) {
			continue
		}
		contentHash := asString(dnsData["content_hash"])
		if contentHash == "" {
			continue
		}
		ddnsHash := asString(dnsData["ddns_hash"])
		ddnsPath := ""
		if ddnsHash != "" {
			ddnsPath = s.server.DdnsPath(ddnsHash)
		}
		if ddnsHash == "" || !fileExists(ddnsPath) {
			okDDNS, ddnsBytes, _ := s.server.MakeRemoteRequestBytes(serverAddr, "/ddns/"+url.PathEscape(domain), http.MethodGet)
			if okDDNS && len(ddnsBytes) > 0 {
				sum := sha256.Sum256(ddnsBytes)
				fetchedHash := hex.EncodeToString(sum[:])
				if ddnsHash == "" || strings.EqualFold(ddnsHash, fetchedHash) {
					ddnsHash = fetchedHash
					ddnsPath = s.server.DdnsPath(ddnsHash)
					_ = s.server.WriteEncryptedFile(ddnsPath, ddnsBytes, 0o644)
				}
			}
		}
		_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO dns_records
			(domain, content_hash, username, original_owner, timestamp, signature, verified, last_resolved, ddns_hash, issuer_server, issuer_public_key, issuer_contract_id, issuer_issued_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			domain,
			contentHash,
			asString(dnsData["username"]),
			defaultStr(asString(dnsData["original_owner"]), asString(dnsData["username"])),
			asFloat(dnsData["timestamp"]),
			asString(dnsData["signature"]),
			intFromBool(asBool(dnsData["verified"])),
			nowSec(),
			ddnsHash,
			defaultStr(asString(dnsData["issuer_server"]), serverAddr),
			asString(dnsData["issuer_public_key"]),
			asString(dnsData["issuer_contract_id"]),
			asFloat(dnsData["issuer_issued_at"]),
		)
		if contracts := castSliceMap(dnsData["contracts"]); len(contracts) > 0 {
			items := make([]any, 0, len(contracts))
			for _, contract := range contracts {
				items = append(items, contract)
			}
			s.server.UpsertContractsFromSyncPayload(serverAddr, map[string]any{"items": items})
		}
		return true
	}
	if s.requestDDNSFromClients(domain) {
		return true
	}
	return false
}

func (s *Server) fetchContractFromNetwork(contractID string) bool {
	contractID = trim(contractID)
	if contractID == "" {
		return false
	}
	servers := s.listRemoteServersByReputation()
	for _, serverAddr := range servers {
		okRaw, contractBytes, _ := s.server.MakeRemoteRequestBytes(serverAddr, "/contract/"+url.PathEscape(contractID), http.MethodGet)
		if !okRaw || len(contractBytes) == 0 {
			continue
		}
		contractPath := filepath.Join(s.server.FilesDir, "contracts", contractID+".contract")
		if err := s.server.WriteEncryptedFile(contractPath, contractBytes, 0o644); err != nil {
			continue
		}
		valid, _, contractInfo := core.ValidateContractStructure(contractBytes)
		actionType := ""
		username := ""
		signature := ""
		contentHash := ""
		domain := ""
		verified := 0
		if valid && contractInfo != nil {
			actionType = contractInfo.Action
			username = contractInfo.User
			signature = contractInfo.Signature
			contentHash = core.ExtractContractDetail(contractInfo, "FILE_HASH")
			if contentHash == "" {
				contentHash = core.ExtractContractDetail(contractInfo, "CONTENT_HASH")
			}
			domain = core.ExtractContractDetail(contractInfo, "DOMAIN")
			if domain == "" {
				domain = core.ExtractContractDetail(contractInfo, "DNAME")
			}
			if s.server.VerifyContractSignature(contractBytes, username, signature, "") {
				verified = 1
			}
		}
		if core.ShouldHideReplicatedContract(username, verified != 0) {
			continue
		}
		_, _ = s.server.DB.Exec(`INSERT OR REPLACE INTO contracts
			(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			contractID,
			actionType,
			nullIfEmpty(contentHash),
			nullIfEmpty(domain),
			username,
			signature,
			nowSec(),
			verified,
			base64.StdEncoding.EncodeToString(contractBytes),
		)
		return true
	}
	if s.requestContractFromClients(contractID) {
		return true
	}
	return false
}

func (s *Server) requestContentFromClients(contentHash string) bool {
	contentHash = trim(contentHash)
	if contentHash == "" {
		return false
	}
	clientIDs := []string{}
	indexed := false
	rows, err := s.server.DB.Query(`SELECT DISTINCT client_identifier FROM client_files WHERE content_hash = ?
		UNION
		SELECT DISTINCT client_identifier FROM client_contracts WHERE content_hash = ?`, contentHash, contentHash)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cid string
			if rows.Scan(&cid) == nil && trim(cid) != "" {
				clientIDs = append(clientIDs, cid)
			}
		}
	}
	if len(clientIDs) > 0 {
		indexed = true
	}
	if len(clientIDs) == 0 {
		clientIDs = s.authenticatedClientIdentifiers()
		if len(clientIDs) == 0 {
			log.Printf("content propagation: no client candidates hash=%s", contentHash)
			return false
		}
		log.Printf("content propagation: no indexed candidates hash=%s; broadcasting to authenticated clients=%d", contentHash, len(clientIDs))
	}
	log.Printf("content propagation: requesting hash=%s from client_candidates=%d", contentHash, len(clientIDs))
	if s.requestContentFromClientIdentifiers(contentHash, clientIDs, 8*time.Second) {
		return true
	}
	if indexed {
		indexedSet := map[string]bool{}
		for _, cid := range clientIDs {
			indexedSet[trim(cid)] = true
		}
		fallbackClientIDs := []string{}
		for _, cid := range s.authenticatedClientIdentifiers() {
			if indexedSet[trim(cid)] {
				continue
			}
			fallbackClientIDs = append(fallbackClientIDs, cid)
		}
		if len(fallbackClientIDs) > 0 {
			log.Printf("content propagation: indexed clients missed hash=%s; broadcasting to other authenticated clients=%d", contentHash, len(fallbackClientIDs))
			if s.requestContentFromClientIdentifiers(contentHash, fallbackClientIDs, 8*time.Second) {
				return true
			}
		}
	}
	log.Printf("content propagation: client request timed out hash=%s client_candidates=%d", contentHash, len(clientIDs))
	return false
}

func (s *Server) requestContentFromClientIdentifiers(contentHash string, clientIDs []string, timeout time.Duration) bool {
	emitted := s.emitRequestToClientIdentifiers(clientIDs, "request_content_from_client", map[string]any{"content_hash": contentHash})
	log.Printf("content propagation: request emitted hash=%s requested_clients=%d delivered_clients=%d", contentHash, len(clientIDs), emitted)
	if emitted == 0 {
		return false
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.contentPayloadStored(contentHash) {
			log.Printf("content propagation: client response stored hash=%s", contentHash)
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (s *Server) authenticatedClientIdentifiers() []string {
	clientIDs := []string{}
	seen := map[string]bool{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, client := range s.clients {
		if client == nil || !client.Authenticated {
			continue
		}
		cid := trim(client.ClientIdentifier)
		if cid == "" || seen[cid] {
			continue
		}
		seen[cid] = true
		clientIDs = append(clientIDs, cid)
	}
	return clientIDs
}

func (s *Server) contentReadyForResponse(contentHash string) bool {
	if !s.contentPayloadStored(contentHash) {
		return false
	}
	violation, reason := s.server.EvaluateContractViolationForContent(contentHash)
	if violation && reason == "missing_contract" {
		_ = s.requestContractsForContentFromClients(contentHash)
		violation, _ = s.server.EvaluateContractViolationForContent(contentHash)
	}
	return !violation
}

func (s *Server) contentPayloadStored(contentHash string) bool {
	if _, err := os.Stat(s.server.ContentPath(contentHash)); err != nil {
		return false
	}
	var exists int
	_ = s.server.DB.QueryRow(`SELECT 1 FROM content WHERE content_hash = ?`, contentHash).Scan(&exists)
	return exists == 1
}

func (s *Server) requestDDNSFromClients(domain string) bool {
	domain = strings.ToLower(trim(domain))
	if domain == "" {
		return false
	}
	clientIDs := []string{}
	rows, err := s.server.DB.Query(`SELECT DISTINCT client_identifier FROM client_dns_files WHERE domain = ?`, domain)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cid string
			if rows.Scan(&cid) == nil && trim(cid) != "" {
				clientIDs = append(clientIDs, cid)
			}
		}
	}
	if len(clientIDs) == 0 {
		return false
	}
	s.emitRequestToClientIdentifiers(clientIDs, "request_ddns_from_client", map[string]any{"domain": domain})
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var exists int
		_ = s.server.DB.QueryRow(`SELECT 1 FROM dns_records WHERE domain = ?`, domain).Scan(&exists)
		if exists == 1 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (s *Server) requestContractFromClients(contractID string) bool {
	contractID = trim(contractID)
	if contractID == "" {
		return false
	}
	clientIDs := []string{}
	rows, err := s.server.DB.Query(`SELECT DISTINCT client_identifier FROM client_contracts WHERE contract_id = ?`, contractID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cid string
			if rows.Scan(&cid) == nil && trim(cid) != "" {
				clientIDs = append(clientIDs, cid)
			}
		}
	}
	if len(clientIDs) == 0 {
		return false
	}
	s.emitRequestToClientIdentifiers(clientIDs, "request_contract_from_client", map[string]any{"contract_id": contractID})
	contractPath := filepath.Join(s.server.FilesDir, "contracts", contractID+".contract")
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var exists int
		_ = s.server.DB.QueryRow(`SELECT 1 FROM contracts WHERE contract_id = ?`, contractID).Scan(&exists)
		if exists == 1 {
			if _, err := os.Stat(contractPath); err == nil {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (s *Server) requestContractsForContentFromClients(contentHash string) bool {
	contentHash = trim(contentHash)
	if contentHash == "" {
		return false
	}
	rows, err := s.server.DB.Query(`SELECT DISTINCT contract_id FROM client_contracts WHERE content_hash = ?`, contentHash)
	if err != nil {
		return false
	}
	defer rows.Close()
	contractIDs := []string{}
	for rows.Next() {
		var contractID string
		if rows.Scan(&contractID) != nil || trim(contractID) == "" {
			continue
		}
		var exists int
		_ = s.server.DB.QueryRow(`SELECT 1 FROM contracts WHERE contract_id = ? LIMIT 1`, contractID).Scan(&exists)
		if exists == 1 {
			return true
		}
		contractIDs = append(contractIDs, contractID)
	}
	if len(contractIDs) == 0 {
		return false
	}
	for _, contractID := range contractIDs {
		contractID := contractID
		go s.requestContractFromClients(contractID)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var exists int
		_ = s.server.DB.QueryRow(`SELECT 1 FROM contracts WHERE content_hash = ? LIMIT 1`, contentHash).Scan(&exists)
		if exists == 1 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (s *Server) requestContractsForDomainFromClients(domain string) bool {
	domain = strings.ToLower(trim(domain))
	if domain == "" {
		return false
	}
	rows, err := s.server.DB.Query(`SELECT DISTINCT contract_id FROM client_contracts WHERE domain = ?`, domain)
	if err != nil {
		return false
	}
	defer rows.Close()
	contractIDs := []string{}
	for rows.Next() {
		var contractID string
		if rows.Scan(&contractID) != nil || trim(contractID) == "" {
			continue
		}
		var exists int
		_ = s.server.DB.QueryRow(`SELECT 1 FROM contracts WHERE contract_id = ? LIMIT 1`, contractID).Scan(&exists)
		if exists == 1 {
			return true
		}
		contractIDs = append(contractIDs, contractID)
	}
	if len(contractIDs) == 0 {
		return false
	}
	for _, contractID := range contractIDs {
		contractID := contractID
		go s.requestContractFromClients(contractID)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var exists int
		_ = s.server.DB.QueryRow(`SELECT 1 FROM contracts WHERE domain = ? LIMIT 1`, domain).Scan(&exists)
		if exists == 1 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (s *Server) emitRequestToClientIdentifiers(clientIdentifiers []string, event string, payload map[string]any) int {
	if len(clientIdentifiers) == 0 || trim(event) == "" {
		return 0
	}
	idSet := map[string]bool{}
	for _, cid := range clientIdentifiers {
		cid = trim(cid)
		if cid != "" {
			idSet[cid] = true
		}
	}
	s.mu.Lock()
	targets := []socketio.Conn{}
	for sid, state := range s.clients {
		if state == nil || !state.Authenticated {
			continue
		}
		if !idSet[trim(state.ClientIdentifier)] {
			continue
		}
		if conn, ok := s.conns[sid]; ok && conn != nil {
			targets = append(targets, conn)
		}
	}
	s.mu.Unlock()
	for _, conn := range targets {
		conn.Emit(event, payload)
	}
	return len(targets)
}

func (s *Server) broadcastToAuthenticated(event string, payload map[string]any) {
	if trim(event) == "" {
		return
	}
	s.mu.Lock()
	targets := []string{}
	for sid, c := range s.clients {
		if c != nil && c.Authenticated {
			targets = append(targets, sid)
		}
	}
	s.mu.Unlock()
	for _, sid := range targets {
		s.io.BroadcastToRoom("/", sid, event, payload)
	}
}

func (s *Server) getHpsEconomyStatusPayload() map[string]any {
	powCosts := map[string]any{}
	for action := range s.server.HpsPowCosts {
		powCosts[action] = s.server.GetHpsPowCost(action)
	}
	var connectedServers int
	_ = s.server.DB.QueryRow(`SELECT COUNT(*) FROM known_servers WHERE is_active = 1`).Scan(&connectedServers)
	return map[string]any{
		"issuer":                 s.server.Address,
		"total_minted":           s.server.GetEconomyStat("total_minted", 0.0),
		"custody_balance":        s.server.GetEconomyStat("custody_balance", 0.0),
		"owner_balance":          s.server.GetEconomyStat("owner_balance", 0.0),
		"rebate_balance":         s.server.GetEconomyStat("rebate_balance", 0.0),
		"inflation_rate":         s.server.GetInflationRate(),
		"multiplier":             s.server.GetEconomyMultiplier(),
		"pow_costs":              powCosts,
		"exchange_fee_rate":      s.server.ExchangeFeeRate,
		"exchange_fee_min":       s.server.ExchangeFeeMin,
		"last_economy_update":    s.server.GetEconomyStat("last_economy_update_ts", 0.0),
		"last_economy_event":     s.server.GetEconomyStat("last_economy_event_ts", 0.0),
		"last_economy_reason":    s.getEconomyStatText("last_economy_event_reason"),
		"last_economy_contract":  s.getEconomyStatText("last_economy_contract_id"),
		"connected_clients":      atomic.LoadInt64(&s.server.ConnectedClients),
		"connected_servers":      connectedServers,
		"hps_issuer_invalidated": s.isExchangeBlocked(s.server.Address),
	}
}

func (s *Server) getEconomyStatText(key string) string {
	if key == "" {
		return ""
	}
	var value sql.NullString
	if err := s.server.DB.QueryRow(`SELECT stat_value FROM hps_economy_stats WHERE stat_key = ?`, key).Scan(&value); err != nil {
		return ""
	}
	if !value.Valid {
		return ""
	}
	return value.String
}

func (s *Server) emitContractViolationsForUser(username string) {
	username = trim(username)
	if username == "" {
		return
	}
	rows, err := s.server.DB.Query(`SELECT violation_type, content_hash, domain, reason
		FROM contract_violations WHERE owner_username = ?`, username)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var violationType, reason string
		var contentHash, domain sql.NullString
		if rows.Scan(&violationType, &contentHash, &domain, &reason) != nil {
			continue
		}
		s.emitToUser(username, "contract_violation_notice", map[string]any{
			"violation_type": violationType,
			"content_hash":   nullableString(contentHash),
			"domain":         nullableString(domain),
			"reason":         reason,
		})
	}
}

func intFromBool(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Server) getClient(sid string) (*ClientState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[sid]
	return c, ok
}

func (s *Server) listUserVouchers(username string) []map[string]any {
	rows, err := s.server.DB.Query(`SELECT voucher_id, issuer, owner, value, reason, issued_at, payload, issuer_signature, owner_signature, status, session_id, invalidated, last_updated
		FROM hps_vouchers WHERE owner = ? ORDER BY issued_at DESC`, username)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var voucherID, issuer, owner, reason, payloadText, issuerSignature, ownerSignature, status string
		var value int
		var issuedAt, lastUpdated float64
		var sessionID sql.NullString
		var invalidated int
		if err := rows.Scan(&voucherID, &issuer, &owner, &value, &reason, &issuedAt, &payloadText, &issuerSignature, &ownerSignature, &status, &sessionID, &invalidated, &lastUpdated); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"voucher_id":       voucherID,
			"issuer":           issuer,
			"is_local_issuer":  s.server.IsLocalIssuer(issuer),
			"owner":            owner,
			"value":            value,
			"reason":           reason,
			"issued_at":        issuedAt,
			"payload":          payloadText,
			"issuer_signature": issuerSignature,
			"owner_signature":  ownerSignature,
			"status":           status,
			"session_id":       nullableString(sessionID),
			"invalidated":      invalidated != 0,
			"last_updated":     lastUpdated,
		})
	}
	return out
}

func (s *Server) getUserReputation(username string) int {
	var reputation int
	err := s.server.DB.QueryRow("SELECT reputation FROM user_reputations WHERE username = ?", username).Scan(&reputation)
	if err != nil {
		return 100
	}
	return reputation
}

type OnlineUser struct {
	SID              string
	Username         string
	NodeType         string
	Address          string
	ClientIdentifier string
}

func (s *Server) ListOnlineUsers() []OnlineUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]OnlineUser, 0, len(s.clients))
	for sid, c := range s.clients {
		if c == nil || !c.Authenticated {
			continue
		}
		out = append(out, OnlineUser{
			SID:              sid,
			Username:         c.Username,
			NodeType:         c.NodeType,
			Address:          c.Address,
			ClientIdentifier: c.ClientIdentifier,
		})
	}
	return out
}

func (s *Server) BanUser(username string, duration int, reason string) bool {
	username = trim(username)
	if username == "" {
		return false
	}
	s.mu.Lock()
	clientIdentifier := ""
	for _, c := range s.clients {
		if c != nil && c.Authenticated && c.Username == username && trim(c.ClientIdentifier) != "" {
			clientIdentifier = c.ClientIdentifier
			break
		}
	}
	s.mu.Unlock()
	if clientIdentifier == "" {
		return false
	}
	s.banClientAndNotify(clientIdentifier, duration, reason)
	return true
}

func (s *Server) EmitReputationUpdate(username string, reputation int) {
	s.emitToUser(username, "reputation_update", map[string]any{"reputation": reputation})
}

func (s *Server) EmitPendingVoucherOffersForUser(username string) {
	s.emitPendingVoucherOffers(username)
}

func isValidDomain(domain string) bool {
	if len(domain) < 3 || len(domain) > 63 {
		return false
	}
	for _, c := range domain {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' {
			continue
		}
		return false
	}
	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}
	return true
}

func extractContentHashFromDDNS(ddns []byte) string {
	text := string(ddns)
	patterns := []string{
		`(?m)^#\s*CONTENT_HASH\s*[:=]\s*([a-fA-F0-9]{64})\s*$`,
		`(?m)^CONTENT_HASH\s*[:=]\s*([a-fA-F0-9]{64})\s*$`,
		`([a-fA-F0-9]{64})`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		m := re.FindStringSubmatch(text)
		if len(m) > 1 {
			return strings.ToLower(m[1])
		}
		if len(m) == 1 && len(m[0]) == 64 {
			return strings.ToLower(m[0])
		}
	}
	return ""
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, asString(item))
		}
		return out
	default:
		return []string{}
	}
}

func validateExchangeDkvhpsDisclosure(raw string, vouchers []map[string]any) (bool, string) {
	hashDisclosureKey := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, "Missing DKVHPS disclosure"
	}
	entries, ok := parseDkvhpsDisclosure(raw)
	if !ok {
		return false, "Invalid DKVHPS disclosure"
	}
	byVoucher := map[string]map[string]any{}
	lineageKeys := map[string]string{}
	for _, entry := range entries {
		voucherID := strings.TrimSpace(asString(entry["voucher_id"]))
		if voucherID != "" {
			byVoucher[voucherID] = entry
		}
	}
	for _, voucher := range vouchers {
		payload := castMap(voucher["payload"])
		voucherID := strings.TrimSpace(asString(payload["voucher_id"]))
		if voucherID == "" {
			return false, "Voucher disclosure mismatch"
		}
		entry := byVoucher[voucherID]
		if entry == nil {
			return false, "Missing DKVHPS disclosure for voucher " + voucherID
		}
		dkvhps := castMap(payload["dkvhps"])
		rootID := strings.TrimSpace(asString(payload["lineage_root_voucher_id"]))
		if rootID == "" {
			rootID = voucherID
		}
		if disclosedRoot := strings.TrimSpace(asString(entry["lineage_root_voucher_id"])); disclosedRoot != "" && disclosedRoot != rootID {
			return false, "Lineage root mismatch for voucher " + voucherID
		}
		voucherKey := asString(entry["voucher_dkvhps"])
		lineageKey := asString(entry["lineage_dkvhps"])
		if voucherKey != "" {
			if expected := asString(dkvhps["voucher_hash"]); expected != "" && hashDisclosureKey(voucherKey) != expected {
				return false, "Voucher DKVHPS hash mismatch for voucher " + voucherID
			}
		} else if asString(dkvhps["voucher_hash"]) == "" {
			return false, "Missing DKVHPS disclosure for voucher " + voucherID
		}
		if lineageKey != "" {
			if expected := asString(dkvhps["lineage_hash"]); expected != "" && hashDisclosureKey(lineageKey) != expected {
				return false, "Lineage DKVHPS hash mismatch for voucher " + voucherID
			}
		} else if asString(dkvhps["lineage_hash"]) == "" {
			return false, "Missing DKVHPS disclosure for voucher " + voucherID
		}
		if lineageKey != "" {
			if prior := lineageKeys[rootID]; prior != "" && prior != lineageKey {
				return false, "Inconsistent lineage DKVHPS for lineage " + rootID
			}
			lineageKeys[rootID] = lineageKey
		}
	}
	return true, ""
}

func parseDkvhpsDisclosure(raw string) ([]map[string]any, bool) {
	var entries []map[string]any
	if err := json.Unmarshal([]byte(raw), &entries); err == nil {
		return entries, true
	}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	indexed := map[string]map[string]any{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "## ") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(line, "## "))
		parts := strings.SplitN(body, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if !strings.HasPrefix(key, "ENTRY_") {
			continue
		}
		rest := strings.TrimPrefix(key, "ENTRY_")
		sep := strings.Index(rest, "_")
		if sep <= 0 {
			continue
		}
		entryID := rest[:sep]
		field := strings.ToLower(strings.TrimSpace(rest[sep+1:]))
		entry := indexed[entryID]
		if entry == nil {
			entry = map[string]any{}
			indexed[entryID] = entry
		}
		entry[field] = value
	}
	if len(indexed) == 0 {
		return nil, false
	}
	keys := make([]string, 0, len(indexed))
	for key := range indexed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries = make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, indexed[key])
	}
	return entries, true
}

func defaultSlice(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case []string:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, item)
		}
		return out
	default:
		return []any{}
	}
}

func toJSONString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func intToString(v int) string {
	return strconv.Itoa(v)
}

func asBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	default:
		return false
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.io.ServeHTTP(w, r)
}

func (s *Server) Close() error {
	if s == nil || s.io == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			// Ignore shutdown panics to avoid crashing on exit.
		}
	}()
	return s.io.Close()
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case json.Number:
		return t.String()
	case int:
		return strconv.Itoa(t)
	case int8:
		return strconv.FormatInt(int64(t), 10)
	case int16:
		return strconv.FormatInt(int64(t), 10)
	case int32:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint:
		return strconv.FormatUint(uint64(t), 10)
	case uint8:
		return strconv.FormatUint(uint64(t), 10)
	case uint16:
		return strconv.FormatUint(uint64(t), 10)
	case uint32:
		return strconv.FormatUint(uint64(t), 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float32:
		if math.Trunc(float64(t)) == float64(t) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case float64:
		if math.Trunc(t) == t {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func asFloat(v any) float64 {
	switch t := v.(type) {
	case json.Number:
		f, _ := t.Float64()
		return f
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int8:
		return float64(t)
	case int16:
		return float64(t)
	case int32:
		return float64(t)
	case int64:
		return float64(t)
	case uint:
		return float64(t)
	case uint8:
		return float64(t)
	case uint16:
		return float64(t)
	case uint32:
		return float64(t)
	case uint64:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	default:
		return 0
	}
}

func asInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		i, _ := strconv.Atoi(t)
		return i
	default:
		return 0
	}
}

func nowSec() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

func trim(v string) string {
	if v == "" {
		return ""
	}
	for len(v) > 0 && (v[0] == ' ' || v[0] == '\n' || v[0] == '\t' || v[0] == '\r') {
		v = v[1:]
	}
	for len(v) > 0 {
		last := v[len(v)-1]
		if last != ' ' && last != '\n' && last != '\t' && last != '\r' {
			break
		}
		v = v[:len(v)-1]
	}
	return v
}

func fileExists(path string) bool {
	path = trim(path)
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func nullableString(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}

func nullableInt(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}

func castMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return map[string]any{}
}

func castSliceMap(v any) []map[string]any {
	if v == nil {
		return []map[string]any{}
	}
	switch t := v.(type) {
	case []map[string]any:
		return t
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, item := range t {
			out = append(out, castMap(item))
		}
		return out
	default:
		return []map[string]any{}
	}
}

func parseJSONStringSlice(raw string) []string {
	raw = trim(raw)
	if raw == "" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []string{}
	}
	return out
}

func parseJSONMap(raw string) map[string]any {
	raw = trim(raw)
	if raw == "" {
		return map[string]any{}
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]any{}
	}
	return out
}

func parseJSONArray(raw string) []any {
	raw = trim(raw)
	if raw == "" {
		return []any{}
	}
	var out []any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []any{}
	}
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string{}, values...)
	if len(out) < 2 {
		return out
	}
	for i := 0; i < len(out)-1; i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func nullIfEmpty(value string) any {
	if trim(value) == "" {
		return nil
	}
	return value
}

func defaultStr(value, fallback string) string {
	if trim(value) == "" {
		return fallback
	}
	return value
}

func nullableFloat(v sql.NullFloat64) any {
	if !v.Valid {
		return nil
	}
	return v.Float64
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, v := range a {
		count[v]++
	}
	for _, v := range b {
		if count[v] == 0 {
			return false
		}
		count[v]--
	}
	for _, v := range count {
		if v != 0 {
			return false
		}
	}
	return true
}

func countPendingForUser(db *sql.DB, username string) int {
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM pending_transfers WHERE target_user = ? AND status = ?`, username, "pending").Scan(&count)
	return count
}

func parseTransferTitle(title string) (string, string, string) {
	if trim(title) == "" {
		return "", "", ""
	}
	re := regexp.MustCompile(`\(HPS!transfer\)\{type=([^,}]+),\s*to=([^,}]+)(?:,\s*app=([^}]+))?\}`)
	m := re.FindStringSubmatch(title)
	if len(m) == 0 {
		return "", "", ""
	}
	transferType := strings.ToLower(strings.TrimSpace(m[1]))
	targetUser := strings.TrimSpace(m[2])
	appName := ""
	if len(m) > 3 {
		appName = strings.TrimSpace(m[3])
	}
	return transferType, targetUser, appName
}

func extractAppName(title string) string {
	re := regexp.MustCompile(`\(HPS!api\)\{app\}:\{"([^"]+)"\}`)
	m := re.FindStringSubmatch(title)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func processAppUpdate(db *sql.DB, title, username, contentHash string) (bool, string) {
	appName := extractAppName(title)
	if appName == "" {
		return false, "Invalid app name format"
	}
	var existingOwner, oldHash string
	err := db.QueryRow(`SELECT username, content_hash FROM api_apps WHERE app_name = ?`, appName).Scan(&existingOwner, &oldHash)
	if err == nil {
		if existingOwner != username {
			return false, "API app '" + appName + "' is owned by " + existingOwner + ". Only the owner can update."
		}
		if oldHash != contentHash {
			_, _ = db.Exec(`UPDATE dns_records SET content_hash = ? WHERE content_hash = ?`, contentHash, oldHash)
			_, _ = db.Exec(`INSERT OR REPLACE INTO content_redirects (old_hash, new_hash, username, redirect_type, timestamp)
				VALUES (?, ?, ?, ?, ?)`, oldHash, contentHash, username, "app_update", nowSec())
			_, _ = db.Exec(`UPDATE api_apps SET content_hash = ?, last_updated = ? WHERE app_name = ?`,
				contentHash, nowSec(), appName)
			versionNumber := 1
			_ = db.QueryRow(`SELECT COALESCE(MAX(version_number), 0) + 1 FROM api_app_versions WHERE app_name = ?`, appName).Scan(&versionNumber)
			_, _ = db.Exec(`INSERT INTO api_app_versions (version_id, app_name, content_hash, username, timestamp, version_number)
				VALUES (?, ?, ?, ?, ?, ?)`, core.NewUUID(), appName, contentHash, username, nowSec(), versionNumber)
			return true, "App '" + appName + "' updated"
		}
		return true, "App already up to date"
	}
	_, _ = db.Exec(`INSERT INTO api_apps (app_name, username, content_hash, timestamp, last_updated)
		VALUES (?, ?, ?, ?, ?)`, appName, username, contentHash, nowSec(), nowSec())
	_, _ = db.Exec(`INSERT INTO api_app_versions (version_id, app_name, content_hash, username, timestamp, version_number)
		VALUES (?, ?, ?, ?, ?, ?)`, core.NewUUID(), appName, contentHash, username, nowSec(), 1)
	return true, "New app '" + appName + "' registered"
}

func parseDNSChangeManifest(content []byte) (string, string, string) {
	contentStr := string(content)
	if !strings.HasPrefix(contentStr, "# HSYST P2P SERVICE") {
		return "", "", "Missing HSYST header in DNS change file"
	}
	if !strings.Contains(contentStr, "### MODIFY:") || !strings.Contains(contentStr, "# change_dns_owner = true") {
		return "", "", "Invalid DNS change file format"
	}
	lines := strings.Split(contentStr, "\n")
	domain := ""
	newOwner := ""
	inDNS := false
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "### DNS:" {
			inDNS = true
			continue
		}
		if line == "### :END DNS" {
			inDNS = false
			continue
		}
		if inDNS && strings.HasPrefix(line, "# NEW_DNAME:") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				domain = strings.TrimSpace(parts[1])
			}
		}
		if strings.HasPrefix(line, "# NEW_DOWNER:") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				newOwner = strings.TrimSpace(parts[1])
			}
		}
	}
	if domain == "" || newOwner == "" {
		return "", "", "Missing domain or new owner in DNS change file"
	}
	return domain, newOwner, ""
}

func hasPendingTransferForUser(db *sql.DB, username, transferType, contentHash, domain, appName string) bool {
	return getPendingTransferIDForUser(db, username, transferType, contentHash, domain, appName) != ""
}

func getPendingTransferIDForUser(db *sql.DB, username, transferType, contentHash, domain, appName string) string {
	query := `SELECT 1 FROM pending_transfers WHERE target_user = ? AND status = ?`
	args := []any{username, "pending"}
	if trim(transferType) != "" {
		query += ` AND transfer_type = ?`
		args = append(args, transferType)
	}
	if trim(contentHash) != "" {
		query += ` AND content_hash = ?`
		args = append(args, contentHash)
	}
	if trim(domain) != "" {
		query += ` AND domain = ?`
		args = append(args, domain)
	}
	if trim(appName) != "" {
		query += ` AND app_name = ?`
		args = append(args, appName)
	}
	query += ` LIMIT 1`
	query = strings.Replace(query, "SELECT 1", "SELECT transfer_id", 1)
	var transferID string
	_ = db.QueryRow(query, args...).Scan(&transferID)
	return transferID
}

func createPendingTransfer(db *sql.DB, transferType, targetUser, originalOwner, contentHash, domain, appName, contractID string) string {
	return createPendingTransferWithRequest(db, transferType, targetUser, originalOwner, contentHash, domain, appName, contractID, "", nil)
}

func createPendingTransferWithRequest(db *sql.DB, transferType, targetUser, originalOwner, contentHash, domain, appName, contractID, requesterUser string, requestPayload map[string]any) string {
	transferID := core.NewUUID()
	payloadText := ""
	if requestPayload != nil {
		payloadText = toJSONString(requestPayload)
	}
	_, _ = db.Exec(`INSERT INTO pending_transfers
		(transfer_id, transfer_type, target_user, original_owner, custody_user, content_hash, domain, app_name, contract_id, status, timestamp, requester_user, request_payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		transferID, transferType, targetUser, originalOwner, core.CustodyUsername,
		nullIfEmpty(contentHash), nullIfEmpty(domain), nullIfEmpty(appName), contractID, "pending", nowSec(),
		nullIfEmpty(requesterUser), nullIfEmpty(payloadText))
	return transferID
}

func listPendingTransfersForUser(db *sql.DB, username string) []map[string]any {
	if trim(username) == "" {
		return []map[string]any{}
	}
	rows, err := db.Query(`SELECT transfer_id, transfer_type, target_user, original_owner, custody_user, content_hash, domain, app_name, contract_id, status, timestamp, hps_amount, hps_total_value, hps_voucher_ids, hps_session_id
		FROM pending_transfers WHERE target_user = ? AND status = ? ORDER BY timestamp DESC`, username, "pending")
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	transfers := make([]map[string]any, 0)
	for rows.Next() {
		var transferID, transferType, targetUser, originalOwner, custodyUser, contractID, status string
		var contentHash, domain, appName, voucherIDsText, sessionID sql.NullString
		var timestamp float64
		var hpsAmount, hpsTotal sql.NullInt64
		if rows.Scan(&transferID, &transferType, &targetUser, &originalOwner, &custodyUser, &contentHash, &domain, &appName, &contractID, &status, &timestamp, &hpsAmount, &hpsTotal, &voucherIDsText, &sessionID) != nil {
			continue
		}
		transfer := map[string]any{
			"transfer_id":     transferID,
			"transfer_type":   transferType,
			"target_user":     targetUser,
			"original_owner":  originalOwner,
			"custody_user":    custodyUser,
			"content_hash":    nullableString(contentHash),
			"domain":          nullableString(domain),
			"app_name":        nullableString(appName),
			"contract_id":     contractID,
			"status":          status,
			"timestamp":       timestamp,
			"hps_amount":      nullableInt(hpsAmount),
			"hps_total_value": nullableInt(hpsTotal),
			"hps_voucher_ids": parseJSONStringSlice(voucherIDsText.String),
			"hps_session_id":  nullableString(sessionID),
		}
		if contentHash.Valid && contentHash.String != "" {
			var title, description, mimeType string
			if err := db.QueryRow(`SELECT title, description, mime_type FROM content WHERE content_hash = ?`, contentHash.String).Scan(&title, &description, &mimeType); err == nil {
				transfer["title"] = title
				transfer["description"] = description
				if mimeType == "" {
					mimeType = "application/octet-stream"
				}
				transfer["mime_type"] = mimeType
			}
		}
		transfers = append(transfers, transfer)
	}
	return transfers
}
