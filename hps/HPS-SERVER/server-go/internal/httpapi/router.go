package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"hpsserver/internal/core"
)

func NewRouter(server *core.Server) http.Handler {
	r := chi.NewRouter()

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := context.WithValue(req.Context(), "server", server)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method == "POST" {
				if ct := req.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
					writeJSON(w, http.StatusUnsupportedMediaType, jsonResponse{"success": false, "error": "Content-Type must be application/json"})
					return
				}
			}
			next.ServeHTTP(w, req)
		})
	})

	r.Post("/upload", HandleUpload(server))
	r.Get("/content/{content_hash}", HandleContent(server))
	r.Get("/dns/{domain}", HandleDNS(server))
	r.Get("/ddns/{domain}", HandleDDNS(server))
	r.Get("/voucher/{voucher_id}", HandleVoucher(server))
	r.Get("/health", HandleHealth(server))
	r.Get("/server_info", HandleServerInfo(server))
	r.Get("/node/status", HandleNodeStatus(server))
	r.Post("/server/audit", HandleAuditContract(server))
	r.Get("/server/integrity", HandleServerIntegrity(server))
	r.Post("/server/challenge", HandleChallengeResponse(server))
	r.Get("/server/verify", HandleVerifyBehavior(server))
	r.Get("/server/audit", HandleFullAudit(server))
	r.Get("/server/audit/anomalies", HandleAuditAnomalies(server))
	r.Get("/server/audit/chain", HandleAuditChain(server))
	r.Get("/server/audit/miners", HandleMinerAudit(server))
	r.Get("/server/audit/fees", HandleFeeAudit(server))
	r.Get("/economy_report", HandleEconomyReport(server))
	r.Get("/vouchers/user", HandleUserVouchers(server))
	r.Get("/phps/market", HandlePhpsMarket(server))
	r.Post("/phps/title/purchase", HandlePhpsTitlePurchase(server))
	r.Post("/phps/title/redeem", HandlePhpsTitleRedeem(server))
	r.Post("/exchange/validate", HandleExchangeValidate(server))
	r.Post("/exchange/confirm", HandleExchangeConfirm(server))

	r.Post("/fee/quotes", HandleFeeQuotes(server))
	r.Get("/fee/market", HandleFeeMarket(server))
	r.Post("/voucher/supply-chain", HandleVoucherSupplyChain(server))
	r.Get("/voucher/supply-chain-tip", HandleSupplyChainTip(server))
	r.Get("/content/{hash}/receipt", HandleContentReceipt(server))
	r.Get("/supply/audit", HandleSupplyAudit(server))

	// Handshake endpoints (public - for initial authentication)
	r.Post("/handshake/init", HandleHandshakeInit(server))
	r.Post("/handshake/complete", HandleHandshakeComplete(server))

	// Voucher cross-server endpoints
	r.Post("/voucher/confirm", HandleVoucherConfirm(server))
	r.Get("/voucher/{voucher_id}/receipt", HandleVoucherReceipt(server))

	// Content dual-signature endpoints (anti-censura)
	r.Post("/content/register", HandleContentRegister(server))
	r.Post("/content/replicate", HandleContentReplicate(server))
	r.Get("/content/{hash}/registration", HandleContentRegistration(server))

	// Voucher lock endpoints (anti double-spend)
	r.Post("/voucher/lock", HandleVoucherLock(server))
	r.Post("/voucher/lock/confirm", HandleVoucherLockConfirm(server))
	r.Post("/voucher/spent", HandleVoucherSpent(server))
	r.Get("/voucher/{voucher_id}/lock-status", HandleVoucherLockStatus(server))

	r.Group(func(sr chi.Router) {
		sr.Use(RequireInterServerAuth(server))
		// Cross-server validation endpoints
		sr.Post("/transfer/validate", HandleTransferValidate(server))
		sr.Post("/transfer/notify", HandleTransferNotify(server))
		sr.Post("/exchange/relay", HandleExchangeRelay(server))
		sr.Post("/exchange/complete", HandleExchangeComplete(server))
		sr.Post("/exchange/rollback", HandleExchangeRollback(server))
		sr.Post("/exchange/incoming", HandleExchangeIncoming(server))
		sr.Get("/contract/{contract_id}", HandleContract(server))
		sr.Get("/sync/content", HandleSyncContent(server))
		sr.Get("/sync/dns", HandleSyncDNS(server))
		sr.Get("/sync/users", HandleSyncUsers(server))
		sr.Get("/sync/contracts", HandleSyncContracts(server))
		sr.Post("/voucher/audit", HandleVoucherAudit(server))
	})

	return r
}
