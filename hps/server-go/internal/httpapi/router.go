package httpapi

import (
	"context"
	"net/http"

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

	r.Post("/upload", HandleUpload(server))
	r.Get("/content/{content_hash}", HandleContent(server))
	r.Get("/dns/{domain}", HandleDNS(server))
	r.Get("/ddns/{domain}", HandleDDNS(server))
	r.Get("/voucher/{voucher_id}", HandleVoucher(server))
	r.Get("/health", HandleHealth(server))
	r.Get("/server_info", HandleServerInfo(server))
	r.Get("/economy_report", HandleEconomyReport(server))
	r.Post("/exchange/validate", HandleExchangeValidate(server))
	r.Post("/exchange/confirm", HandleExchangeConfirm(server))

	r.Group(func(sr chi.Router) {
		sr.Use(RequireInterServerAuth(server))
		sr.Post("/exchange/relay", HandleExchangeRelay(server))
		sr.Post("/exchange/complete", HandleExchangeComplete(server))
		sr.Post("/exchange/rollback", HandleExchangeRollback(server))
		sr.Get("/contract/{contract_id}", HandleContract(server))
		sr.Get("/sync/content", HandleSyncContent(server))
		sr.Get("/sync/dns", HandleSyncDNS(server))
		sr.Get("/sync/users", HandleSyncUsers(server))
		sr.Get("/sync/contracts", HandleSyncContracts(server))
		sr.Post("/voucher/audit", HandleVoucherAudit(server))
	})

	return r
}
