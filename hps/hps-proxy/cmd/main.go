package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg := ReadConfig()
	identity, err := EnsureProxyCryptoIdentity(cfg.User, cfg.Pass, cfg.CryptoDir)
	if err != nil {
		log.Fatalf("falha ao preparar criptografia local: %v", err)
	}
	log.Printf("[crypto] perfil pronto em %s (fingerprint=%s)", cfg.CryptoDir, identity.Fingerprint)
	storageKey, err := EnsureProxyStorageKey(cfg.User, cfg.Pass, cfg.CryptoDir)
	if err != nil {
		log.Fatalf("falha ao preparar chave de armazenamento local: %v", err)
	}
	log.Printf("[crypto] chave de armazenamento local pronta")

	log.Printf("[auth] iniciando bootstrap PoW para usuario=%s", cfg.User)
	RunBootstrapPoW(cfg.User, cfg.Pass)
	log.Printf("[auth] bootstrap concluido")

	store, err := NewLocalStore(cfg.DataDir, storageKey)
	if err != nil {
		log.Fatalf("falha ao preparar armazenamento local: %v", err)
	}
	log.Printf("[store] base local pronta em %s", store.DataDir())

	api := NewAPIClient(cfg)
	syncCtx, syncCancel := context.WithTimeout(context.Background(), 30*time.Second)
	snap, syncErr := api.SyncSnapshot(syncCtx, 300)
	syncCancel()
	if syncErr != nil {
		log.Printf("[sync] falha ao sincronizar bootstrap: %v", syncErr)
	} else {
		store.ApplySyncSnapshot(snap)
		contracts := make([]ContractRecord, 0, len(snap.Contracts))
		for _, row := range snap.Contracts {
			contracts = append(contracts, ContractRecord{
				ContractID:  strings.TrimSpace(asString(row["contract_id"])),
				ActionType:  strings.TrimSpace(asString(row["action_type"])),
				ContentHash: strings.TrimSpace(asString(row["content_hash"])),
				Domain:      strings.ToLower(strings.TrimSpace(asString(row["domain"]))),
				Username:    strings.TrimSpace(asString(row["username"])),
				Verified:    asBool(row["verified"]),
				Timestamp:   toRFC3339(asString(row["timestamp"])),
			})
		}
		store.UpsertContracts(contracts)
		log.Printf("[sync] bootstrap ok: content=%d dns=%d contracts=%d users=%d", len(snap.Content), len(snap.DNS), len(snap.Contracts), len(snap.Users))
	}

	handler := NewProxyHandler(api, store, cfg.Server)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Printf("[proxy] encerrando")
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()

	log.Printf("[proxy] em execucao: http://%s", cfg.Listen)
	log.Printf("[proxy] configure o navegador para usar proxy HTTP em %s", cfg.Listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("falha no proxy: %v", err)
	}
}
