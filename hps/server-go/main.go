package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"hpsserver/internal/core"
	"hpsserver/internal/httpapi"
	"hpsserver/internal/socket"
)

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (w *loggingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	if w.status == 0 {
		w.status = http.StatusSwitchingProtocols
	}
	return hijacker.Hijack()
}

func (w *loggingResponseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

func logHTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("http request method=%s path=%q remote=%s status=%d bytes=%d duration_ms=%d ua=%q",
			r.Method, r.URL.RequestURI(), r.RemoteAddr, status, recorder.bytes, time.Since(start).Milliseconds(), r.UserAgent())
	})
}

func main() {
	var (
		dbPath          = flag.String("db", "hps_server.db", "Database file path")
		filesDir        = flag.String("files", "hps_files", "Files directory")
		host            = flag.String("host", "0.0.0.0", "Host to bind to")
		advertiseHost   = flag.String("advertise-host", "", "Host advertised to other HPS servers; defaults to auto-detected host")
		port            = flag.Int("port", 1080, "Port to bind to")
		sslCert         = flag.String("ssl-cert", "", "SSL certificate file")
		sslKey          = flag.String("ssl-key", "", "SSL private key file")
		ownerEnabled    = flag.Bool("owner-enabled", false, "Enable owner account revenue split")
		ownerUsername   = flag.String("owner-username", core.OwnerUsernameDefault, "Owner username")
		exchangeFeeRate = flag.Float64("exchange-fee-rate", 0.02, "Exchange fee rate")
		exchangeFeeMin  = flag.Int("exchange-fee-min", 1, "Minimum exchange fee")
		masterPass      = flag.String("master-pass", "", "Server master passphrase for storage-key encryption")
	)
	flag.Parse()

	serverMasterPass := strings.TrimSpace(*masterPass)
	if serverMasterPass == "" {
		serverMasterPass = strings.TrimSpace(os.Getenv("HPS_SERVER_MASTER_PASSWORD"))
	}
	if serverMasterPass == "" {
		fmt.Print("Server master passphrase: ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		serverMasterPass = strings.TrimSpace(line)
	}
	if serverMasterPass == "" {
		log.Fatalf("server master passphrase is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server, err := core.NewServer(core.Config{
		DBPath:           *dbPath,
		FilesDir:         *filesDir,
		Host:             *host,
		AdvertiseHost:    *advertiseHost,
		Port:             *port,
		SSLCert:          *sslCert,
		SSLKey:           *sslKey,
		OwnerEnabled:     *ownerEnabled,
		OwnerUsername:    *ownerUsername,
		ExchangeFeeRate:  *exchangeFeeRate,
		ExchangeFeeMin:   *exchangeFeeMin,
		MasterPassphrase: serverMasterPass,
	})
	if err != nil {
		log.Fatalf("server init failed: %v", err)
	}
	logPath := server.LogPath()
	if err := os.MkdirAll(server.FilesDir, 0o755); err != nil {
		log.Fatalf("server log dir init failed: %v", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatalf("server log init failed: %v", err)
	}
	defer func() {
		if err := logFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "server log close warning: %v\n", err)
		}
	}()
	log.SetOutput(io.MultiWriter(os.Stderr, logFile))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	log.Printf("server log enabled path=%s server_id=%s address=%s db=%s files=%s owner_enabled=%t",
		logPath, server.ServerID, server.Address, *dbPath, server.FilesDir, *ownerEnabled)
	defer func() {
		if err := server.Close(); err != nil {
			log.Printf("server close warning: %v", err)
		}
	}()
	server.StartBackgroundJobs(ctx)

	httpHandler := httpapi.NewRouter(server)
	socketServer, err := socket.NewServer(server)
	if err != nil {
		log.Fatalf("socket init failed: %v", err)
	}
	startAdminConsole(ctx, stop, server, socketServer)

	mux := http.NewServeMux()
	mux.Handle("/socket.io/", logHTTPHandler(socketServer))
	mux.Handle("/socket.io", logHTTPHandler(socketServer))
	mux.Handle("/", logHTTPHandler(httpHandler))

	h := &http.Server{
		Addr:              server.ListenAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		// Socket.IO long-polling can keep requests open for longer than 60s.
		// Keep these timeouts disabled to avoid transport disconnects.
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = socketServer.Close()
		_ = h.Shutdown(shutdownCtx)
	}()

	log.Printf("HPS Server listening on %s", h.Addr)
	if *sslCert != "" && *sslKey != "" {
		if err := h.ListenAndServeTLS(*sslCert, *sslKey); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen tls failed: %v", err)
		}
		return
	}
	if err := h.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen failed: %v", err)
	}
}
