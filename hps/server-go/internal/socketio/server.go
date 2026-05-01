package socketio

import (
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	etypes "github.com/zishang520/engine.io/types"
	zsocket "github.com/zishang520/socket.io/socket"
)

type Conn interface {
	ID() string
	Emit(event string, payload any)
}

type connAdapter struct {
	socket *zsocket.Socket
}

func (c *connAdapter) ID() string {
	if c == nil || c.socket == nil {
		return ""
	}
	return string(c.socket.Id())
}

func (c *connAdapter) Emit(event string, payload any) {
	if c == nil || c.socket == nil {
		return
	}
	_ = c.socket.Emit(event, payload)
}

type namespaceHandlers struct {
	attached     bool
	onConnect    func(Conn) error
	onDisconnect func(Conn, string)
	events       map[string]func(Conn, map[string]any)
}

type Server struct {
	raw      *zsocket.Server
	mu       sync.RWMutex
	handlers map[string]*namespaceHandlers
}

func NewServer(_ any) *Server {
	opts := zsocket.DefaultServerOptions()
	opts.SetAllowEIO3(true)
	opts.SetTransports(etypes.NewSet("polling", "websocket"))
	opts.SetAllowUpgrades(true)
	allowedOrigins := parseAllowedOrigins(os.Getenv("HPS_SOCKETIO_ALLOWED_ORIGINS"))
	cors := &etypes.Cors{
		Origin:      "*",
		Credentials: false,
	}
	if len(allowedOrigins) > 0 {
		cors.Origin = allowedOrigins
		cors.Credentials = true
	}
	opts.SetCors(cors)
	opts.SetPingTimeout(180 * time.Second)
	opts.SetPingInterval(25 * time.Second)
	opts.SetMaxHttpBufferSize(200 * 1024 * 1024)

	return &Server{
		raw:      zsocket.NewServer(nil, opts),
		handlers: map[string]*namespaceHandlers{},
	}
}

func (s *Server) ensureNamespace(ns string) *namespaceHandlers {
	if ns == "" {
		ns = "/"
	}
	h, ok := s.handlers[ns]
	if !ok {
		h = &namespaceHandlers{events: map[string]func(Conn, map[string]any){}}
		s.handlers[ns] = h
	}
	if !h.attached {
		nsp := s.raw.Of(ns, nil)
		_ = nsp.On("connection", func(args ...any) {
			if len(args) == 0 {
				return
			}
			socket, ok := args[0].(*zsocket.Socket)
			if !ok || socket == nil {
				return
			}
			conn := &connAdapter{socket: socket}

			s.mu.RLock()
			current := s.handlers[ns]
			onConnect := current.onConnect
			onDisconnect := current.onDisconnect
			eventHandlers := make(map[string]func(Conn, map[string]any), len(current.events))
			for ev, fn := range current.events {
				eventHandlers[ev] = fn
			}
			s.mu.RUnlock()

			if onConnect != nil {
				if err := onConnect(conn); err != nil {
					_ = socket.Emit("connect_error", map[string]any{"error": err.Error()})
					socket.Disconnect(true)
					return
				}
			}

			if onDisconnect != nil {
				_ = socket.On("disconnect", func(dargs ...any) {
					onDisconnect(conn, firstStringArg(dargs))
				})
			}

			for eventName, fn := range eventHandlers {
				ev := eventName
				handler := fn
				_ = socket.On(ev, func(dargs ...any) {
					handler(conn, firstMapArg(dargs))
				})
			}
		})
		h.attached = true
	}
	return h
}

func (s *Server) OnConnect(namespace string, fn func(Conn) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.ensureNamespace(namespace)
	h.onConnect = fn
}

func (s *Server) OnDisconnect(namespace string, fn func(Conn, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.ensureNamespace(namespace)
	h.onDisconnect = fn
}

func (s *Server) OnEvent(namespace, event string, fn func(Conn, map[string]any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.ensureNamespace(namespace)
	h.events[event] = fn
}

func (s *Server) BroadcastToRoom(namespace, room, event string, payload any) {
	if namespace == "" {
		namespace = "/"
	}
	if room == "" || event == "" {
		return
	}
	_ = s.raw.Of(namespace, nil).To(zsocket.Room(room)).Emit(event, payload)
}

func (s *Server) Close() error {
	if s == nil || s.raw == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			// Ignore close panics from underlying socket.io server.
		}
	}()
	done := make(chan struct{}, 1)
	s.raw.Close(func() {
		done <- struct{}{}
	})
	select {
	case <-done:
		s.raw = nil
		return nil
	case <-time.After(3 * time.Second):
		s.raw = nil
		return nil
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("HPS_SOCKETIO_DEBUG") != "" {
		log.Printf("[socketio] %s %s from %s upgrade=%q ua=%q",
			r.Method,
			r.URL.String(),
			r.RemoteAddr,
			r.Header.Get("Upgrade"),
			r.UserAgent(),
		)
	}
	s.raw.ServeHandler(nil).ServeHTTP(w, r)
}

func firstMapArg(args []any) map[string]any {
	for _, arg := range args {
		if m, ok := arg.(map[string]any); ok && m != nil {
			return m
		}
	}
	return map[string]any{}
}

func firstStringArg(args []any) string {
	if len(args) == 0 || args[0] == nil {
		return ""
	}
	if s, ok := args[0].(string); ok {
		return s
	}
	return ""
}

func parseAllowedOrigins(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		v := strings.TrimSpace(part)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}
