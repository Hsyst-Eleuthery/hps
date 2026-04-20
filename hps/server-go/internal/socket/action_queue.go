package socket

import (
	"sync"
	"sync/atomic"

	socketio "hpsserver/internal/socketio"
)

type actionQueueTicket struct {
	id        uint64
	sid       string
	action    string
	requestID string
	ready     chan struct{}
	once      sync.Once
}

func (t *actionQueueTicket) signalReady() {
	t.once.Do(func() {
		close(t.ready)
	})
}

func (s *Server) enqueueAction(action string, conn socketio.Conn, requestID string) (*actionQueueTicket, int) {
	if action == "" || conn == nil {
		return nil, 0
	}

	ticket := &actionQueueTicket{
		id:        atomic.AddUint64(&s.actionQueueSeq, 1),
		sid:       conn.ID(),
		action:    action,
		requestID: requestID,
		ready:     make(chan struct{}),
	}

	s.actionQueueMu.Lock()
	queue := s.actionQueues[action]
	queue = append(queue, ticket)
	s.actionQueues[action] = queue
	position := len(queue)
	if position == 1 {
		ticket.signalReady()
	}
	s.actionQueueMu.Unlock()

	s.emitQueuePositionUpdates(action)
	return ticket, position
}

func (s *Server) releaseAction(ticket *actionQueueTicket) {
	if ticket == nil || ticket.action == "" {
		return
	}

	s.actionQueueMu.Lock()
	queue := s.actionQueues[ticket.action]
	if len(queue) == 0 {
		s.actionQueueMu.Unlock()
		return
	}

	index := -1
	for i := range queue {
		if queue[i] == ticket {
			index = i
			break
		}
	}
	if index < 0 {
		s.actionQueueMu.Unlock()
		return
	}

	queue = append(queue[:index], queue[index+1:]...)
	if len(queue) == 0 {
		delete(s.actionQueues, ticket.action)
	} else {
		s.actionQueues[ticket.action] = queue
		queue[0].signalReady()
	}
	s.actionQueueMu.Unlock()

	s.emitQueuePositionUpdates(ticket.action)
}

func (s *Server) runQueuedAction(conn socketio.Conn, action string, requestID string, fn func()) {
	if conn == nil || fn == nil || action == "" {
		return
	}

	ticket, position := s.enqueueAction(action, conn, requestID)
	if ticket == nil {
		fn()
		return
	}

	conn.Emit("action_queue_update", map[string]any{
		"action":     action,
		"request_id": requestID,
		"status":     "queued",
		"position":   position,
		"timestamp":  nowSec(),
	})

	<-ticket.ready

	conn.Emit("action_queue_update", map[string]any{
		"action":     action,
		"request_id": requestID,
		"status":     "processing",
		"position":   0,
		"timestamp":  nowSec(),
	})

	defer func() {
		s.releaseAction(ticket)
		conn.Emit("action_queue_update", map[string]any{
			"action":     action,
			"request_id": requestID,
			"status":     "done",
			"position":   0,
			"timestamp":  nowSec(),
		})
	}()

	fn()
}

func (s *Server) emitQueuePositionUpdates(action string) {
	if action == "" {
		return
	}

	s.actionQueueMu.Lock()
	queue := append([]*actionQueueTicket(nil), s.actionQueues[action]...)
	s.actionQueueMu.Unlock()

	if len(queue) == 0 {
		return
	}

	for i, ticket := range queue {
		if ticket == nil || ticket.sid == "" {
			continue
		}
		s.mu.Lock()
		conn := s.conns[ticket.sid]
		s.mu.Unlock()
		if conn == nil {
			continue
		}

		conn.Emit("action_queue_update", map[string]any{
			"action":     action,
			"request_id": ticket.requestID,
			"status":     "queued",
			"position":   i + 1,
			"timestamp":  nowSec(),
		})
	}
}

func (s *Server) dropQueuedActionsBySid(sid string) {
	if sid == "" {
		return
	}

	actionsToRefresh := make([]string, 0)
	s.actionQueueMu.Lock()
	for action, queue := range s.actionQueues {
		if len(queue) == 0 {
			continue
		}

		removedHead := false
		filtered := make([]*actionQueueTicket, 0, len(queue))
		for i, ticket := range queue {
			if ticket != nil && ticket.sid == sid {
				if i == 0 {
					removedHead = true
				}
				continue
			}
			filtered = append(filtered, ticket)
		}

		if len(filtered) == len(queue) {
			continue
		}

		if len(filtered) == 0 {
			delete(s.actionQueues, action)
		} else {
			s.actionQueues[action] = filtered
			if removedHead {
				filtered[0].signalReady()
			}
		}
		actionsToRefresh = append(actionsToRefresh, action)
	}
	s.actionQueueMu.Unlock()

	for _, action := range actionsToRefresh {
		s.emitQueuePositionUpdates(action)
	}
}

func (s *Server) handlePublishContentQueued(conn socketio.Conn, data map[string]any) {
	requestID := asString(data["content_hash"])
	s.runQueuedAction(conn, "publish_content", requestID, func() {
		s.handlePublishContent(conn, data)
	})
}

func (s *Server) handleRegisterDNSQueued(conn socketio.Conn, data map[string]any) {
	requestID := asString(data["domain"])
	s.runQueuedAction(conn, "register_dns", requestID, func() {
		s.handleRegisterDNS(conn, data)
	})
}

func (s *Server) handleTransferHPSQueued(conn socketio.Conn, data map[string]any) {
	requestID := asString(data["transfer_id"])
	if requestID == "" {
		requestID = asString(data["target_user"])
	}
	s.runQueuedAction(conn, "transfer_hps", requestID, func() {
		s.handleTransferHPS(conn, data)
	})
}

func (s *Server) handleAcceptUsageContractQueued(conn socketio.Conn, data map[string]any) {
	requestID := asString(data["username"])
	s.runQueuedAction(conn, "accept_usage_contract", requestID, func() {
		s.handleAcceptUsageContract(conn, data)
	})
}

func (s *Server) handleAuthenticateQueued(conn socketio.Conn, data map[string]any) {
	requestID := asString(data["username"])
	if requestID == "" {
		requestID = asString(data["client_identifier"])
	}
	s.runQueuedAction(conn, "authenticate", requestID, func() {
		s.handleAuthenticate(conn, data)
	})
}
