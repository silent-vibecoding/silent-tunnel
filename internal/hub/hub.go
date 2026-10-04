package hub

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"silenttunnel/internal/config"
	"silenttunnel/internal/crypto"
	"silenttunnel/internal/proto"
	"silenttunnel/internal/relay"
	"silenttunnel/internal/state"
)

const maxSessions = 16

// Hub is the Iran-side server. Nodes dial its TLS port; users connect to
// the forwarded ports and are relayed through the tunnel.
type Hub struct {
	// StatusPath overrides where live statistics are written (tests and
	// containers); empty means the platform default.
	StatusPath string

	cfg      *config.Hub
	secret   []byte
	tlsConf  *tls.Config
	st       *state.State
	mu       sync.Mutex
	sessions []*session
	rr       int
}

type session struct {
	sess  *smux.Session
	addr  string
	since time.Time
}

// New prepares the hub: loads the certificate and builds the TLS config.
func New(cfg *config.Hub) (*Hub, error) {
	secret, err := cfg.Secret()
	if err != nil {
		return nil, err
	}
	cert, err := crypto.LoadCert(cfg.Cert, cfg.CertKey)
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	return &Hub{
		cfg:    cfg,
		secret: secret,
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		st: state.New("hub"),
	}, nil
}

// Run blocks serving until ctx is cancelled or a fatal listen error occurs.
func (h *Hub) Run(ctx context.Context) error {
	stop := make(chan struct{})
	defer close(stop)
	statusPath := h.StatusPath
	if statusPath == "" {
		statusPath = config.StatusPath()
	}
	go h.st.WriteLoop(statusPath, 5*time.Second, stop)

	// User-facing forwarded ports.
	for _, p := range h.listenPorts() {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			return fmt.Errorf("listen forward port %d: %w (is it free / root?)", p, err)
		}
		go h.serveForward(ctx, ln, p)
		log.Printf("forwarding :%d -> node:%d", p, h.cfg.RemoteFor(p))
	}

	tlsLn, err := net.Listen("tcp", fmt.Sprintf(":%d", h.cfg.TLSPort))
	if err != nil {
		return fmt.Errorf("listen tls port %d: %w (is it free / root?)", h.cfg.TLSPort, err)
	}
	ln := tls.NewListener(tlsLn, h.tlsConf)
	log.Printf("hub listening for nodes on :%d (sni=%s)", h.cfg.TLSPort, h.cfg.SNI)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		h.closeSessions()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return fmt.Errorf("accept: %w", err)
		}
		go h.handleNode(conn)
	}
}

func (h *Hub) listenPorts() []int {
	if len(h.cfg.Maps) > 0 {
		ports := make([]int, 0, len(h.cfg.Maps))
		for _, m := range h.cfg.Maps {
			ports = append(ports, m[0])
		}
		return ports
	}
	return h.cfg.Listen
}

func (h *Hub) closeSessions() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.sessions {
		_ = s.sess.Close()
	}
	h.sessions = nil
}

// handleNode authenticates one node connection and hosts its mux session.
func (h *Hub) handleNode(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return
	}
	aead, err := proto.ServerHandshake(tlsConn, h.secret)
	if err != nil {
		if !errors.Is(err, proto.ErrBadProbe) {
			log.Printf("node handshake from %s: %v", conn.RemoteAddr(), err)
		}
		_ = conn.Close()
		return
	}
	sess, err := smux.Server(aead, proto.MuxConfig())
	if err != nil {
		log.Printf("mux server: %v", err)
		_ = aead.Close()
		return
	}
	s := &session{sess: sess, addr: conn.RemoteAddr().String(), since: time.Now()}
	if !h.register(s) {
		log.Printf("rejecting %s: too many sessions", s.addr)
		_ = sess.Close()
		return
	}
	h.st.Sessions.Store(int64(h.count()))
	h.st.SetPeer(s.addr)
	log.Printf("node connected from %s (sessions=%d)", s.addr, h.count())

	defer func() {
		h.unregister(s)
		h.st.Sessions.Store(int64(h.count()))
		_ = sess.Close()
		log.Printf("node disconnected %s (sessions=%d)", s.addr, h.count())
	}()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		_ = stream.Close() // hub never accepts inbound streams; keep sessions symmetric
	}
}

func (h *Hub) register(s *session) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.sessions) >= maxSessions {
		return false
	}
	h.sessions = append(h.sessions, s)
	return true
}

func (h *Hub) unregister(s *session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, x := range h.sessions {
		if x == s {
			h.sessions = append(h.sessions[:i], h.sessions[i+1:]...)
			return
		}
	}
}

func (h *Hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sessions)
}

// pick returns a healthy session round-robin, waiting briefly when the
// pool is temporarily empty (node reconnecting).
func (h *Hub) pick() *session {
	deadline := time.Now().Add(10 * time.Second)
	for {
		h.mu.Lock()
		n := len(h.sessions)
		if n > 0 {
			s := h.sessions[h.rr%n]
			h.rr = (h.rr + 1) % n
			h.mu.Unlock()
			return s
		}
		h.mu.Unlock()
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// serveForward accepts one user connection per forwarded port and opens a
// stream for it on a healthy tunnel session.
func (h *Hub) serveForward(ctx context.Context, ln net.Listener, port int) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	remote := h.cfg.RemoteFor(port)
	for {
		user, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			log.Printf("forward :%d accept: %v", port, err)
			return
		}
		go h.forwardConn(user, remote)
	}
}

func (h *Hub) forwardConn(user net.Conn, remote int) {
	defer user.Close()
	s := h.pick()
	if s == nil {
		log.Printf("no healthy node session; dropping %s", user.RemoteAddr())
		return
	}
	stream, err := s.sess.OpenStream()
	if err != nil {
		log.Printf("open stream: %v", err)
		return
	}
	defer stream.Close()

	if err := stream.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(remote))
	if _, err := stream.Write(hdr[:]); err != nil {
		return
	}
	var ack [1]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil || ack[0] != 0 {
		// Node could not reach the local service.
		return
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return
	}

	h.st.Streams.Add(1)
	h.st.Total.Add(1)
	relay.Pipe(user, stream, &h.st.In, &h.st.Out)
	h.st.Streams.Add(-1)
}
