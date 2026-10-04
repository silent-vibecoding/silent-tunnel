// Package node implements the abroad-side exit: it dials the hub with a
// disguised TLS connection, keeps a pool of those connections healthy and
// serves each inbound stream by connecting to the local service.
package node

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"silenttunnel/internal/config"
	"silenttunnel/internal/crypto"
	"silenttunnel/internal/proto"
	"silenttunnel/internal/relay"
	"silenttunnel/internal/state"
)

// sleepCtx sleeps for d but returns immediately when ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Node is the abroad-side client.
type Node struct {
	// StatusPath overrides where live statistics are written (tests and
	// containers); empty means the platform default.
	StatusPath string

	cfg    *config.Node
	secret []byte
	st     *state.State
}

// New prepares the node.
func New(cfg *config.Node) (*Node, error) {
	secret, err := cfg.Secret()
	if err != nil {
		return nil, err
	}
	return &Node{cfg: cfg, secret: secret, st: state.New("node")}, nil
}

// Run blocks until ctx is cancelled, keeping the connection pool alive.
func (n *Node) Run(ctx context.Context) error {
	stop := make(chan struct{})
	defer close(stop)
	statusPath := n.StatusPath
	if statusPath == "" {
		statusPath = config.StatusPath()
	}
	go n.st.WriteLoop(statusPath, 5*time.Second, stop)

	addr := net.JoinHostPort(n.cfg.Host, strconv.Itoa(n.cfg.Port))
	log.Printf("node starting: hub=%s sni=%s pool=%d bind=%s", addr, n.cfg.SNI, n.cfg.Pool, n.cfg.Bind)

	var wg sync.WaitGroup
	for i := 0; i < n.cfg.Pool; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			n.worker(ctx, idx, addr)
		}(i)
	}
	<-ctx.Done()
	wg.Wait()
	return nil
}

// worker owns one pool slot: connect, serve, and reconnect with exponential
// backoff until the process is told to stop.
func (n *Node) worker(ctx context.Context, idx int, addr string) {
	backoff := time.Second
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		attempt++
		sess, err := n.connect(addr)
		if err != nil {
			if attempt == 1 {
				log.Printf("[pool %d] connect failed: %v", idx, err)
			}
			j := time.Duration(rand.Int63n(int64(500 * time.Millisecond)))
			sleepCtx(ctx, backoff+j)
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second
		attempt = 0
		n.st.Sessions.Add(1)
		n.st.Reconnects.Add(1)
		n.st.SetPeer(addr)
		log.Printf("[pool %d] tunnel established (sessions=%d)", idx, n.st.Sessions.Load())

		if len(n.cfg.Ports) > 0 {
			if err := announce(sess, n.cfg.Ports); err != nil {
				log.Printf("[pool %d] announce ports: %v", idx, err)
			} else {
				log.Printf("[pool %d] announced %d forwarded port(s)", idx, len(n.cfg.Ports))
			}
		}

		n.serveSession(sess)

		n.st.Sessions.Add(-1)
		log.Printf("[pool %d] session lost (sessions=%d), reconnecting", idx, n.st.Sessions.Load())
		sleepCtx(ctx, 250*time.Millisecond)
	}
}

// connect dials TLS with fingerprint pinning, runs the inner handshake and
// opens the mux session.
func (n *Node) connect(addr string) (*smux.Session, error) {
	tlsConf := &tls.Config{
		ServerName:            n.cfg.SNI,
		InsecureSkipVerify:    true, // fingerprint pinning below is the real check
		VerifyPeerCertificate: crypto.PinFingerprint(n.cfg.FP),
		// Browser-like ALPN keeps the client hello unremarkable to DPI.
		NextProtos: []string{"h2", "http/1.1"},
	}
	d := &net.Dialer{Timeout: proto.DialTimeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	aead, err := proto.ClientHandshake(conn, n.secret)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	sess, err := smux.Client(aead, proto.MuxConfig())
	if err != nil {
		_ = aead.Close()
		return nil, fmt.Errorf("mux client: %w", err)
	}
	return sess, nil
}

// announce tells the hub which local ports to forward, over a control
// stream (header 0x0000). The hub opens the same port numbers on itself.
func announce(sess *smux.Session, ports []int) error {
	stream, err := sess.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))

	payload, err := json.Marshal(struct {
		Ports []int `json:"ports"`
	}{ports})
	if err != nil {
		return err
	}
	var hdr [2]byte // 0x0000 marks the control stream
	if _, err := stream.Write(hdr[:]); err != nil {
		return err
	}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	if _, err := stream.Write(l[:]); err != nil {
		return err
	}
	_, err = stream.Write(payload)
	return err
}

// serveSession accepts hub-opened streams until the session dies. Each
// stream carries [2-byte remote port][1-byte dial status][raw TCP].
func (n *Node) serveSession(sess *smux.Session) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.handleStream(stream)
		}()
	}
}

func (n *Node) handleStream(stream *smux.Stream) {
	defer stream.Close()
	n.st.Streams.Add(1)
	n.st.Total.Add(1)
	defer n.st.Streams.Add(-1)

	if err := stream.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return
	}
	var hdr [2]byte
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(hdr[:])

	local, err := net.DialTimeout("tcp", net.JoinHostPort(n.cfg.Bind, strconv.Itoa(int(port))), 10*time.Second)
	if err != nil {
		_, _ = stream.Write([]byte{1}) // dial failed
		return
	}
	defer local.Close()
	if _, err := stream.Write([]byte{0}); err != nil { // dial ok
		return
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		return
	}
	relay.Pipe(local, stream, &n.st.In, &n.st.Out)
}

// Probe dials the hub and performs a full auth handshake, reporting the
// result — used by `silent doctor`.
func Probe(cfg *config.Node) error {
	secret, err := cfg.Secret()
	if err != nil {
		return err
	}
	tlsConf := &tls.Config{
		ServerName:            cfg.SNI,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: crypto.PinFingerprint(cfg.FP),
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, tlsConf)
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()
	aead, err := proto.ClientHandshake(conn, secret)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	_ = aead.Close()
	return nil
}
