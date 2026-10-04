// Package proto defines the Silent Tunnel wire handshake: the inner
// token-based authentication performed right after TLS, the decoy answer
// served to unauthorized probes, and the shared smux configuration.
package proto

import (
	"time"

	"github.com/xtaci/smux"
)

// Magic starts every handshake; Version guards future protocol changes.
var Magic = [4]byte{'S', 'L', 'N', 'T'}

const Version = 1

// HandshakeLen is the exact byte length of the client hello:
// magic(4) + version(1) + clientSalt(16) + proof(48).
const ClientHelloLen = 4 + 1 + 16 + 48

// ServerReplyLen is the exact byte length of the server reply:
// serverSalt(16) + ack(48).
const ServerReplyLen = 16 + 48

const (
	// AuthReadTimeout bounds how long the hub waits for a valid hello
	// before serving the decoy and closing.
	AuthReadTimeout = 5 * time.Second
	// DialTimeout bounds the handshake on the node side.
	DialTimeout = 15 * time.Second
	// ClockSkew is the tolerated difference between node and hub clocks.
	ClockSkew = 120 * time.Second
)

// MuxConfig returns the shared smux configuration. Generous buffers keep
// throughput stable on high-latency satellite/long-haul links.
func MuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	cfg.MaxFrameSize = 32768
	cfg.MaxReceiveBuffer = 8 << 20
	cfg.MaxStreamBuffer = 4 << 20
	return cfg
}
