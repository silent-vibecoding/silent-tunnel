// Package e2e boots a real hub and node in-process and drives traffic
// through the whole stack: TLS disguise, inner auth, AEAD, smux and the
// forwarded-port data path.
package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"silenttunnel/internal/config"
	"silenttunnel/internal/crypto"
	"silenttunnel/internal/hub"
	"silenttunnel/internal/node"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func encodeKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

// TestTunnelEndToEnd exercises the full path a user packet takes.
func TestTunnelEndToEnd(t *testing.T) {
	t.Setenv("SILENT_STATUS_PATH", filepath.Join(t.TempDir(), "status.json"))

	// The "x-ui panel" living on the abroad server.
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "SILENT_OK")
	}))
	defer svc.Close()
	svcPort := svc.Listener.Addr().(*net.TCPAddr).Port

	tlsPort := freePort(t)
	userPort := freePort(t)

	dir := t.TempDir()
	cert, err := crypto.GenerateSelfSigned("cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.SaveCert(cert, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")); err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0xAB}, 32)

	hubCfg := &config.Hub{
		Version: 1,
		Role:    "hub",
		Host:    "127.0.0.1",
		TLSPort: tlsPort,
		SNI:     "cloudflare.com",
		Maps:    [][2]int{{userPort, svcPort}},
		Key:     encodeKey(secret),
		Cert:    filepath.Join(dir, "cert.pem"),
		CertKey: filepath.Join(dir, "key.pem"),
	}
	hubStatusPath := filepath.Join(dir, "hub-status.json")
	h, err := hub.New(hubCfg)
	if err != nil {
		t.Fatal(err)
	}
	h.StatusPath = hubStatusPath
	hubCtx, stopHub := context.WithCancel(context.Background())
	defer stopHub()
	hubErr := make(chan error, 1)
	go func() { hubErr <- h.Run(hubCtx) }()

	nodeCfg := &config.Node{
		Version: 1,
		Role:    "node",
		Host:    "127.0.0.1",
		Port:    tlsPort,
		SNI:     "cloudflare.com",
		Key:     encodeKey(secret),
		FP:      crypto.Fingerprint(cert),
		Pool:    2,
		Bind:    "127.0.0.1",
	}
	n, err := node.New(nodeCfg)
	if err != nil {
		t.Fatal(err)
	}
	nodeCtx, stopNode := context.WithCancel(context.Background())
	defer stopNode()
	go func() { _ = n.Run(nodeCtx) }()

	// Drive an HTTP request through the tunnel, retrying while the pool
	// establishes itself.
	client := &http.Client{Timeout: 5 * time.Second}
	var body string
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", userPort))
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body = string(b)
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel never carried traffic: last err=%v body=%q", err, body)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if body != "SILENT_OK" {
		t.Fatalf("unexpected body through tunnel: %q", body)
	}

	// Status file must exist and reflect the running hub.
	checkHubStatus(t, hubStatusPath)

	// A wrong-token node must NOT establish a tunnel session. Point its
	// status file elsewhere so it does not clobber the hub's.
	t.Setenv("SILENT_STATUS_PATH", filepath.Join(t.TempDir(), "bad-status.json"))
	badCfg := *nodeCfg
	badKey := bytes.Repeat([]byte{0xCD}, 32)
	badCfg.Key = encodeKey(badKey)
	badNode, err := node.New(&badCfg)
	if err != nil {
		t.Fatal(err)
	}
	badCtx, stopBad := context.WithCancel(context.Background())
	defer stopBad()
	go func() { _ = badNode.Run(badCtx) }()
	time.Sleep(2 * time.Second) // give it time to (fail to) connect

	// The decoy: a plain TLS client speaking HTTP gets a believable 404.
	tlsConn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort), &tls.Config{
		ServerName:         "cloudflare.com",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("tls dial for decoy: %v", err)
	}
	_, _ = tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: something\r\n\r\n"))
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := io.ReadAll(tlsConn)
	_ = tlsConn.Close()
	if err != nil && !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("decoy read: %v", err)
	}
	if !strings.Contains(string(resp), "404 Not Found") {
		t.Fatalf("expected nginx-style decoy, got: %q", string(resp))
	}

	stopNode()
	stopHub()
	select {
	case err := <-hubErr:
		if err != nil {
			t.Fatalf("hub run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hub did not stop")
	}
}

// checkHubStatus polls the hub status file (refreshed every 5s) until it
// reflects a healthy tunnel.
func checkHubStatus(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			var st struct {
				Role         string `json:"role"`
				Sessions     int64  `json:"sessions"`
				BytesIn      uint64 `json:"bytes_in"`
				BytesOut     uint64 `json:"bytes_out"`
				StreamsOpen  int64  `json:"streams_open"`
				TotalStreams uint64 `json:"total_streams"`
			}
			if err := json.Unmarshal(raw, &st); err == nil {
				if st.Role == "hub" && st.Sessions >= 1 && st.BytesIn+st.BytesOut > 0 {
					t.Logf("tunnel carried %d bytes total, %d streams", st.BytesIn+st.BytesOut, st.TotalStreams)
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never became healthy: file=%q err=%v content=%s", path, err, string(raw))
		}
		time.Sleep(500 * time.Millisecond)
	}
}
