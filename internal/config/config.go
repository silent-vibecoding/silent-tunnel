// Package config loads and saves the hub (Iran) and node (abroad) JSON
// configuration files and resolves platform-specific default paths.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Hub is the Iran-side configuration: one TLS listener for the node plus
// the user-facing forwarded ports.
type Hub struct {
	Version int      `json:"version"`
	Role    string   `json:"role"`
	Host    string   `json:"host"` // public IP/domain written into the pairing token
	TLSPort int      `json:"tls_port"`
	SNI     string   `json:"sni"`
	Listen  []int    `json:"listen_ports"`   // user-facing ports
	Maps    [][2]int `json:"maps,omitempty"` // [listen, remote]; empty = same-port
	Key     string   `json:"key"`            // base64 of the 32-byte shared secret
	Cert    string   `json:"cert"`
	CertKey string   `json:"cert_key"`
	Bind    string   `json:"bind"` // address services bind on the node, default 127.0.0.1
}

// Node is the abroad-side configuration, normally written from a token.
type Node struct {
	Version int    `json:"version"`
	Role    string `json:"role"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	SNI     string `json:"sni"`
	Key     string `json:"key"`
	FP      string `json:"fp"`
	Pool    int    `json:"pool"`
	Bind    string `json:"bind"`
	// Ports is the list the node announces to the hub on every connect;
	// the hub opens the same port numbers and forwards them here.
	Ports []int `json:"ports"`
}

const (
	hubFile  = "hub.json"
	nodeFile = "node.json"
)

// BaseDir is where configs live: /etc/silent on Linux, %LOCALAPPDATA%\silent
// on Windows.
func BaseDir() string {
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			return filepath.Join(la, "silent")
		}
		return filepath.Join(os.Getenv("USERPROFILE"), "silent")
	}
	return "/etc/silent"
}

// StatusPath is where the running daemon drops its live statistics.
// The SILENT_STATUS_PATH environment variable overrides it (used by tests
// and container setups).
func StatusPath() string {
	if p := os.Getenv("SILENT_STATUS_PATH"); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(BaseDir(), "status.json")
	}
	return "/var/lib/silent/status.json"
}

func HubPath() string  { return filepath.Join(BaseDir(), hubFile) }
func NodePath() string { return filepath.Join(BaseDir(), nodeFile) }

// LoadHub reads and sanity-checks the hub config.
func LoadHub(path string) (*Hub, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var h Hub
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if h.Role != "hub" {
		return nil, errors.New("not a hub config")
	}
	h.fillDefaults()
	if err := h.validate(); err != nil {
		return nil, err
	}
	return &h, nil
}

// LoadNode reads and sanity-checks the node config.
func LoadNode(path string) (*Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var n Node
	if err := json.Unmarshal(b, &n); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if n.Role != "node" {
		return nil, errors.New("not a node config")
	}
	n.fillDefaults()
	if err := n.validate(); err != nil {
		return nil, err
	}
	return &n, nil
}

func (h *Hub) fillDefaults() {
	if h.TLSPort == 0 {
		h.TLSPort = 443
	}
	if h.Bind == "" {
		h.Bind = "127.0.0.1"
	}
}

func (h *Hub) validate() error {
	switch {
	case h.Host == "":
		return errors.New("hub config: host is empty")
	case h.TLSPort < 1 || h.TLSPort > 65535:
		return errors.New("hub config: invalid tls_port")
	case h.SNI == "":
		return errors.New("hub config: sni is empty")
	case h.Key == "":
		return errors.New("hub config: key is empty")
	case h.Cert == "" || h.CertKey == "":
		return errors.New("hub config: certificate paths missing")
	}
	// Listen/Maps are optional: when absent the hub forwards whatever
	// ports the node announces over the control stream.
	if _, err := h.Secret(); err != nil {
		return err
	}
	for _, p := range h.Listen {
		if p < 1 || p > 65535 {
			return fmt.Errorf("hub config: invalid listen port %d", p)
		}
	}
	for _, m := range h.Maps {
		if m[0] < 1 || m[0] > 65535 || m[1] < 1 || m[1] > 65535 {
			return fmt.Errorf("hub config: invalid mapping %d->%d", m[0], m[1])
		}
	}
	return nil
}

func (n *Node) fillDefaults() {
	if n.Pool == 0 {
		n.Pool = 3
	}
	if n.Pool > 16 {
		n.Pool = 16
	}
	if n.Bind == "" {
		n.Bind = "127.0.0.1"
	}
}

func (n *Node) validate() error {
	switch {
	case n.Host == "":
		return errors.New("node config: host is empty")
	case n.Port < 1 || n.Port > 65535:
		return errors.New("node config: invalid port")
	case n.SNI == "":
		return errors.New("node config: sni is empty")
	case n.Key == "":
		return errors.New("node config: key is empty")
	case len(n.FP) != 64:
		return errors.New("node config: malformed certificate fingerprint")
	}
	if len(n.Ports) > 64 {
		return errors.New("node config: too many forwarded ports (max 64)")
	}
	for _, p := range n.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("node config: invalid forwarded port %d", p)
		}
	}
	if _, err := n.Secret(); err != nil {
		return err
	}
	return nil
}

// RemoteFor resolves the node-side port for a hub listen port: explicit
// mapping when present, identity (same port) otherwise.
func (h *Hub) RemoteFor(listen int) int {
	for _, m := range h.Maps {
		if m[0] == listen {
			return m[1]
		}
	}
	return listen
}

// Secret decodes the base64 shared key from either config.
func (h *Hub) Secret() ([]byte, error) { return decodeKey(h.Key) }

// Secret decodes the base64 shared key from the node config.
func (n *Node) Secret() ([]byte, error) { return decodeKey(n.Key) }

func decodeKey(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return nil, errors.New("config key must be base64 of 32 bytes")
	}
	return b, nil
}

// Save writes JSON with permissions that keep the shared key private.
func Save(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
