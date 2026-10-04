package cli

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"silenttunnel/internal/config"
	"silenttunnel/internal/crypto"
	"silenttunnel/internal/node"
)

// cmdDoctor runs environment checks for whichever role is configured.
func cmdDoctor(args []string) int {
	if cfg, err := config.LoadHub(config.HubPath()); err == nil {
		return doctorHub(cfg)
	}
	if cfg, err := config.LoadNode(config.NodePath()); err == nil {
		return doctorNode(cfg)
	}
	errf("no config found — run setup-hub or setup-node first")
	return 1
}

func doctorHub(cfg *config.Hub) int {
	fmt.Println()
	tipf("Hub (Iran) health check")
	code := 0

	cert, err := crypto.LoadCert(cfg.Cert, cfg.CertKey)
	if err != nil {
		errf("certificate: %v", err)
		code = 1
	} else {
		okf("certificate OK (fingerprint %s...)", crypto.Fingerprint(cert)[:16])
		if _, err := tokenFor(cfg); err != nil {
			errf("cannot build the pairing token: %v", err)
			code = 1
		} else {
			okf("pairing token ready (run 'silent token' to print it)")
		}
	}

	for _, p := range append([]int{cfg.TLSPort}, cfg.Listen...) {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(p))
		if err != nil {
			errf("port %d is not free: %v", p, err)
			code = 1
			continue
		}
		_ = ln.Close()
		okf("port %d is free", p)
	}
	if len(cfg.Listen) == 0 && len(cfg.Maps) == 0 {
		okf("port forwarding is automatic (the node announces its ports on connect)")
	}

	if hint := clockCheck(); hint != "" {
		fmt.Printf("  %s\n", warn(hint))
	}
	fmt.Println()
	return code
}

func doctorNode(cfg *config.Node) int {
	fmt.Println()
	tipf("Node (abroad) health check")

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		errf("cannot reach the hub over TCP at %s: %v", addr, err)
		fmt.Printf("  %s\n", warn("Check: is the IP/port correct? Does the Iran firewall allow port "+strconv.Itoa(cfg.Port)+"?"))
		return 1
	}
	_ = conn.Close()
	okf("TCP connection to the hub %s works", addr)

	if err := node.Probe(cfg); err != nil {
		errf("inner handshake: %v", err)
		fmt.Printf("  %s\n", warn("If the error mentions clock skew: sync both servers with NTP (timedatectl set-ntp true)"))
		fmt.Printf("  %s\n", warn("If it says fingerprint mismatch: the hub config or token changed — run 'silent token' on the hub and re-run setup-node"))
		return 1
	}
	okf("auth and inner encryption OK — the tunnel is ready")
	fmt.Println()
	return 0
}

// clockCheck compares the local clock against Cloudflare's daytime service
// and returns a warning when the skew could break the ±2min auth window.
func clockCheck() string {
	resp, err := net.DialTimeout("tcp", "time.cloudflare.com:13", 4*time.Second)
	if err != nil {
		return ""
	}
	defer resp.Close()
	_ = resp.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 128)
	n, _ := resp.Read(buf)
	// NIST daytime: "87953 25-10-04 15:20:30 00 0 0 12.4 UTC(NIST) *"
	f := strings.Fields(string(buf[:n]))
	if len(f) < 3 {
		return ""
	}
	remote, err := time.Parse("06-01-02 15:04:05", f[1]+" "+f[2])
	if err != nil {
		return ""
	}
	remote = remote.UTC()
	skew := time.Since(remote).Round(time.Second)
	if skew < 0 {
		skew = -skew
	}
	if skew > 60*time.Second {
		return fmt.Sprintf("this server's clock differs from the global reference by %.0f seconds — sync it with timedatectl set-ntp true", skew.Seconds())
	}
	return ""
}
