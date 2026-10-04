// Package firewall opens TCP ports in the local firewall so forwarded
// ports become reachable without manual steps. Best-effort: when no
// supported firewall (ufw, firewalld) is active it reports back so the
// caller can print manual instructions. Rules are only ever added, never
// removed, and it is safe to call repeatedly.
package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Result describes what OpenTCPPort did (or what should be done by hand).
type Result struct {
	Opened bool   // a rule was added (or already existed)
	Tool   string // "ufw" / "firewalld" / ""
	Note   string // human-readable outcome or hint
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func ufwActive() bool {
	out, err := run("ufw", "status")
	return err == nil && strings.Contains(out, "Status: active")
}

func firewalldRunning() bool {
	out, err := run("firewall-cmd", "--state")
	return err == nil && strings.TrimSpace(out) == "running"
}

// OpenTCPPort best-effort allows a TCP port on the local firewall
// (effective only as root on Linux).
func OpenTCPPort(port int) Result {
	p := fmt.Sprintf("%d/tcp", port)
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		return Result{Note: fmt.Sprintf("open %s in the firewall manually (e.g. sudo ufw allow %s)", p, p)}
	}
	if _, err := exec.LookPath("ufw"); err == nil && ufwActive() {
		if _, err := run("ufw", "allow", p); err == nil {
			return Result{Opened: true, Tool: "ufw", Note: fmt.Sprintf("ufw: allowed %s", p)}
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil && firewalldRunning() {
		if _, err := run("firewall-cmd", "--add-port="+p); err == nil {
			_, _ = run("firewall-cmd", "--permanent", "--add-port="+p)
			return Result{Opened: true, Tool: "firewalld", Note: fmt.Sprintf("firewalld: allowed %s", p)}
		}
	}
	return Result{Note: fmt.Sprintf("no active firewall detected — if you use one (or a cloud security group), open %s manually", p)}
}
