package cli

import (
	"flag"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"

	survey "github.com/AlecAivazis/survey/v2"

	"silenttunnel/internal/config"
)

// cmdSetupNode writes the abroad-side config from a pairing token. Port
// forwarding is fully automatic: the node detects its listening services
// (or takes --ports), and announces them to the hub on every connect.
func cmdSetupNode(args []string) int {
	fs := flag.NewFlagSet("setup-node", flag.ContinueOnError)
	fs.Usage = func() { fmt.Println("usage: silent setup-node --token st1_... [--ports 2087,44301] [--pool 3] [--config path]") }
	token := fs.String("token", "", "pairing token printed by setup-hub")
	pool := fs.Int("pool", 3, "number of pooled tunnel connections (1-16)")
	portsFlag := fs.String("ports", "", "ports to forward (omit to pick from auto-detected services)")
	conf := fs.String("config", "", "config path (default per-OS)")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	p, err := tokenFromInput(*token)
	if err != nil {
		errf("%v", err)
		return 1
	}
	if *pool < 1 {
		*pool = 3
	}
	if *pool > 16 {
		*pool = 16
	}

	var ports []int
	if *portsFlag != "" {
		ports, err = parsePortList(*portsFlag)
		if err != nil {
			errf("%v", err)
			return 1
		}
	} else if isTTY() {
		ports, err = portWizard()
		if err != nil {
			errf("wizard cancelled: %v", err)
			return 1
		}
	}

	cfg := configFromToken(p, *pool)
	cfg.Ports = ports
	path := *conf
	if path == "" {
		path = config.NodePath()
	}
	if err := config.Save(path, cfg); err != nil {
		errf("save config: %v", err)
		return 1
	}

	fmt.Println()
	okf("node created at %s (%s)", path, subtle("abroad"))
	fmt.Printf("  Hub: %s:%d    SNI: %s    pool: %d connections\n", p.Host, p.Port, p.SNI, *pool)
	if len(ports) > 0 {
		fmt.Printf("  Forwarded ports: %s\n", intsString(ports))
		tipf("The same port numbers become reachable on the Iran server (%s) as soon as the tunnel is up.", p.Host)
		tipf("The hub opens them in its own firewall automatically — only cloud security groups need manual rules.")
	} else {
		fmt.Printf("  %s\n", warn("no ports forwarded — run setup-node again and pick at least one"))
	}
	fmt.Println()
	tipf("Start here:  sudo silent node        Start on Iran:  sudo silent hub")

	if isTTY() && len(ports) > 0 {
		yes, err := Confirm("Install the systemd service now (start on boot)?", true)
		if err == nil && yes {
			fmt.Println()
			_ = cmdInstall(nil)
			return 0
		}
	}
	return 0
}

// portWizard auto-detects listening services and lets the user tick the
// ones to expose through the tunnel.
func portWizard() ([]int, error) {
	fmt.Println()
	tipf("Pick the services to expose — the SAME port numbers will open on the Iran server")

	var chosen []int
	detected := detectListeningPorts()
	if len(detected) > 0 {
		options := make([]string, len(detected))
		for i, p := range detected {
			options[i] = strconv.Itoa(p)
		}
		var def []int
		for i, p := range detected {
			if p != 22 { // never expose SSH by default
				def = append(def, i)
			}
		}
		var idxs []int
		prompt := &survey.MultiSelect{
			Message: "Detected listening ports (space to toggle, Enter to confirm):",
			Options: options,
			Default: def,
		}
		if err := survey.AskOne(prompt, &idxs); err != nil {
			return nil, uiErr(err)
		}
		for _, i := range idxs {
			if i >= 0 && i < len(detected) {
				chosen = append(chosen, detected[i])
			}
		}
	} else {
		tipf("could not auto-detect listening services — enter them manually")
	}

	extra, err := Ask("Extra ports, comma-separated (Enter to skip)", "")
	if err != nil {
		return nil, uiErr(err)
	}
	if strings.TrimSpace(extra) != "" {
		more, err := parsePortList(extra)
		if err != nil {
			return nil, err
		}
		chosen = append(chosen, more...)
	}

	seen := map[int]bool{}
	var out []int
	for _, p := range chosen {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	if len(out) == 0 {
		errf("no ports selected — the tunnel will carry nothing")
	}
	return out, nil
}

func parsePortList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port: %s", part)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one port is required")
	}
	return out, nil
}

// detectListeningPorts returns TCP ports listening on loopback or all
// interfaces (Linux only, parsed from `ss -tln`).
func detectListeningPorts() []int {
	if runtime.GOOS != "linux" {
		return nil
	}
	out, err := exec.Command("ss", "-tln").Output()
	if err != nil {
		return nil
	}
	set := map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "LISTEN" {
			continue
		}
		host, portStr, err := net.SplitHostPort(f[3])
		if err != nil {
			continue
		}
		switch host {
		case "", "0.0.0.0", "::", "*", "127.0.0.1", "::1":
		default:
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		set[port] = true
	}
	var ports []int
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}
