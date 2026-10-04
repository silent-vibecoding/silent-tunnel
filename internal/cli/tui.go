package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"silenttunnel/internal/config"
	"silenttunnel/internal/hub"
	"silenttunnel/internal/node"
)

// constructors wired here keep the daemon wiring out of the menu code.
var (
	newHub  = hub.New
	newNode = node.New
)

const banner = `
   ╔═╦╗╔═╗╔═╗╔═╗╔═╗╦ ╦╔╦╗╔═╗╔═╗
   ║ ║║║ ║║╣ ╠═╝╠╣ ║ ║ ║ ║ ║║╣
   ╚╩═╝╚═╝╚═╝╩ ╩╚  ╚═╝ ╩ ╚═╝╚═╝   v%s
`

// tuiMain is the interactive menu — the primary interface. Everything is
// reachable by arrow keys; no memorized commands needed.
func tuiMain() int {
	fmt.Printf(banner, Version)
	if !isTTY() {
		usage()
		return 1
	}

	options := []string{
		"Set this server up as the hub (Iran)",
		"Set this server up as the node (abroad)",
		"Run the tunnel (based on the existing config)",
		"Install the systemd service (start on boot)",
		"Live status",
		"Health check (doctor)",
		"Show the pairing token",
		"Full removal (uninstall)",
		"Exit",
	}

	for {
		idx, err := Select("Choose an option:", options)
		if err != nil {
			fmt.Println()
			return 0
		}
		switch idx {
		case 0:
			runStep(func() int { return cmdSetupHub(nil) })
		case 1:
			runStep(func() int { return cmdSetupNode(nil) })
		case 2:
			runStep(runTunnel)
		case 3:
			runStep(func() int { return cmdInstall(nil) })
		case 4:
			runStep(cmdStatus)
		case 5:
			runStep(func() int { return cmdDoctor(nil) })
		case 6:
			runStep(cmdToken)
		case 7:
			runStep(func() int { return cmdUninstall(nil) })
		default:
			return 0
		}
	}
}

// runStep runs a menu action and pauses so its output stays readable.
func runStep(fn func() int) {
	fmt.Println()
	_ = fn()
	fmt.Println()
	pause()
}

func pause() {
	if _, err := Ask(subtle("Press Enter to return to the menu"), ""); err != nil {
		os.Exit(0)
	}
}

// runTunnel picks the daemon to run based on which config exists.
func runTunnel() int {
	role, _ := detectRole()
	if role == "" {
		errf("no config yet — run option 1 or 2 first")
		return 1
	}
	return runDaemon(role, nil)
}

// runDaemon loads the role config and blocks serving traffic.
func runDaemon(role string, args []string) int {
	path := ""
	if len(args) > 0 {
		if a := args[0]; !strings.HasPrefix(a, "-") {
			path = a
		}
	}
	ctx := signalCtx()

	switch role {
	case "hub":
		if path == "" {
			path = config.HubPath()
		}
		cfg, err := config.LoadHub(path)
		if err != nil {
			errf("hub config (%s): %v", filepath.Base(path), err)
			return 1
		}
		h, err := newHub(cfg)
		if err != nil {
			errf("%v", err)
			return 1
		}
		okf("hub running — press Ctrl+C to stop")
		if err := h.Run(ctx); err != nil {
			errf("%v", err)
			return 1
		}
		okf("hub stopped")
		return 0
	case "node":
		if path == "" {
			path = config.NodePath()
		}
		cfg, err := config.LoadNode(path)
		if err != nil {
			errf("node config (%s): %v", filepath.Base(path), err)
			return 1
		}
		n, err := newNode(cfg)
		if err != nil {
			errf("%v", err)
			return 1
		}
		okf("node running — press Ctrl+C to stop")
		if err := n.Run(ctx); err != nil {
			errf("%v", err)
			return 1
		}
		okf("node stopped")
		return 0
	default:
		usage()
		return 1
	}
}
