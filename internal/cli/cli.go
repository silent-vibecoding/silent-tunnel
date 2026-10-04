// Package cli wires the subcommands, the interactive TUI menu and the
// setup wizards of Silent Tunnel.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

// Version is overridden at build time with -ldflags.
var Version = "dev"

// Run dispatches args; empty args open the interactive menu.
func Run(args []string) int {
	if len(args) == 0 {
		return tuiMain()
	}
	switch args[0] {
	case "setup-hub":
		return cmdSetupHub(args[1:])
	case "setup-node":
		return cmdSetupNode(args[1:])
	case "hub":
		return runDaemon("hub", args[1:])
	case "node":
		return runDaemon("node", args[1:])
	case "status":
		return cmdStatus()
	case "doctor":
		return cmdDoctor(args[1:])
	case "install":
		return cmdInstall(args[1:])
	case "uninstall":
		return cmdUninstall(args[1:])
	case "token":
		return cmdToken()
	case "version", "--version", "-v":
		fmt.Println("Silent Tunnel", Version)
		return 0
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		fmt.Printf("unknown command: %s\n\n", args[0])
		usage()
		return 1
	}
}

func usage() {
	fmt.Print(`Silent Tunnel — disguised reverse tunnel for Iran <-> abroad setups

Usage: silent [command]

  (no command)     interactive menu
  setup-hub        set up the Iran server (config, certificate, pairing token)
  setup-node       set up the abroad server from a pairing token
  hub              run the hub daemon (Iran)
  node             run the node daemon (abroad)
  status           live status of the running daemon
  doctor           health check and troubleshooting
  install          install the systemd service (start on boot)
  uninstall        remove the service
  token            print the pairing token again

Examples:
  sudo silent                      # menu
  sudo silent setup-hub            # Iran wizard
  sudo silent setup-node --token st1_...
`)
}

// signalCtx returns a context cancelled on SIGINT/SIGTERM.
func signalCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx
}
