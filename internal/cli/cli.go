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
		fmt.Printf("دستور ناشناخته: %s\n\n", args[0])
		usage()
		return 1
	}
}

func usage() {
	fmt.Print(`Silent Tunnel — تونل اختصاصی ایران ⇄ خارج

استفاده: silent [دستور]

  بدون دستور       منوی تعاملی
  setup-hub        راه‌اندازی سرور ایران (ساخت کانفیگ، گواهی و توکن pairing)
  setup-node       راه‌اندازی سرور خارج با توکن pairing
  hub              اجرای دیمن هاب (ایران)
  node             اجرای دیمن نود (خارج)
  status           وضعیت زنده‌ی دیمن در حال اجرا
  doctor           تست سلامت و عیب‌یابی
  install          نصب سرویس systemd (اجرای خودکار پس از ریبوت)
  uninstall        حذف کامل سرویس
  token            نمایش دوباره‌ی توکن pairing

مثال:
  sudo silent                      # منو
  sudo silent setup-hub            # ویزارد ایران
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
