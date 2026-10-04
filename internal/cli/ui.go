package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	survey "github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/fatih/color"
)

// isTTY reports whether stdin is an interactive terminal; the TUI refuses
// to open inside scripts and pipes.
func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

var (
	good   = color.New(color.FgGreen, color.Bold).SprintFunc()
	bad    = color.New(color.FgRed, color.Bold).SprintFunc()
	info   = color.New(color.FgCyan, color.Bold).SprintFunc()
	warn   = color.New(color.FgYellow).SprintFunc()
	subtle = color.New(color.Faint).SprintFunc()
)

func okf(format string, a ...interface{})  { fmt.Println(good("✔"), fmt.Sprintf(format, a...)) }
func errf(format string, a ...interface{}) { fmt.Println(bad("✘"), fmt.Sprintf(format, a...)) }
func tipf(format string, a ...interface{}) { fmt.Println(info("»"), fmt.Sprintf(format, a...)) }

// Select shows an arrow-key menu and returns the chosen index.
func Select(label string, options []string) (int, error) {
	idx := 0
	err := survey.AskOne(&survey.Select{
		Message: label,
		Options: options,
	}, &idx)
	return idx, err
}

// Ask prompts for a string with a default.
func Ask(label, def string) (string, error) {
	var v string
	err := survey.AskOne(&survey.Input{Message: label, Default: def}, &v)
	return strings.TrimSpace(v), err
}

// AskInt prompts until the input parses as an integer in [min,max].
func AskInt(label string, def, min, max int) (int, error) {
	for {
		v, err := Ask(label, strconv.Itoa(def))
		if err != nil {
			return 0, err
		}
		n, convErr := strconv.Atoi(v)
		if convErr == nil && n >= min && n <= max {
			return n, nil
		}
		errf("enter a number between %d and %d", min, max)
	}
}

// Confirm asks a yes/no question.
func Confirm(label string, def bool) (bool, error) {
	v := false
	err := survey.AskOne(&survey.Confirm{Message: label, Default: def}, &v)
	return v, err
}

// uiErr normalizes the survey abort error (Ctrl+C / EOF).
func uiErr(err error) error {
	if err == terminal.InterruptErr {
		return fmt.Errorf("cancelled")
	}
	return err
}
