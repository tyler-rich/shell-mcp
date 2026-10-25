package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
	"github.com/tyler-rich/shell-mcp/internal/approval/qr"
)

const approverUsage = `usage: shell-mcp approver <command> [flags]

commands:
  add     --name <name> --file <path> [--allow-multiple]
          enrol an approver: add a new seed to the approvers file (mode 0600)
          and show its otpauth QR code once; stdout must be a terminal
  remove  --name <name> --file <path>
          remove an approver
  list    --file <path>
          print the enrolled names

The server reads the approvers file at start; restart it after a change.
`

// approverEnv is what the approver command takes from the process; tests
// replace it.
type approverEnv struct {
	rand       io.Reader
	isTerminal func(io.Writer) bool
}

var processApproverEnv = approverEnv{rand: rand.Reader, isTerminal: isTerminal}

// cmdApprover runs `shell-mcp approver add|remove|list`. Refusals exit 1 and
// usage errors 2. The seed and its URI go to stdout only, only once, and only
// when stdout is a terminal; stderr gets one-line reasons and the audit
// lines, which carry the name and file path only.
func cmdApprover(args []string, stdout, stderr io.Writer, env approverEnv) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, approverUsage)
		return 2
	}
	switch args[0] {
	case "add":
		return approverAdd(args[1:], stdout, stderr, env)
	case "remove":
		return approverRemove(args[1:], stderr)
	case "list":
		return approverList(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		_, _ = io.WriteString(stdout, approverUsage)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "shell-mcp: approver: unknown command %q\n%s", args[0], approverUsage)
	return 2
}

// approverFlags parses one subcommand's flags; every flag it is given is
// required.
func approverFlags(cmd string, args []string, stderr io.Writer, name, file *string, multiple *bool) bool {
	fs := flag.NewFlagSet("approver "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	if name != nil {
		fs.StringVar(name, "name", "", "approver name, matching ^[a-z][a-z0-9-]{0,31}$")
	}
	fs.StringVar(file, "file", "", "approvers file")
	if multiple != nil {
		fs.BoolVar(multiple, "allow-multiple", false, "allow an approver when the file already holds one")
	}
	if err := fs.Parse(args); err != nil {
		return false
	}
	if fs.NArg() != 0 || *file == "" || (name != nil && *name == "") {
		_, _ = fmt.Fprintf(stderr, "shell-mcp: approver %s: missing or extra arguments\n%s", cmd, approverUsage)
		return false
	}
	if name != nil && !approvers.ValidName(*name) {
		_, _ = fmt.Fprintf(stderr, "shell-mcp: approver %s: the name must match ^[a-z][a-z0-9-]{0,31}$\n", cmd)
		return false
	}
	return true
}

func approverAdd(args []string, stdout, stderr io.Writer, env approverEnv) int {
	var name, file string
	var multiple bool
	if !approverFlags("add", args, stderr, &name, &file, &multiple) {
		return 2
	}
	// Checked before anything is generated or written, so a seed never
	// exists that nobody saw, and is never shown into a pipe, file or log.
	if !env.isTerminal(stdout) {
		return refuse(stderr, "add", errors.New("stdout is not a terminal, and the seed is shown only on one (in a container, run it with docker run --rm -it)"))
	}
	seed := make([]byte, approvers.MinSeedBytes)
	if _, err := io.ReadFull(env.rand, seed); err != nil {
		return refuse(stderr, "add", errors.New("cannot generate a seed"))
	}
	uri := approvers.URI(name, seed)
	code, err := qr.Encode([]byte(uri))
	if err != nil {
		return refuse(stderr, "add", errors.New("cannot encode the QR code"))
	}
	if err := approvers.Add(file, name, seed, multiple); err != nil {
		if errors.Is(err, approvers.ErrMultiple) {
			err = errors.New("the file already holds an approver; pass --allow-multiple to add another (the server also needs SHELL_MCP_APPROVAL_MAX_APPROVERS raised)")
		}
		return refuse(stderr, "add", err)
	}
	_, _ = io.WriteString(stdout, code.Terminal()+"\n"+uri+"\n\n"+
		"Scan the code, or enter the URI, in the approver's authenticator app. It is not shown again.\n"+
		"Keep the seed only there and in the server's secret file; never paste it into a chat.\n"+
		"The server reads the file at start: restart it to use the new approver.\n")
	audit(stderr).Info("approver enrolled", "name", name, "file", file)
	return 0
}

func approverRemove(args []string, stderr io.Writer) int {
	var name, file string
	if !approverFlags("remove", args, stderr, &name, &file, nil) {
		return 2
	}
	if err := approvers.Remove(file, name); err != nil {
		return refuse(stderr, "remove", err)
	}
	audit(stderr).Info("approver removed", "name", name, "file", file)
	return 0
}

func approverList(args []string, stdout, stderr io.Writer) int {
	var file string
	if !approverFlags("list", args, stderr, nil, &file, nil) {
		return 2
	}
	names, err := approvers.List(file)
	if err != nil {
		return refuse(stderr, "list", err)
	}
	for _, n := range names {
		_, _ = io.WriteString(stdout, n+"\n")
	}
	return 0
}

// refuse prints a one-line reason. Every error here is built from fixed
// text and line numbers, never from the file's content or the seed.
func refuse(stderr io.Writer, cmd string, err error) int {
	_, _ = fmt.Fprintf(stderr, "shell-mcp: approver %s: %v\n", cmd, err)
	return 1
}

// audit is the JSON logger for the command's audit lines (handoff §6.8).
func audit(stderr io.Writer) *slog.Logger { return slog.New(slog.NewJSONHandler(stderr, nil)) }
