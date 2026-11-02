//go:build linux

// Package serverinit is `shell-mcp init` (handoff §4.C): the server's bearer
// token, SSH key pair and approvers file, created in one directory owned by
// the server's uid, through the setup tools' write helper (a temp file in
// the directory, owner and mode on its descriptor, rename, read-back), never
// overwritten and never printed. It runs as root on the host or as the
// server's uid in its image, and starts no process.
package serverinit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/tyler-rich/shell-mcp/internal/approval/approvers"
	"github.com/tyler-rich/shell-mcp/internal/approval/qr"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
)

// The files init manages, under --dir.
const (
	TokenFile     = "mcp_token"
	KeyFile       = "ssh_key"
	PubFile       = "ssh_key.pub"
	ApproversFile = "approvers"
)

// DefaultID is the image's user and group.
const DefaultID = 65532

const (
	tokenBytes  = 32 // 43 characters of base64url
	tokenChars  = 43
	keyComment  = "shell-mcp"
	fileLimit   = 64 << 10
	dirMode     = fs.FileMode(0o700)
	secretMode  = fs.FileMode(0o600)
	publicMode  = fs.FileMode(0o644)
	placeholder = "<43 random characters>"
)

// Options are init's flags.
type Options struct {
	Dir      string
	UID, GID uint32
	Approver string
	DryRun   bool
}

// Usage is init's usage text.
const Usage = `usage: shell-mcp init --dir <dir> [--uid <n>] [--gid <n>] [--approver <name>] [--dry-run]

Creates the server's secrets in <dir> (0700), owned by --uid:--gid (default
65532:65532, the image's user): mcp_token and ssh_key (0600), ssh_key.pub
(0644) and, with --approver, the approvers file (0600). Existing files are
kept, never overwritten. Run it as root on the host, or as --uid in the image.
`

// ParseFlags parses init's flags. Every error is a usage error.
func ParseFlags(args []string) (*Options, error) {
	o := &Options{UID: DefaultID, GID: DefaultID}
	set := flag.NewFlagSet("init", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&o.Dir, "dir", "", "")
	id := func(dst *uint32) func(string) error {
		return func(s string) error {
			n, err := strconv.ParseUint(s, 10, 32)
			if err != nil {
				return errors.New("must be a decimal id")
			}
			*dst = uint32(n)
			return nil
		}
	}
	set.Func("uid", "", id(&o.UID))
	set.Func("gid", "", id(&o.GID))
	set.StringVar(&o.Approver, "approver", "", "")
	set.BoolVar(&o.DryRun, "dry-run", false, "")
	if err := set.Parse(args); err != nil {
		return nil, err
	}
	switch {
	case set.NArg() != 0:
		return nil, fmt.Errorf("unexpected argument %q", set.Arg(0))
	case o.Dir == "":
		return nil, errors.New("missing --dir")
	case o.Approver != "" && !approvers.ValidName(o.Approver):
		return nil, errors.New("--approver must match ^[a-z][a-z0-9-]{0,31}$")
	}
	return o, nil
}

// Files is what init reads and changes on the filesystem.
type Files interface {
	State(path string, limit int64) (setupx.FileState, error)
	WriteFile(path string, data []byte, mode fs.FileMode, owner setupx.Owner) error
	Mkdir(path string, mode fs.FileMode, owner setupx.Owner) error
	Remove(path string) error
	RemoveLeftovers(target string) ([]string, error)
}

// RealFiles is the real filesystem; tempOwner owns a killed run's temp files.
func RealFiles(tempOwner uint32) Files { return setupx.Disk{TempOwner: tempOwner} }

// Env is what init takes from the process.
type Env struct {
	Euid, Egid int
	Groups     []int
	Rand       io.Reader
	IsTerminal func(io.Writer) bool
}

// file is one managed file: what is there, and what the run does with it.
type file struct {
	name   string
	path   string
	mode   fs.FileMode
	state  setupx.FileState
	create bool
	data   []byte
	shown  string // the dry run's stand-in for data
}

type run struct {
	o     *Options
	h     Files
	env   *Env
	r     *setupx.Report
	owner setupx.Owner
	files map[string]*file
	pub   ssh.PublicKey // the kept key's
	list  []approvers.Approver
}

// Run is shell-mcp init.
func Run(o *Options, h Files, env *Env, stdout, stderr io.Writer) int {
	ru := &run{o: o, h: h, env: env, r: &setupx.Report{W: stdout}, owner: setupx.Owner{UID: o.UID, GID: o.GID}, files: map[string]*file{}}
	createDir := ru.checkIdentity() && ru.checkDir()
	if ru.r.Failures == 0 {
		ru.checkFiles()
	}
	if ru.r.Failures > 0 {
		_, _ = fmt.Fprintln(stdout, "init: refused; nothing written")
		return ExitFail
	}
	enrol := o.Approver != "" && !ru.enrolled(o.Approver)
	if o.DryRun {
		return ru.dryRun(createDir, enrol, stdout)
	}
	uri, code, err := ru.generate(enrol)
	if err != nil {
		ru.r.Fail("%v", err)
		_, _ = fmt.Fprintln(stdout, "init: refused; nothing written")
		return ExitFail
	}
	return ru.write(createDir, uri, code, stdout, stderr)
}

// checkIdentity: who runs it, and for whom. It reports whether the
// directory checks can follow.
func (ru *run) checkIdentity() bool {
	o, env, r := ru.o, ru.env, ru.r
	if o.UID == 0 {
		r.Fail("--uid 0: the server never runs as root; give it its own uid (the image's is %d)", DefaultID)
	}
	if o.GID == 0 {
		r.Fail("--gid 0: the server's files must not belong to root's group; give it its own gid (the image's is %d)", DefaultID)
	}
	if env.Euid != 0 && int64(env.Euid) != int64(o.UID) {
		r.Fail("effective uid %d is neither 0 nor --uid %d: run init as root on the host, or as uid %d in the image, "+
			"so that every file belongs to the server", env.Euid, o.UID, o.UID)
	} else if env.Euid != 0 && !ru.inGroup(o.GID) {
		r.Fail("--gid %d is not a group of this process (gid %d): run init as %d:%d in the image", o.GID, env.Egid, o.UID, o.GID)
	}
	if !filepath.IsAbs(o.Dir) || filepath.Clean(o.Dir) != o.Dir || o.Dir == "/" {
		r.Fail("--dir %q must be an absolute, clean path other than /", o.Dir)
	}
	return r.Failures == 0
}

func (ru *run) inGroup(gid uint32) bool {
	if int64(ru.env.Egid) == int64(gid) {
		return true
	}
	for _, g := range ru.env.Groups {
		if int64(g) == int64(gid) {
			return true
		}
	}
	return false
}

// ownerOK reports whether uid may own a directory init relies on: root,
// --uid, or the process itself.
func (ru *run) ownerOK(uid uint32) bool {
	return uid == 0 || uid == ru.o.UID || int64(uid) == int64(ru.env.Euid)
}

// checkDir checks every directory above --dir (each an existing real
// directory that only its owner can write to, or a sticky one whose entry on
// the path belongs to root, --uid or the process) and --dir itself. It
// reports whether --dir is to be created.
func (ru *run) checkDir() bool {
	o, r := ru.o, ru.r
	var chain []string
	for p := filepath.Dir(o.Dir); ; p = filepath.Dir(p) {
		chain = append([]string{p}, chain...)
		if p == "/" {
			break
		}
	}
	sticky := false
	for _, p := range chain {
		st, err := ru.dirState(p)
		switch {
		case err != nil:
			r.Fail("%s: %v", p, err)
			return false
		case !st.Exists:
			r.Fail("%s does not exist: create it first (init creates only --dir itself)", p)
			return false
		case st.Mode&fs.ModeSymlink != 0:
			r.Fail("%s is a symbolic link: give --dir by its resolved path", p)
			return false
		case !st.IsDir():
			r.Fail("%s is not a directory", p)
			return false
		case sticky && !ru.ownerOK(st.Owner.UID):
			r.Fail("%s is in a directory others can write to, and is owned by uid %d, not root or %d", p, st.Owner.UID, o.UID)
			return false
		}
		sticky = false
		if st.Perm()&0o022 != 0 {
			if st.Perm()&0o1000 == 0 {
				r.Fail("%s is writable by group or other (mode %04o): whoever can write there could replace --dir; "+
					"choose a directory only its owner can write to", p, st.Perm())
				return false
			}
			sticky = true
		}
	}
	st, err := ru.dirState(o.Dir)
	switch {
	case err != nil:
		r.Fail("%s: %v", o.Dir, err)
		return false
	case !st.Exists:
		if sticky {
			r.Fail("%s would be created in a directory others can write to; choose a directory only its owner can write to", o.Dir)
		}
		return true
	case st.Mode&fs.ModeSymlink != 0:
		r.Fail("%s is a symbolic link: give --dir by its resolved path", o.Dir)
	case !st.IsDir():
		r.Fail("%s is not a directory", o.Dir)
	case st.Perm()&0o077 != 0:
		r.Fail("%s is accessible by group or other (mode %04o): chmod 700 %s", o.Dir, st.Perm(), o.Dir)
	case ru.env.Euid != 0 && st.Owner.UID != o.UID:
		r.Fail("%s is owned by %d, not --uid %d: create it on the host with install -d -o %d -g %d -m 0700 %s, then run init in the image",
			o.Dir, st.Owner.UID, o.UID, o.UID, o.GID, o.Dir)
	case ru.env.Euid == 0 && st.Owner.UID != 0 && st.Owner.UID != o.UID:
		r.Fail("%s is owned by %d, neither root nor --uid %d: chown %d:%d %s", o.Dir, st.Owner.UID, o.UID, o.UID, o.GID, o.Dir)
	case st.Owner.UID == 0:
		r.Note("%s is owned by root: the secrets form (Docker mounts each file) works, but init compose --form bind needs it "+
			"owned by %d, which can then traverse it: chown %d:%d %s", o.Dir, o.UID, o.UID, o.GID, o.Dir)
	default:
		r.OK("%s: kept (owner %s, mode %04o)", o.Dir, st.Owner, st.Perm())
	}
	return false
}

// dirState is State for a path that should be a directory: a regular file's
// content is not read, and one too large to read is reported by its kind.
func (ru *run) dirState(p string) (setupx.FileState, error) {
	st, err := ru.h.State(p, 0)
	if errors.Is(err, setupx.ErrTooLarge) {
		return setupx.FileState{Exists: true}, nil // a non-empty regular file: not a directory
	}
	return st, err
}

func (ru *run) state(name string, mode fs.FileMode) *file {
	f := &file{name: name, path: filepath.Join(ru.o.Dir, name), mode: mode}
	ru.files[name] = f
	st, err := ru.h.State(f.path, fileLimit)
	if err != nil {
		ru.r.Fail("%s: %v", f.path, err)
		return nil
	}
	f.state = st
	return f
}

// owned checks an existing file's type, owner and mode; it reports whether
// its content may be checked.
func (ru *run) owned(f *file) bool {
	st, o, r := f.state, ru.o, ru.r
	switch {
	case !st.IsRegular():
		r.Fail("%s is not a regular file: remove it and run init again", f.path)
	case st.Owner != ru.owner:
		r.Fail("%s is owned by %s, not %d:%d: chown %d:%d %s", f.path, st.Owner, o.UID, o.GID, o.UID, o.GID, f.path)
	case f.mode == secretMode && (st.Perm()&0o077 != 0 || st.Perm()&0o400 == 0):
		r.Fail("%s has mode %04o: chmod 600 %s", f.path, st.Perm(), f.path)
	case f.mode == publicMode && (st.Perm()&0o7022 != 0 || st.Perm()&0o400 == 0):
		r.Fail("%s has mode %04o: chmod 644 %s", f.path, st.Perm(), f.path)
	default:
		return true
	}
	return false
}

func (ru *run) checkFiles() {
	r := ru.r
	tok, key, pub := ru.state(TokenFile, secretMode), ru.state(KeyFile, secretMode), ru.state(PubFile, publicMode)
	appr := ru.state(ApproversFile, secretMode)
	if tok == nil || key == nil || pub == nil || appr == nil {
		return
	}
	if !tok.state.Exists {
		tok.create, tok.shown = true, placeholder
	} else if ru.owned(tok) {
		if err := checkToken(tok.state.Data); err != nil {
			r.Fail("%s %v: delete it and run init again (then give clients the new token)", tok.path, err)
		}
	}
	keyOK := false
	if !key.state.Exists {
		key.create, key.shown = true, "<new Ed25519 key>"
		if pub.state.Exists {
			r.Fail("%s exists without %s: remove it, or put the matching private key back", pub.path, key.path)
		}
	} else if ru.owned(key) {
		k, err := parseKey(key.state.Data)
		if err != nil {
			r.Fail("%s %v: delete it and run init again (then install the new ssh_key.pub on the targets)", key.path, err)
		} else {
			ru.pub, keyOK = k, true
		}
	}
	switch {
	case !pub.state.Exists:
		pub.create, pub.shown = true, "<the public half of the new key>"
		if keyOK {
			pub.data = publicLine(ru.pub)
			pub.shown = string(bytes.TrimSuffix(pub.data, []byte("\n")))
		}
	case key.state.Exists && ru.owned(pub) && keyOK:
		if err := checkPublicKey(pub.state.Data, ru.pub.Marshal()); err != nil {
			r.Fail("%s does not match %s (%v): remove it and run init again, which writes it from the key", pub.path, key.path, err)
		}
	}
	if appr.state.Exists && ru.owned(appr) {
		list, err := approvers.Parse(appr.state.Data, approvers.MaxApprovers)
		if err != nil {
			r.Fail("%s: %v", appr.path, err)
		}
		ru.list = list
	}
	if ru.o.Approver == "" || ru.enrolled(ru.o.Approver) || r.Failures > 0 {
		return
	}
	if len(ru.list) > 0 {
		r.Fail("%s already enrols an approver, and init enrols only the first: add %s with shell-mcp approver add --allow-multiple "+
			"(and raise SHELL_MCP_APPROVAL_MAX_APPROVERS)", appr.path, ru.o.Approver)
		return
	}
	if !ru.o.DryRun && !ru.env.IsTerminal(ru.r.W) {
		r.Fail("--approver: stdout is not a terminal, and the seed is shown only on one (in a container, run init with docker run --rm -it)")
	}
}

func (ru *run) enrolled(name string) bool {
	for _, a := range ru.list {
		if a.Name == name {
			return true
		}
	}
	return false
}

// generate makes every new value from the random source, before anything
// is written, and the approver's QR code, so that a seed is never written
// that cannot be shown.
func (ru *run) generate(enrol bool) (uri, code string, err error) {
	rnd := ru.env.Rand
	if f := ru.files[TokenFile]; f.create {
		b := make([]byte, tokenBytes)
		if _, rerr := io.ReadFull(rnd, b); rerr != nil {
			return "", "", errors.New("cannot read random bytes for the token")
		}
		f.data = []byte(base64.RawURLEncoding.EncodeToString(b))
	}
	if f := ru.files[KeyFile]; f.create {
		if kerr := ru.newKey(f); kerr != nil {
			return "", "", kerr
		}
	}
	if !enrol {
		return "", "", nil
	}
	seed := make([]byte, approvers.MinSeedBytes)
	if _, rerr := io.ReadFull(rnd, seed); rerr != nil {
		return "", "", errors.New("cannot read random bytes for the seed")
	}
	f := ru.files[ApproversFile]
	if f.data, err = approvers.Append(f.state.Data, ru.o.Approver, seed, false); err != nil {
		return "", "", fmt.Errorf("%s: %w", f.path, err)
	}
	f.create = true
	uri = approvers.URI(ru.o.Approver, seed)
	q, err := qr.Encode([]byte(uri))
	if err != nil {
		return "", "", errors.New("cannot encode the QR code")
	}
	return uri, q.Terminal(), nil
}

// newKey generates the Ed25519 key into f, and its public line into the
// .pub file's data.
func (ru *run) newKey(f *file) error {
	pub, priv, err := ed25519.GenerateKey(ru.env.Rand)
	if err != nil {
		return errors.New("cannot generate the key")
	}
	blk, err := ssh.MarshalPrivateKey(priv, keyComment)
	if err != nil {
		return errors.New("cannot encode the key")
	}
	f.data = pem.EncodeToMemory(blk)
	if ru.pub, err = ssh.NewPublicKey(pub); err != nil {
		return errors.New("cannot encode the public key")
	}
	ru.files[PubFile].data = publicLine(ru.pub)
	return nil
}

func publicLine(k ssh.PublicKey) []byte {
	return append(bytes.TrimSuffix(ssh.MarshalAuthorizedKey(k), []byte("\n")), []byte(" "+keyComment+"\n")...)
}

var order = []string{TokenFile, KeyFile, PubFile, ApproversFile}

func (ru *run) dryRun(createDir, enrol bool, stdout io.Writer) int {
	r := ru.r
	if createDir {
		r.OK("%s: create directory (owner %s, mode %04o)", ru.o.Dir, ru.owner, dirMode)
	}
	for _, n := range order {
		f := ru.files[n]
		switch {
		case n == ApproversFile && enrol:
			r.OK("%s: create (owner %s, mode %04o): would enrol %s; the seed is shown once, on the real run", f.path, ru.owner, f.mode, ru.o.Approver)
		case f.create:
			r.OK("%s: create (owner %s, mode %04o): %s", f.path, ru.owner, f.mode, f.shown)
		case f.state.Exists:
			r.OK("%s: kept (owner %s, mode %04o)", f.path, f.state.Owner, f.state.Perm())
		}
	}
	_, _ = fmt.Fprintln(stdout, "dry run: nothing written")
	return ExitOK
}

func (ru *run) write(createDir bool, uri, code string, stdout, stderr io.Writer) int {
	r, o := ru.r, ru.o
	audit := slog.New(slog.NewJSONHandler(stderr, nil))
	if !createDir {
		for _, n := range order {
			removed, err := ru.h.RemoveLeftovers(ru.files[n].path)
			for _, p := range removed {
				r.Warn("removed %s, a temp file a killed run left", p)
			}
			if err != nil {
				r.Fail("%v", err)
				_, _ = fmt.Fprintln(stdout, "init: refused; nothing written")
				return ExitFail
			}
		}
	}
	j := setupx.NewJournal(ru.h, nil)
	fail := func(err error) int {
		undone, failed := j.Rollback()
		for _, p := range undone {
			audit.Info("secret rolled back", "file", p)
		}
		r.Fail("%v; rolled back: every file this run created was removed", err)
		for _, e := range failed {
			r.Fail("%v", e)
		}
		_, _ = fmt.Fprintln(stdout, "init: failed")
		return ExitFail
	}
	if createDir {
		if err := j.Mkdir(o.Dir, dirMode, ru.owner, &setupx.Record{}); err != nil {
			return fail(fmt.Errorf("creating %s: %w", o.Dir, err))
		}
		r.OK("%s: create directory (owner %s, mode %04o)", o.Dir, ru.owner, dirMode)
		audit.Info("directory created", "file", o.Dir, "owner", ru.owner.String(), "mode", setupx.ModeString(dirMode))
	}
	created := 0
	for _, n := range order {
		f := ru.files[n]
		if !f.create {
			continue
		}
		if err := j.Write(f.path, f.state, f.data, f.mode, ru.owner, &setupx.Record{}); err != nil {
			return fail(err)
		}
		created++
	}
	for _, n := range order {
		f := ru.files[n]
		if !f.create && !f.state.Exists {
			continue
		}
		verb, owner, mode := "kept", f.state.Owner, f.state.Perm()
		if f.create {
			verb, owner, mode = "create", ru.owner, f.mode
		}
		r.OK("%s: %s (owner %s, mode %04o)", f.path, verb, owner, mode)
		attrs := []any{"file", f.path, "owner", owner.String(), "mode", setupx.ModeString(mode)}
		if (n == KeyFile || n == PubFile) && ru.pub != nil {
			attrs = append(attrs, "fingerprint", ssh.FingerprintSHA256(ru.pub))
		}
		if n == ApproversFile && o.Approver != "" {
			attrs = append(attrs, "approver", o.Approver)
		}
		msg := "secret kept"
		if f.create {
			msg = "secret created"
		}
		audit.Info(msg, attrs...)
	}
	if ru.pub != nil {
		r.Note("install ssh_key.pub on each target with shell-mcp-gate install --key (TARGET-SETUP §12.1); it is:")
		_, _ = fmt.Fprintf(stdout, "%s     %s\n", publicLine(ru.pub), ssh.FingerprintSHA256(ru.pub))
	}
	if uri != "" {
		_, _ = io.WriteString(stdout, "\n"+code+"\n"+uri+"\n\n"+
			"Scan the code, or enter the URI, in the approver's authenticator app. It is not shown again.\n"+
			"Keep the seed only there and in the server's secret file; never paste it into a chat.\n")
	}
	if created == 0 && !createDir {
		_, _ = fmt.Fprintln(stdout, "nothing to do: every file kept")
	} else {
		_, _ = fmt.Fprintf(stdout, "init: done: %d created\n", created)
	}
	return ExitOK
}

// parseKey returns the public half of an unencrypted Ed25519 private key.
func parseKey(data []byte) (ssh.PublicKey, error) {
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			return nil, errors.New("is encrypted with a passphrase; the server needs an unencrypted key")
		}
		return nil, errors.New("cannot be parsed as an OpenSSH private key")
	}
	var priv ed25519.PrivateKey
	switch k := raw.(type) {
	case ed25519.PrivateKey:
		priv = k
	case *ed25519.PrivateKey:
		priv = *k
	default:
		return nil, errors.New("is not an Ed25519 key (D-012)")
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, errors.New("cannot be parsed as an OpenSSH private key")
	}
	return signer.PublicKey(), nil
}

// checkToken checks a token file as the server reads it: one trailing
// newline (and a carriage return before it) removed, at least 43 characters
// and no line break.
func checkToken(data []byte) error {
	s := data
	if n := len(s); n > 0 && s[n-1] == '\n' {
		s = s[:n-1]
		if n := len(s); n > 0 && s[n-1] == '\r' {
			s = s[:n-1]
		}
	}
	if len(s) < tokenChars {
		return fmt.Errorf("is shorter than %d characters", tokenChars)
	}
	if bytes.ContainsAny(s, "\r\n") {
		return errors.New("has a line break inside")
	}
	return nil
}

// checkPublicKey requires data to be exactly one authorized-keys line, with
// no options, holding the key want (its wire form).
func checkPublicKey(data, want []byte) error {
	k, _, opts, rest, err := ssh.ParseAuthorizedKey(data)
	switch {
	case err != nil:
		return errors.New("it cannot be parsed")
	case len(opts) != 0:
		return errors.New("it carries options")
	case len(bytes.TrimSpace(rest)) != 0:
		return errors.New("it holds more than one key")
	case !bytes.Equal(k.Marshal(), want):
		return errors.New("it holds another key")
	}
	return nil
}
