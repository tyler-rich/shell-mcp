//go:build linux

package setup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/gate/policy"
	"github.com/tyler-rich/shell-mcp/internal/gate/polkit"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// The sshd -T -C connection parameters install checks with: the host name
// is a placeholder (UseDNS is off), the address the first from= entry's.
const (
	checkHost = "client.example.test"
	// otherUser is a name that is not an account, whose effective sshd
	// configuration the drop-in must leave as it was.
	otherUser = "shell-mcp-install-check"
)

// file is one file or directory install manages, with what it holds now
// and what the run does with it.
type file struct {
	path   string
	dir    bool
	data   []byte
	mode   fs.FileMode
	prev   setupx.FileState
	class  string // create, unchanged, replace
	object string
	rec    setupx.Record
}

// Result classes (TARGET-SETUP §12.4).
const (
	classCreate    = "create"
	classUnchanged = "unchanged"
	classReplace   = "replace"
)

// installer is one run of shell-mcp-gate install.
type installer struct {
	o *Options
	h Host
	r *setupx.Report
	a *setupx.Auditor

	p       *policy.Policy
	key     *PubKey
	from    []FromEntry
	journal bool // the policy has a journal section
	priv    bool // privileged.enabled
	control bool // services.control

	createGroup, createUser, createSocketGroup bool
	memberships                                []string // supplementary groups to add
	allowed                                    []string // the account's allowed supplementary groups

	memoryBytes uint64
	memoryText  string // "" for none

	sliceDir, sliceFile, polkitFile, dropIn, keysDir, keysFile file
	baseline                                                   []byte // sshd -T -C for otherUser before the drop-in
	reloadSSH                                                  string // the unit to reload, "" when the socket starts sshd
	warnedRoots                                                []string
}

// Install runs shell-mcp-gate install (TARGET-SETUP §12.1) on h, printing
// to stdout and auditing through a. It returns the exit code: 0 done, 1
// refused or failed.
func Install(o *Options, h Host, stdout io.Writer, a *setupx.Auditor) int {
	in := &installer{o: o, h: h, r: &setupx.Report{W: stdout}, a: a}
	return in.run()
}

func (in *installer) refuse(object, reason, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	in.r.Fail("%s", msg)
	in.a.Log(&setupx.Record{Action: setupx.ActionRefuse, Object: object, Reason: reason, Detail: msg})
}

func (in *installer) run() int {
	o, r := in.o, in.r
	mode := ""
	if o.DryRun {
		mode = " (dry run: nothing is changed; only commands that read are run)"
	}
	r.Info("shell-mcp-gate install%s: policy %s, principal %s, account %s (%d:%d)", mode, o.Policy, o.Principal, o.User, o.UID, o.GID)
	if _, ok := in.h.LookupEnv("SSH_ORIGINAL_COMMAND"); ok {
		in.refuse("process", "forced_command", "SSH_ORIGINAL_COMMAND is set: install never runs as an SSH forced command")
		return 1
	}
	if in.h.Euid() != 0 {
		in.refuse("process", "not_root", "install runs as root only (effective uid %d)", in.h.Euid())
		return 1
	}
	in.checks()
	if r.Failures > 0 {
		r.Info("%d problem(s): install refused; nothing was changed", r.Failures)
		return 1
	}
	if o.DryRun {
		in.describe()
		r.OK("dry run: every check passed; the run above would be made")
		return 0
	}
	return in.apply()
}

// checks is step 1 (TARGET-SETUP §12.1): everything is checked, and every
// problem reported, before anything is written.
func (in *installer) checks() {
	in.checkBinaries()
	in.checkPolicy()
	in.checkKey()
	in.checkFrom()
	in.checkSSHD()
	in.checkAccount()
	in.checkSlice()
	in.checkPolkit()
	in.checkSSHFiles()
	in.checkOwnerScan()
	in.checkReload()
}

func (in *installer) checkBinaries() {
	exe, err := in.h.Executable()
	if err != nil || exe != GatePath {
		in.refuse("binary", "binary_path", "the running binary is %s, not %s: run the installed gate (TARGET-SETUP §3), which the forced command names", exe, GatePath)
	}
	if err := in.h.CheckChain(GatePath); err != nil {
		in.refuse("binary", "binary_insecure", "%s: %v (it and every directory above it must be root's and not group- or world-writable)", GatePath, err)
	}
	progs := []string{setupx.Groupadd, setupx.Useradd, setupx.Usermod, setupx.Sshd}
	if !in.o.NoReload {
		progs = append(progs, setupx.Systemctl)
	}
	for _, p := range progs {
		if err := in.h.CheckChain(p); err != nil {
			in.refuse("binary", "program_insecure", "%s: %v", p, err)
		}
	}
}

func (in *installer) checkPolicy() {
	o := in.o
	ok := true
	if err := CheckSafePath("--policy", o.Policy); err != nil {
		in.refuse("policy", "policy_path", "%v", err)
		ok = false
	}
	if !ValidPrincipal(o.Principal) {
		in.refuse("key", "principal", "--principal %q must match ^[a-z][a-z0-9-]{0,31}$ (sshd runs the forced command through /bin/sh)", o.Principal)
	}
	if err := CheckSafePath("--home", o.Home); err != nil {
		in.refuse("account", "home", "%v", err)
		ok = false
	}
	if !ok {
		return
	}
	p, err := in.h.LoadPolicy(o.Policy, o.Home)
	if err != nil {
		for _, l := range strings.Split(err.Error(), "\n") {
			in.refuse("policy", "policy_invalid", "policy: %s", l)
		}
		return
	}
	in.p = p
	in.r.OK("policy %s: sha256 %s, max_tier %s", o.Policy, p.SHA256, p.MaxTier)
	in.journal = len(p.Journal.Units) > 0
	in.priv = p.Privileged.Enabled
	in.control = len(p.Services.ControlUnits) > 0
	abi, err := in.h.CheckSandbox(p)
	if err != nil {
		in.refuse("policy", "sandbox", "sandbox: %v (kernel Landlock ABI %d, mode %s)", err, abi, p.Sandbox.Landlock)
	} else {
		in.r.OK("sandbox: kernel Landlock ABI %d, mode %s", abi, p.Sandbox.Landlock)
	}
}

// hostKey is one of the host's own public keys.
type hostKey struct {
	path, typ, fingerprint string
	marshal                []byte
}

// hostKeys reads /etc/ssh/ssh_host_*_key.pub.
func hostKeys(h setupx.Host) ([]hostKey, error) {
	names, err := h.ReadDir(SSHDir)
	if err != nil {
		return nil, err
	}
	var out []hostKey
	for _, n := range names {
		if !strings.HasPrefix(n, "ssh_host_") || !strings.HasSuffix(n, "_key.pub") {
			continue
		}
		p := SSHDir + "/" + n
		st, err := h.State(p, maxKeyFile)
		if err != nil || !st.IsRegular() {
			continue
		}
		f := strings.Fields(string(st.Data))
		if len(f) < 2 {
			continue
		}
		k, err := parseAnyKey(f[1])
		if err != nil || k.Type() != f[0] {
			continue
		}
		out = append(out, hostKey{path: p, typ: k.Type(), fingerprint: sshFingerprint(k), marshal: k.Marshal()})
	}
	return out, nil
}

func (in *installer) checkKey() {
	st, err := in.h.State(in.o.Key, maxKeyFile)
	switch {
	case err != nil:
		in.refuse("key", "key_file", "--key %s: %v", in.o.Key, err)
		return
	case !st.IsRegular():
		in.refuse("key", "key_file", "--key %s is not a regular file", in.o.Key)
		return
	}
	k, err := ParsePubFile(st.Data)
	if err != nil {
		in.refuse("key", "key_invalid", "--key %s: %v", in.o.Key, err)
		return
	}
	hks, err := hostKeys(in.h)
	if err != nil {
		in.refuse("key", "host_keys", "cannot read the host's keys in %s: %v", SSHDir, err)
		return
	}
	for _, hk := range hks {
		if bytes.Equal(hk.marshal, k.Marshal) {
			in.refuse("key", "host_key", "--key is this host's own host key %s; give the server's ssh_key.pub", hk.path)
			return
		}
	}
	in.key = k
	in.r.OK("key %s: %s %s", in.o.Key, KeyType, k.Fingerprint)
}

func (in *installer) checkFrom() {
	es, warns, err := ParseFrom(in.o.From)
	if err != nil {
		in.refuse("key", "from", "--from: %v", err)
		return
	}
	in.from = es
	for _, w := range warns {
		in.r.Warn("%s", w)
		in.a.Log(&setupx.Record{Action: setupx.ActionWarn, Object: "key", Reason: "from_wide", Detail: w})
	}
	in.r.OK("from=%q", FromList(es))
}

// sshdT runs sshd -T (with -C spec when given) and parses it.
func (in *installer) sshdT(spec string) (m map[string][]string, raw []byte, err error) {
	args := []string{"-T"}
	if spec != "" {
		args = append(args, "-C", spec)
	}
	out, err := in.h.Run(setupx.Sshd, args...)
	if err != nil {
		return nil, nil, err
	}
	if !out.OK() {
		return nil, nil, fmt.Errorf("sshd %s exited %d: %s", strings.Join(args, " "), out.Exit, firstLine(out.Stderr))
	}
	m, err = ParseSshdT(out.Stdout)
	return m, out.Stdout, err
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func (in *installer) checkSSHD() {
	m, _, err := in.sshdT("")
	if err != nil {
		in.refuse("sshd", "sshd_config", "sshd -T: %v", err)
		return
	}
	if v := m["strictmodes"]; len(v) != 1 || v[0] != "yes" {
		in.refuse("sshd", "strictmodes", "sshd -T reports strictmodes %q; StrictModes must stay yes (TARGET-SETUP §7)", strings.Join(v, " "))
		return
	}
	in.r.OK("sshd: strictmodes yes")
}

// state reads a managed path.
func (in *installer) state(p string) (setupx.FileState, bool) {
	st, err := in.h.State(p, maxManagedFile)
	if err != nil {
		in.refuse("file", "file_unreadable", "%s: %v", p, err)
		return st, false
	}
	return st, true
}

// owned classifies an owned file (handoff §3.2): absent → create,
// identical → unchanged, anything else refused with a diff.
func (in *installer) owned(p string, data []byte, mode fs.FileMode, object string) file {
	f := file{path: p, data: data, mode: mode, object: object}
	st, ok := in.state(p)
	if !ok {
		return f
	}
	f.prev = st
	switch {
	case !st.Exists:
		f.class = classCreate
	case st.Same(data, mode, setupx.Root):
		f.class = classUnchanged
	case !st.IsRegular():
		in.refuse("file", "file_differs", "%s exists and is not a regular file; remove it and run again", p)
	case st.Perm() != mode || st.Owner != setupx.Root:
		in.refuse("file", "file_differs", "%s is %s %04o, not root:root %04o; remove it (or fix it) and run again", p, st.Owner, st.Perm(), mode)
	default:
		in.refuse("file", "file_differs", "%s exists with other content; install never overwrites it: remove it (or revert the edit) and run again", p)
		in.r.Block(setupx.UnifiedDiff(p+" (on the host)", p+" (install)", st.Data, data))
	}
	return f
}

// ownedDir classifies a directory install creates: absent → create, a
// root:root directory of exactly mode → unchanged, anything else refused.
func (in *installer) ownedDir(p string, mode fs.FileMode) file {
	f := file{path: p, dir: true, mode: mode, object: "directory"}
	st, ok := in.state(p)
	if !ok {
		return f
	}
	f.prev = st
	switch {
	case !st.Exists:
		f.class = classCreate
	case st.IsDir() && st.Owner == setupx.Root && st.Perm() == mode:
		f.class = classUnchanged
	default:
		in.refuse("file", "directory_differs", "%s exists but is not a root:root directory of mode %04o (%s %s); fix it and run again", p, mode, st.Owner, st.Mode)
	}
	return f
}

// requireDir requires an existing directory that passes the chain rule.
func (in *installer) requireDir(p, why string) bool {
	st, ok := in.state(p)
	if !ok {
		return false
	}
	if !st.IsDir() {
		in.refuse("file", "directory_missing", "%s does not exist or is not a directory; %s", p, why)
		return false
	}
	if err := in.h.CheckChain(p); err != nil {
		in.refuse("file", "directory_insecure", "%s: %v (it and every directory above it must be root's and not group- or world-writable)", p, err)
		return false
	}
	return true
}

func (in *installer) checkAccount() {
	o := in.o
	for _, c := range []struct {
		what string
		id   uint32
	}{{"--uid", o.UID}, {"--gid", o.GID}} {
		if why := idRefusal(c.what, c.id); why != "" {
			in.refuse("account", "id_range", "%s", why)
		}
	}
	if !ValidName(o.User) {
		in.refuse("account", "name", "--user %q is not a plain account name (^[a-z_][a-z0-9_-]{0,31}$)", o.User)
		return
	}
	if slices.Contains(install.DeniedGroups, o.User) {
		in.refuse("account", "name", "--user %q is the name of a privileged group", o.User)
		return
	}
	db, err := in.h.Accounts()
	if err != nil {
		in.refuse("account", "accounts", "cannot read the user and group databases: %v", err)
		return
	}
	// The primary group: named after the account, with --gid.
	if g, ok := db.Group(o.User); ok {
		if g.GID != o.GID {
			in.refuse("account", "group_gid", "group %s exists with gid %d, not --gid %d", o.User, g.GID, o.GID)
		}
	} else {
		if gs := db.GroupsByGID(o.GID); len(gs) > 0 {
			in.refuse("account", "gid_in_use", "gid %d is already group %s's; choose an unused gid", o.GID, gs[0].Name)
		}
		in.createGroup = true
	}
	// The account.
	if u, ok := db.User(o.User); ok {
		switch {
		case u.UID != o.UID:
			in.refuse("account", "account_differs", "account %s exists with uid %d, not --uid %d", o.User, u.UID, o.UID)
		case u.GID != o.GID:
			in.refuse("account", "account_differs", "account %s exists with primary gid %d, not --gid %d", o.User, u.GID, o.GID)
		case u.Home != o.Home:
			in.refuse("account", "account_differs", "account %s has the home %s, not --home %s", o.User, u.Home, o.Home)
		case u.Shell != ServiceShell:
			in.refuse("account", "account_differs", "account %s has the shell %q; it must be %s (sshd runs the forced command through it; nologin or false refuse every login)", o.User, u.Shell, ServiceShell)
		}
		if st, ok := in.state(o.Home); ok && (!st.IsDir() || st.Owner.UID != o.UID) {
			in.refuse("account", "home", "account %s's home %s is not a directory it owns", o.User, o.Home)
		}
	} else {
		if us := db.UsersByUID(o.UID); len(us) > 0 {
			in.refuse("account", "uid_in_use", "uid %d is already account %s's; choose an unused uid", o.UID, us[0].Name)
		}
		if st, ok := in.state(o.Home); ok && st.Exists {
			in.refuse("account", "home", "the home %s exists already but the account does not; remove it or choose another --home", o.Home)
		}
		in.createUser = true
	}
	if st, ok := in.state(ServiceShell); ok && !st.Exists {
		in.refuse("account", "shell", "%s does not exist; the account's shell must be a real POSIX shell", ServiceShell)
	}
	// The socket group: given exactly when the policy forwards to the helper.
	switch {
	case in.p == nil:
	case in.priv && !o.HasSocket:
		in.refuse("account", "socket_group", "the policy has privileged.enabled: give --socket-group and --socket-gid (the helper's socket group)")
	case !in.priv && o.HasSocket:
		in.refuse("account", "socket_group", "--socket-group and --socket-gid are for a policy with privileged.enabled, which this one does not have")
	case in.priv:
		in.checkSocketGroup(db)
	}
	if in.journal {
		if _, ok := db.Group(JournalGroup); !ok {
			in.refuse("account", "journal_group", "the policy has a journal section but the host has no %s group", JournalGroup)
		}
		in.allowed = append(in.allowed, JournalGroup)
	}
	if in.priv && o.HasSocket {
		in.allowed = append(in.allowed, o.SocketGroup)
	}
	// Supplementary groups (handoff §7 Q5): only the allowed ones; never
	// removed by install.
	have := map[string]bool{}
	for _, g := range db.Supplementary(o.User) {
		have[g.Name] = true
		switch {
		case slices.Contains(install.DeniedGroups, g.Name):
			in.refuse("account", "privileged_group", "account %s is a member of %s, a privileged group the gate refuses (D-020); remove the membership and run again", o.User, g.Name)
		case g.GID == 0:
			in.refuse("account", "privileged_group", "account %s is a member of group %s with gid 0; remove the membership and run again", o.User, g.Name)
		case !slices.Contains(in.allowed, g.Name):
			in.refuse("account", "supplementary_group", "account %s is a member of %s; its only supplementary groups may be %s; remove the membership and run again", o.User, g.Name, allowedText(in.allowed))
		}
	}
	for _, g := range in.allowed {
		if !have[g] {
			in.memberships = append(in.memberships, g)
		}
	}
}

func allowedText(a []string) string {
	if len(a) == 0 {
		return "none (this policy has neither a journal section nor privileged.enabled)"
	}
	return strings.Join(a, " and ")
}

func (in *installer) checkSocketGroup(db *setupx.Accounts) {
	o := in.o
	switch {
	case !ValidName(o.SocketGroup) || o.SocketGroup == o.User || slices.Contains(install.DeniedGroups, o.SocketGroup) || o.SocketGroup == JournalGroup:
		in.refuse("account", "socket_group", "--socket-group %q must be a plain group name of its own", o.SocketGroup)
		return
	case o.SocketGID == o.GID:
		in.refuse("account", "socket_group", "--socket-gid %d is the account's own --gid", o.SocketGID)
		return
	}
	if why := idRefusal("--socket-gid", o.SocketGID); why != "" {
		in.refuse("account", "id_range", "%s", why)
	}
	if g, ok := db.Group(o.SocketGroup); ok {
		if g.GID != o.SocketGID {
			in.refuse("account", "socket_group", "group %s exists with gid %d, not --socket-gid %d", o.SocketGroup, g.GID, o.SocketGID)
		}
		return
	}
	if gs := db.GroupsByGID(o.SocketGID); len(gs) > 0 {
		in.refuse("account", "gid_in_use", "--socket-gid %d is already group %s's; choose an unused gid", o.SocketGID, gs[0].Name)
	}
	in.createSocketGroup = true
}

func (in *installer) checkSlice() {
	o := in.o
	switch o.MemoryMax {
	case "none":
		in.r.Warn("--memory-max none: no slice drop-in, so the account's processes together have no memory bound (TARGET-SETUP §4)")
		return
	case "":
		if in.p == nil {
			return
		}
		in.memoryText = DefaultSize(in.p.Limits.MaxMemoryMB)
		in.memoryBytes, _, _ = ParseSize(in.memoryText)
	default:
		b, t, err := ParseSize(o.MemoryMax)
		if err != nil {
			in.refuse("file", "memory_max", "--memory-max: %v", err)
			return
		}
		in.memoryBytes, in.memoryText = b, t
	}
	if total, err := in.h.MemTotal(); err == nil && in.memoryBytes > total {
		in.r.Warn("MemoryMax=%s is above this host's memory (%d MiB): the bound would never act", in.memoryText, total>>20)
	}
	if !in.requireDir(SystemdDir, "systemd's unit directory") {
		return
	}
	in.sliceDir = in.ownedDir(SliceDir(o.UID), 0o755)
	in.sliceFile = in.owned(SliceDir(o.UID)+"/"+sliceDropIn, SliceDropIn(in.memoryText), 0o644, "slice")
}

func (in *installer) checkPolkit() {
	if !in.control {
		return
	}
	if !in.requireDir(PolkitDir, "install polkitd (TARGET-SETUP §8); install never creates the directory") {
		return
	}
	rule, err := polkit.Rule(&polkit.Spec{User: in.o.User, Units: in.p.Services.ControlUnits, Verbs: in.p.Services.ControlVerbs, PolicySHA256: in.p.SHA256})
	if err != nil {
		in.refuse("file", "polkit", "polkit rule: %v", err)
		return
	}
	in.polkitFile = in.owned(PolkitRule, []byte(rule), 0o644, "polkit")
}

func (in *installer) checkSSHFiles() {
	o := in.o
	if !in.requireDir(SSHDir, "") || !in.requireDir(SSHDropInDir, "OpenSSH's drop-in directory must exist and be included by sshd_config") {
		return
	}
	// The drop-in: one service account per host.
	want := DropIn(o.User)
	if st, ok := in.state(SSHDropIn); ok && st.IsRegular() && !bytes.Equal(st.Data, want) {
		if u := dropInUser(st.Data); u != "" && u != o.User {
			in.refuse("file", "dropin_other_account", "%s is for account %s; one service account per host", SSHDropIn, u)
			return
		}
	}
	in.dropIn = in.owned(SSHDropIn, want, 0o644, "sshd")
	in.keysDir = in.ownedDir(KeysDir, 0o755)
	in.checkKeysFile()
}

// checkKeysFile plans the keys file (line-keyed, handoff §3.2): every
// existing line parsed and checked, the key's own line added, kept or, with
// --replace-key, rewritten.
func (in *installer) checkKeysFile() {
	o := in.o
	p := KeysFile(o.User)
	st, ok := in.state(p)
	if !ok || in.key == nil || in.from == nil || !ValidPrincipal(o.Principal) || CheckSafePath("--policy", o.Policy) != nil {
		return
	}
	want := RenderKeyLine(FromList(in.from), o.Policy, o.Principal, in.key)
	in.keysFile = file{path: p, mode: 0o644, prev: st, object: "key",
		rec: setupx.Record{User: o.User, Fingerprint: in.key.Fingerprint, Principal: o.Principal, Policy: o.Policy, PolicySHA256: policySHA(in.p)}}
	if !st.Exists {
		in.keysFile.class, in.keysFile.data = classCreate, []byte(want+"\n")
		return
	}
	if !st.IsRegular() || st.Owner != setupx.Root || st.Perm() != 0o644 {
		in.refuse("file", "keys_file_insecure", "%s is %s %04o; it must be a regular root:root 0644 file (StrictModes accepts one the account owns, which could rewrite its own command=)", p, st.Owner, st.Perm())
		return
	}
	lines := strings.Split(strings.TrimSuffix(string(st.Data), "\n"), "\n")
	if len(st.Data) == 0 {
		lines = nil
	}
	seen := map[string]int{}
	found, bad := -1, false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		kl, err := ParseKeyLine(l)
		var k *PubKey
		if err == nil {
			k, err = CheckLine(kl)
		}
		if err != nil {
			in.refuse("key", "keys_file_line", "%s line %d: %v; install keeps only lines it can check: fix or remove the line and run again", p, i+1, err)
			bad = true
			continue
		}
		if j, dup := seen[k.Fingerprint]; dup {
			in.refuse("key", "keys_file_line", "%s lines %d and %d hold the same key", p, j+1, i+1)
			bad = true
		}
		seen[k.Fingerprint] = i
		if k.Fingerprint == in.key.Fingerprint {
			found = i
		}
	}
	if bad {
		return
	}
	switch {
	case found < 0:
		lines = append(lines, want)
		in.keysFile.class = classReplace
	case lines[found] == want:
		in.keysFile.class = classUnchanged
	case o.ReplaceKey:
		lines[found] = want
		in.keysFile.class = classReplace
	default:
		in.refuse("key", "key_options_differ", "%s line %d holds this key with other options; run with --replace-key to rewrite that line", p, found+1)
		return
	}
	in.keysFile.data = []byte(strings.Join(lines, "\n") + "\n")
}

func policySHA(p *policy.Policy) string {
	if p == nil {
		return ""
	}
	return p.SHA256
}

func (in *installer) checkOwnerScan() {
	o := in.o
	var uids, gids []uint32
	if in.createUser {
		uids = append(uids, o.UID)
	}
	if in.createGroup {
		gids = append(gids, o.GID)
	}
	if in.createSocketGroup {
		gids = append(gids, o.SocketGID)
	}
	if len(uids)+len(gids) == 0 {
		if o.OwnerScanPaths != nil {
			in.refuse("owner_scan", "nothing_to_scan", "--owner-scan-paths: the account and its groups exist already, so there is nothing to scan for; leave the flag out")
		}
		return
	}
	if in.r.Failures > 0 {
		// The ids are refused already; a scan would only take time.
		return
	}
	for _, p := range o.OwnerScanPaths {
		st, ok := in.state(p)
		if ok && (!st.IsDir() || st.Mode&fs.ModeSymlink != 0) {
			in.refuse("owner_scan", "scan_path", "--owner-scan-paths: %s is not an existing directory (a symlink is refused)", p)
			return
		}
	}
	res, err := in.h.OwnerScan(uids, gids, o.OwnerScanPaths)
	if err != nil {
		in.refuse("owner_scan", "scan_failed", "owner scan: %v", err)
		return
	}
	rec := setupx.Record{Action: setupx.ActionRun, Object: "owner_scan", OwnerScan: "full", Paths: res.Walked}
	if o.OwnerScanPaths != nil {
		rec.OwnerScan = "narrowed"
		in.r.Warn("owner scan narrowed to %s; not scanned: %s", strings.Join(o.OwnerScanPaths, " "), limited(res.NotCovered, 20))
	}
	if len(res.Skipped) > 0 {
		in.r.Info("owner scan: skipped (pseudo or network filesystems): %s", limited(res.Skipped, 20))
	}
	if res.Hit != "" {
		rec.Action, rec.Reason, rec.Detail = setupx.ActionRefuse, "id_owns_files", res.Hit
		in.a.Log(&rec)
		in.r.Fail("%s is owned by one of the new ids (uid %v, gid %v); choose ids that own nothing on this host (TARGET-SETUP §4)", res.Hit, uids, gids)
		return
	}
	in.a.Log(&rec)
	in.r.OK("owner scan (%s): nothing on %d filesystem(s) is owned by uid %v or gid %v", rec.OwnerScan, len(res.Walked), uids, gids)
}

func limited(l []string, n int) string {
	if len(l) == 0 {
		return "nothing"
	}
	if len(l) > n {
		return strings.Join(l[:n], ", ") + fmt.Sprintf(" and %d more", len(l)-n)
	}
	return strings.Join(l, ", ")
}

// checkReload is step 1's reload check: unless --no-reload, systemd must
// run, and when the drop-in changes, ssh.service must be active (reload)
// or ssh.socket (no reload needed: the next connection starts sshd).
// Before the drop-in changes, the other name's effective configuration is
// recorded, to compare after.
func (in *installer) checkReload() {
	if in.r.Failures > 0 {
		return
	}
	if in.dropIn.class != classUnchanged {
		_, base, err := in.sshdT(in.otherSpec())
		if err != nil {
			in.refuse("sshd", "sshd_config", "sshd -T -C %s: %v", in.otherSpec(), err)
			return
		}
		in.baseline = base
	}
	if in.o.NoReload {
		return
	}
	if !in.h.SystemdRunning() {
		in.refuse("sshd", "no_systemd", "systemd is not running as PID 1, so install cannot reload; run with --no-reload and reload sshd and systemd yourself")
		return
	}
	if in.dropIn.class == classUnchanged {
		return
	}
	switch {
	case in.active("ssh.service"):
		in.reloadSSH = "ssh.service"
	case in.active("ssh.socket"):
		in.reloadSSH = ""
	default:
		in.refuse("sshd", "no_sshd", "neither ssh.service nor ssh.socket is active, so the new drop-in would not be applied; start sshd, or run with --no-reload and reload it yourself")
	}
}

func (in *installer) active(unit string) bool {
	out, err := in.h.Run(setupx.Systemctl, "is-active", "--quiet", unit)
	return err == nil && out.OK()
}

func (in *installer) checkSpec() string {
	return fmt.Sprintf("user=%s,host=%s,addr=%s", in.o.User, checkHost, in.from[0].Prefix.Addr())
}

func (in *installer) otherSpec() string {
	return fmt.Sprintf("user=%s,host=%s,addr=%s", otherUser, checkHost, in.from[0].Prefix.Addr())
}

// accountRuns are step 2's programs, in order.
func (in *installer) accountRuns() [][]string {
	o := in.o
	var runs [][]string
	if in.createGroup {
		runs = append(runs, []string{setupx.Groupadd, "--gid", strconv.FormatUint(uint64(o.GID), 10), o.User})
	}
	if in.createSocketGroup {
		runs = append(runs, []string{setupx.Groupadd, "--gid", strconv.FormatUint(uint64(o.SocketGID), 10), o.SocketGroup})
	}
	if in.createUser {
		runs = append(runs, []string{setupx.Useradd, "--uid", strconv.FormatUint(uint64(o.UID), 10), "--gid", strconv.FormatUint(uint64(o.GID), 10),
			"--home-dir", o.Home, "--create-home", "--shell", ServiceShell, o.User},
			[]string{setupx.Usermod, "-L", o.User})
	}
	for _, g := range in.memberships {
		runs = append(runs, []string{setupx.Usermod, "-aG", g, o.User})
	}
	return runs
}

// managed is every file and directory step, in the order written: the key
// line last.
func (in *installer) managed() []*file {
	var out []*file
	for _, f := range []*file{&in.sliceDir, &in.sliceFile, &in.polkitFile, &in.dropIn, &in.keysDir, &in.keysFile} {
		if f.path != "" {
			out = append(out, f)
		}
	}
	return out
}

// describe prints the run for --dry-run (TARGET-SETUP §12.4).
func (in *installer) describe() {
	r := in.r
	for _, f := range in.managed() {
		if f.dir {
			continue
		}
		if names, err := in.h.ReadDir(path.Dir(f.path)); err == nil {
			for _, n := range names {
				if setupx.IsTempFor(n, path.Base(f.path)) {
					r.Note("would remove %s/%s, a temp file a killed run left", path.Dir(f.path), n)
				}
			}
		}
	}
	for _, c := range in.accountRuns() {
		r.Info("would run %s", strings.Join(c, " "))
	}
	in.describeFiles(in.sliceDir, in.sliceFile)
	if !in.o.NoReload && in.memoryText != "" {
		if in.sliceFile.class != classUnchanged {
			r.Info("would run %s daemon-reload", setupx.Systemctl)
		}
		r.Info("would check %s show -p MemoryMax -p MemorySwapMax user-%d.slice", setupx.Systemctl, in.o.UID)
	}
	r.Info("would run %s check-policy --policy %s as %s (uid %d, gid %d, groups %s)", GatePath, in.o.Policy, in.o.User, in.o.UID, in.o.GID, allowedText(in.allowed))
	in.describeFiles(in.polkitFile, in.dropIn, in.keysDir, in.keysFile)
	r.Info("would check %s -t and %s -T -C %s and -C %s", setupx.Sshd, setupx.Sshd, in.checkSpec(), in.otherSpec())
	in.describeReload()
}

func (in *installer) describeFiles(files ...file) {
	for i := range files {
		f := &files[i]
		if f.path == "" {
			continue
		}
		kind := "file"
		if f.dir {
			kind = "directory"
		}
		in.r.Info("%s %s root:root %04o: %s", kind, f.path, f.mode, f.class)
		if !f.dir && f.class != classUnchanged {
			if f.class == classReplace {
				in.r.Block(setupx.UnifiedDiff(f.path+" (on the host)", f.path+" (install)", f.prev.Data, f.data))
			} else {
				in.r.Block(string(f.data))
			}
		}
	}
}

func (in *installer) describeReload() {
	switch {
	case in.dropIn.class == classUnchanged:
		in.r.Info("sshd: the drop-in is unchanged, no reload")
	case in.o.NoReload:
		in.r.Info("would print the reload to run (--no-reload)")
	case in.reloadSSH != "":
		in.r.Info("would run %s reload %s", setupx.Systemctl, in.reloadSSH)
	default:
		in.r.Info("sshd: ssh.socket starts sshd per connection; no reload needed")
	}
}

// apply makes the run (steps 2 to 9), rolling every file back on a
// failure after the first write.
func (in *installer) apply() int {
	o, r, h := in.o, in.r, in.h
	j := setupx.NewJournal(h, in.a)
	reloaded := false
	fail := func(format string, a ...any) int {
		r.Fail(format, a...)
		in.a.Log(&setupx.Record{Action: setupx.ActionRefuse, Object: "install", Reason: "check_failed", Detail: fmt.Sprintf(format, a...)})
		in.rollback(j, reloaded)
		return 1
	}
	for _, f := range in.managed() {
		if f.dir {
			continue
		}
		left, err := h.RemoveLeftovers(f.path)
		for _, l := range left {
			r.Warn("removed %s, a temp file a killed run left", l)
		}
		if err != nil {
			return fail("%v", err)
		}
	}
	// Step 2: groups, the account, its lock and its memberships.
	for _, c := range in.accountRuns() {
		out, err := h.Run(c[0], c[1:]...)
		if err == nil && !out.OK() {
			err = fmt.Errorf("exit %d: %s", out.Exit, firstLine(out.Stderr))
		}
		if err != nil {
			return fail("%s: %v", strings.Join(c, " "), err)
		}
		r.OK("ran %s", strings.Join(c, " "))
		in.a.Log(&setupx.Record{Action: setupx.ActionRun, Object: "account", User: o.User, Command: c})
	}
	cred, err := in.verifyAccount()
	if err != nil {
		return fail("%v", err)
	}
	// Step 3: the slice drop-in, systemd reloaded, its values in force.
	if err := in.write(j, &in.sliceDir); err != nil {
		return fail("%v", err)
	}
	if err := in.write(j, &in.sliceFile); err != nil {
		return fail("%v", err)
	}
	if !o.NoReload && in.memoryText != "" {
		if in.sliceFile.class != classUnchanged {
			if err := in.systemctl("daemon-reload"); err != nil {
				return fail("%v", err)
			}
			reloaded = true
		}
		if err := in.checkSliceShow(); err != nil {
			return fail("%v", err)
		}
	}
	// Step 4: check-policy as the account.
	if err := in.checkPolicyAsAccount(cred); err != nil {
		return fail("%v", err)
	}
	// Steps 5 and 6: the polkit rule, the sshd drop-in, the keys directory
	// and, last, the key line.
	for _, f := range []*file{&in.polkitFile, &in.dropIn, &in.keysDir, &in.keysFile} {
		if err := in.write(j, f); err != nil {
			return fail("%v", err)
		}
	}
	// Step 7: sshd's own check and its effective configuration.
	if err := in.verifySSHD(); err != nil {
		return fail("%v", err)
	}
	// Step 8: the reload.
	in.reload()
	// Step 9: the pin and what is left to the operator.
	in.r.Info("")
	if err := printPins(h, r); err != nil {
		r.Warn("host keys: %v", err)
	}
	for _, w := range in.warnedRoots {
		r.Warn("%s", w)
	}
	r.Note("keep this session open until a new login with the key has worked")
	if j.Changed() || len(in.accountRuns()) > 0 {
		r.OK("installed: %d file(s) written, %d account change(s)", len(j.Paths()), len(in.accountRuns()))
	} else {
		r.OK("nothing to do: every item unchanged")
	}
	return 0
}

// write applies one file step through the journal.
func (in *installer) write(j *setupx.Journal, f *file) error {
	if f.path == "" || f.class == classUnchanged {
		if f.path != "" {
			in.r.OK("%s: unchanged", f.path)
		}
		return nil
	}
	rec := f.rec
	rec.Object, rec.Owner = f.object, "root:root"
	var err error
	if f.dir {
		err = j.Mkdir(f.path, f.mode, setupx.Root, &rec)
	} else {
		err = j.Write(f.path, f.prev, f.data, f.mode, setupx.Root, &rec)
	}
	if err != nil {
		return err
	}
	in.r.OK("%s: %s (root:root %04o)", f.path, rec.Action, f.mode)
	return nil
}

func (in *installer) systemctl(args ...string) error {
	out, err := in.h.Run(setupx.Systemctl, args...)
	if err == nil && !out.OK() {
		err = fmt.Errorf("exit %d: %s", out.Exit, firstLine(out.Stderr))
	}
	if err != nil {
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	in.r.OK("ran systemctl %s", strings.Join(args, " "))
	in.a.Log(&setupx.Record{Action: setupx.ActionRun, Object: "systemd", Command: append([]string{setupx.Systemctl}, args...)})
	return nil
}

// verifyAccount re-reads the databases after step 2: the account, its
// primary group and exactly the allowed supplementary groups, which become
// the credential check-policy runs with.
func (in *installer) verifyAccount() (*execx.Credential, error) {
	o := in.o
	db, err := in.h.Accounts()
	if err != nil {
		return nil, fmt.Errorf("cannot read the user and group databases back: %w", err)
	}
	u, ok := db.User(o.User)
	if !ok || u.UID != o.UID || u.GID != o.GID || u.Home != o.Home || u.Shell != ServiceShell {
		return nil, fmt.Errorf("account %s is not as created (uid %d, gid %d, home %s, shell %s)", o.User, u.UID, u.GID, u.Home, u.Shell)
	}
	if gs := db.GroupsByGID(o.GID); len(gs) != 1 || gs[0].Name != o.User {
		return nil, fmt.Errorf("the account's primary gid %d is not exactly group %s", o.GID, o.User)
	}
	cred := &execx.Credential{UID: o.UID, GID: o.GID}
	var names []string
	for _, g := range db.Supplementary(o.User) {
		names = append(names, g.Name)
		cred.Groups = append(cred.Groups, g.GID)
	}
	want := slices.Clone(in.allowed)
	slices.Sort(want)
	slices.Sort(names)
	if !slices.Equal(names, want) {
		return nil, fmt.Errorf("account %s's supplementary groups are %v, want exactly %v", o.User, names, want)
	}
	return cred, nil
}

func (in *installer) checkSliceShow() error {
	unit := fmt.Sprintf("user-%d.slice", in.o.UID)
	out, err := in.h.Run(setupx.Systemctl, "show", "-p", "MemoryMax", "-p", "MemorySwapMax", unit)
	if err == nil && !out.OK() {
		err = fmt.Errorf("exit %d: %s", out.Exit, firstLine(out.Stderr))
	}
	if err != nil {
		return fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out.Stdout)), "\n") {
		k, v, _ := strings.Cut(l, "=")
		got[k] = v
	}
	if got["MemoryMax"] != strconv.FormatUint(in.memoryBytes, 10) || got["MemorySwapMax"] != "0" {
		return fmt.Errorf("systemctl show %s: MemoryMax=%s MemorySwapMax=%s, want MemoryMax=%d MemorySwapMax=0", unit, got["MemoryMax"], got["MemorySwapMax"], in.memoryBytes)
	}
	in.r.OK("%s: MemoryMax=%s (%s) MemorySwapMax=0 in force", unit, in.memoryText, got["MemoryMax"])
	return nil
}

// checkPolicyAsAccount is step 4: the installed gate's check-policy, run as
// the account through execx's credential option.
func (in *installer) checkPolicyAsAccount(cred *execx.Credential) error {
	out, err := in.h.RunAs(cred, in.p.Limits.MaxMemoryMB, "check-policy", "--policy", in.o.Policy)
	if err != nil {
		return fmt.Errorf("check-policy as %s: %w", in.o.User, err)
	}
	in.r.Info("check-policy as %s (uid %d, gid %d, groups %v):", in.o.User, cred.UID, cred.GID, cred.Groups)
	in.r.Block(string(out.Stdout))
	for _, l := range strings.Split(string(out.Stdout), "\n") {
		if strings.HasPrefix(l, "WARN paths.write") || strings.HasPrefix(l, "WARN git.repos") {
			in.warnedRoots = append(in.warnedRoots, strings.TrimPrefix(l, "WARN ")+" (TARGET-SETUP §6 is yours)")
		}
	}
	if !out.OK() {
		return fmt.Errorf("check-policy as %s reports FAIL (exit %d): serve would refuse; fix what it names and run again", in.o.User, out.Exit)
	}
	in.a.Log(&setupx.Record{Action: setupx.ActionRun, Object: "check_policy", User: in.o.User, Policy: in.o.Policy, PolicySHA256: in.p.SHA256})
	in.r.OK("check-policy as %s: serve would accept this install and policy", in.o.User)
	return nil
}

// verifySSHD is step 7.
func (in *installer) verifySSHD() error {
	out, err := in.h.Run(setupx.Sshd, "-t")
	if err == nil && !out.OK() {
		err = fmt.Errorf("exit %d: %s", out.Exit, firstLine(out.Stderr))
	}
	if err != nil {
		return fmt.Errorf("sshd -t: %w", err)
	}
	m, _, err := in.sshdT(in.checkSpec())
	if err != nil {
		return fmt.Errorf("sshd -T -C %s: %w", in.checkSpec(), err)
	}
	if bad := blockMismatch(m); len(bad) > 0 {
		return fmt.Errorf("sshd -T -C %s: the Match block is not in force (an earlier drop-in or Match block wins, or sshd_config does not include %s/*.conf): %s",
			in.checkSpec(), SSHDropInDir, strings.Join(bad, "; "))
	}
	om, other, err := in.sshdT(in.otherSpec())
	if err != nil {
		return fmt.Errorf("sshd -T -C %s: %w", in.otherSpec(), err)
	}
	if v := om["authorizedkeysfile"]; len(v) == 1 && v[0] == KeysDir+"/%u" {
		return fmt.Errorf("sshd -T -C %s: the block reaches other accounts (authorizedkeysfile %s)", in.otherSpec(), v[0])
	}
	if in.baseline != nil && !bytes.Equal(other, in.baseline) {
		in.r.Block(setupx.UnifiedDiff("sshd -T -C "+in.otherSpec()+" (before)", "(after)", in.baseline, other))
		return fmt.Errorf("sshd -T -C %s: the drop-in changed the effective configuration of other accounts", in.otherSpec())
	}
	in.r.OK("sshd -t, and sshd -T -C: the Match block is in force for %s and reaches no other account", in.o.User)
	return nil
}

func (in *installer) reload() {
	switch {
	case in.dropIn.class == classUnchanged:
		in.r.OK("sshd: the drop-in is unchanged; no reload (a new key line needs none: sshd reads the keys file at every login)")
	case in.o.NoReload:
		in.r.Note("--no-reload: reload sshd yourself (systemctl reload ssh.service, or restart the sshd you run)%s",
			map[bool]string{true: ", and run systemctl daemon-reload for the slice drop-in", false: ""}[in.sliceFile.class != classUnchanged && in.memoryText != ""])
	case in.reloadSSH != "":
		if err := in.systemctl("reload", in.reloadSSH); err != nil {
			in.r.Warn("%v; the files are in place and verified: reload sshd yourself", err)
		}
	default:
		in.r.OK("sshd: ssh.socket starts sshd per connection; the next connection reads the new drop-in")
	}
}

func (in *installer) rollback(j *setupx.Journal, reloaded bool) {
	undone, failed := j.Rollback()
	for _, p := range undone {
		in.r.Info("rolled back %s", p)
	}
	for _, err := range failed {
		in.r.Fail("%v", err)
	}
	if reloaded {
		if err := in.systemctl("daemon-reload"); err != nil {
			in.r.Warn("%v", err)
		}
	}
	if len(in.accountRuns()) > 0 {
		in.r.Note("the account and groups this run created remain; a new run finds them unchanged")
	}
	in.r.Info("install failed: every file this run changed was restored")
}

// ErrNoHostKey is a host without host keys.
var ErrNoHostKey = errors.New("no host key in " + SSHDir)
