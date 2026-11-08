//go:build linux

package setup

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"
	"github.com/tyler-rich/shell-mcp/internal/gate/install"
	"github.com/tyler-rich/shell-mcp/internal/gate/setupx"
)

// MoveOptions are move-key's flags (TARGET-SETUP §12.1, "Moving a key
// between accounts").
type MoveOptions struct {
	// Principal selects the line: its forced command's --principal.
	Principal string
	// FromUser and ToUser are the source and destination accounts.
	FromUser, ToUser string
	DryRun           bool
	NoReload         bool
}

// MoveUsage is move-key's usage line.
const MoveUsage = `usage: shell-mcp-gate move-key --principal <label> --from-user <name> --to-user <name> [--dry-run] [--no-reload]
`

// ParseMoveFlags parses move-key's arguments. A missing or malformed flag
// is an ErrUsage (exit 2); values are checked later, as refusals.
func ParseMoveFlags(args []string) (*MoveOptions, error) {
	fs := flag.NewFlagSet("move-key", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := &MoveOptions{}
	fs.StringVar(&o.Principal, "principal", "", "")
	fs.StringVar(&o.FromUser, "from-user", "", "")
	fs.StringVar(&o.ToUser, "to-user", "", "")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")
	fs.BoolVar(&o.NoReload, "no-reload", false, "")
	usage := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrUsage}, a...)...)
	}
	if err := fs.Parse(args); err != nil {
		return nil, usage("%v", err)
	}
	if fs.NArg() != 0 {
		return nil, usage("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, req := range []string{"principal", "from-user", "to-user"} {
		if !set[req] {
			return nil, usage("--%s is required", req)
		}
	}
	return o, nil
}

// classRemove is a file the run removes (the source account's polkit rule).
const classRemove = "remove"

// mover is one run of shell-mcp-gate move-key. It shares install's checks
// and writes through installer, whose o.User is the destination account
// and whose o.Policy and p are the moved line's policy.
type mover struct {
	*installer
	m          *MoveOptions
	fromAcct   setupx.Account
	toAcct     setupx.Account
	supp       []setupx.Group // the destination's supplementary groups
	src, dst   *keysFile
	line       string // the moved line, exactly, without its line break
	key        *PubKey
	moving     bool // the source holds the line (otherwise it was moved already)
	cred       *execx.Credential
	remaining  []int // the source's key lines left after the move
	srcKeys    file
	dstKeys    file
	dstRule    file
	srcRule    file
	keepRule   bool // the source's rule stays: a remaining line needs it
	changesKey bool
}

// MoveKey runs shell-mcp-gate move-key (TARGET-SETUP §12.1, "Moving a key
// between accounts") on h: the line of the key whose forced command names
// --principal moves byte for byte from --from-user's keys file to the end
// of --to-user's, with the polkit rules the moved policy needs, checked by
// sshd -t and sshd -T -C and rolled back on any failure, then sshd is
// reloaded. It returns the exit code: 0 done, 1 refused or failed.
func MoveKey(m *MoveOptions, h Host, stdout io.Writer, a *setupx.Auditor) int {
	mv := &mover{m: m, installer: &installer{name: "move-key", h: h, r: &setupx.Report{W: stdout}, a: a,
		o: &Options{User: m.ToUser, Principal: m.Principal, DryRun: m.DryRun, NoReload: m.NoReload}}}
	return mv.run()
}

func (mv *mover) run() int {
	m, r := mv.m, mv.r
	mode := ""
	if m.DryRun {
		mode = " (dry run: nothing is changed; only commands that read are run)"
	}
	r.Info("shell-mcp-gate move-key%s: principal %s, from account %s to account %s", mode, m.Principal, m.FromUser, m.ToUser)
	if !mv.rootNotForced() {
		return 1
	}
	mv.checks()
	if r.Failures > 0 {
		r.Info("%d problem(s): move-key refused; nothing was changed", r.Failures)
		return 1
	}
	if m.DryRun {
		mv.describe()
		r.OK("dry run: every check passed; the run above would be made")
		return 0
	}
	return mv.apply()
}

// checks: everything is checked, and every problem reported, before
// anything is written.
func (mv *mover) checks() {
	mv.checkBinaries(setupx.Sshd)
	if !mv.checkNames() {
		return
	}
	mv.checkSSHD()
	if !mv.checkAccounts() || !mv.checkDropIn() {
		return
	}
	if !mv.checkKeys() || !mv.checkPolicy() {
		return
	}
	mv.checkPolkit()
	mv.checkReload()
}

func (mv *mover) checkNames() bool {
	m := mv.m
	ok := true
	if !ValidPrincipal(m.Principal) {
		mv.refuse("key", "principal", "--principal %q must match ^[a-z][a-z0-9-]{0,31}$", m.Principal)
		ok = false
	}
	for _, c := range []struct{ flag, name string }{{"--from-user", m.FromUser}, {"--to-user", m.ToUser}} {
		if !ValidName(c.name) {
			mv.refuse("account", "name", "%s %q is not a plain account name (^[a-z_][a-z0-9_-]{0,31}$)", c.flag, c.name)
			ok = false
		}
	}
	if ok && m.FromUser == m.ToUser {
		mv.refuse("account", "same_account", "--from-user and --to-user name the same account %s", m.FromUser)
		ok = false
	}
	return ok
}

// checkAccounts requires both accounts as install makes them: existing,
// with the shell /bin/sh and the home as their own directory.
func (mv *mover) checkAccounts() bool {
	db, err := mv.h.Accounts()
	if err != nil {
		mv.refuse("account", "accounts", "cannot read the user and group databases: %v", err)
		return false
	}
	ok := true
	for _, c := range []struct {
		name string
		acct *setupx.Account
	}{{mv.m.FromUser, &mv.fromAcct}, {mv.m.ToUser, &mv.toAcct}} {
		u, found := db.User(c.name)
		switch {
		case !found:
			mv.refuse("account", "no_account", "account %s does not exist; move-key moves a key between accounts that shell-mcp-gate install made (TARGET-SETUP §12.1)", c.name)
			ok = false
			continue
		case u.Shell != ServiceShell:
			mv.refuse("account", "account_differs", "account %s has the shell %q; it must be %s", c.name, u.Shell, ServiceShell)
			ok = false
		}
		*c.acct = u
	}
	if !ok {
		return false
	}
	mv.o.Home = mv.toAcct.Home
	mv.cred = &execx.Credential{UID: mv.toAcct.UID, GID: mv.toAcct.GID}
	for _, g := range db.Supplementary(mv.toAcct.Name) {
		mv.cred.Groups = append(mv.cred.Groups, g.GID)
	}
	mv.supp = db.Supplementary(mv.toAcct.Name)
	return true
}

// checkDropIn requires the drop-in as install writes it, with a block for
// each account. The move never changes it.
func (mv *mover) checkDropIn() bool {
	st, users, ok := mv.readDropIn(mv.m.ToUser)
	if !ok {
		return false
	}
	if !st.Exists {
		mv.refuse("file", "no_block", "%s does not exist: there is no Match block for %s or %s; run shell-mcp-gate install for each account first", SSHDropIn, mv.m.FromUser, mv.m.ToUser)
		return false
	}
	for _, u := range []string{mv.m.FromUser, mv.m.ToUser} {
		if !slices.Contains(users, u) {
			mv.refuse("file", "no_block", "%s has no Match block for account %s; run shell-mcp-gate install for it first (TARGET-SETUP §12.1)", SSHDropIn, u)
			ok = false
		}
	}
	mv.accounts = users
	mv.dropIn = file{path: SSHDropIn, class: classUnchanged}
	return ok
}

// checkKeys reads both keys files and finds the line: exactly one line of
// the source names --principal, and the destination does not hold its key
// (or holds exactly this line: a move half done, finished here); or the
// source names it nowhere and exactly one destination line does (moved
// already: nothing to do).
func (mv *mover) checkKeys() bool {
	m := mv.m
	if !mv.requireDir(SSHDir, "") {
		return false
	}
	if kd := mv.ownedDir(KeysDir, 0o755); kd.class == classCreate {
		mv.refuse("file", "directory_missing", "%s does not exist: there are no keys to move", KeysDir)
		return false
	} else if kd.class == "" {
		return false
	}
	src, ok1 := mv.readKeys(KeysFile(m.FromUser))
	dst, ok2 := mv.readKeys(KeysFile(m.ToUser))
	if !ok1 || !ok2 {
		return false
	}
	mv.src, mv.dst = src, dst
	si, di := withPrincipal(src, m.Principal), withPrincipal(dst, m.Principal)
	switch {
	case len(si) > 1:
		mv.refuse("key", "key_ambiguous", "%d lines of %s name --principal %s (lines %s); move-key moves exactly one line: give each key its own principal", len(si), src.path, m.Principal, lineNumbers(si))
		return false
	case len(si) == 1:
		mv.line, mv.key, mv.moving = src.lines[si[0]], src.keys[si[0]], true
		for j, k := range dst.keys {
			if k != nil && k.Fingerprint == mv.key.Fingerprint && dst.lines[j] != mv.line {
				mv.refuse("key", "key_in_destination", "%s line %d already holds this key (%s) with other bytes than %s line %d; remove one of the two lines and run again",
					dst.path, j+1, mv.key.Fingerprint, src.path, si[0]+1)
				return false
			}
		}
		for i := range src.lines {
			if i != si[0] && src.keys[i] != nil {
				mv.remaining = append(mv.remaining, i)
			}
		}
	case len(di) > 1:
		mv.refuse("key", "key_ambiguous", "no line of %s names --principal %s, and %d lines of %s do (lines %s)", src.path, m.Principal, len(di), dst.path, lineNumbers(di))
		return false
	case len(di) == 1:
		mv.line, mv.key = dst.lines[di[0]], dst.keys[di[0]]
		for i, k := range src.keys {
			if k != nil && k.Fingerprint == mv.key.Fingerprint {
				mv.refuse("key", "key_in_source", "%s line %d holds the key of %s line %d under another principal; remove one of the two lines and run again", src.path, i+1, dst.path, di[0]+1)
				return false
			}
			if k != nil {
				mv.remaining = append(mv.remaining, i)
			}
		}
	default:
		mv.refuse("key", "key_not_found", "no line of %s names --principal %s (nor of %s)", src.path, m.Principal, dst.path)
		return false
	}
	// The plan for both files: the line appended to the destination (unless
	// it is there), removed from the source.
	rec := setupx.Record{Fingerprint: mv.key.Fingerprint, Principal: m.Principal, Reason: "move"}
	mv.dstKeys = file{path: dst.path, mode: 0o644, prev: dst.st, object: "key", class: classUnchanged, rec: rec}
	mv.dstKeys.rec.User = m.ToUser
	if mv.moving && !slices.Contains(dst.lines, mv.line) {
		mv.dstKeys.data = joinKeyLines(append(slices.Clone(dst.lines), mv.line))
		mv.dstKeys.class = classReplace
		if !dst.st.Exists {
			mv.dstKeys.class = classCreate
		}
	}
	mv.srcKeys = file{path: src.path, mode: 0o644, prev: src.st, object: "key", class: classUnchanged, rec: rec}
	mv.srcKeys.rec.User = m.FromUser
	if mv.moving {
		kept := slices.Delete(slices.Clone(src.lines), si[0], si[0]+1)
		mv.srcKeys.data, mv.srcKeys.class = joinKeyLines(kept), classReplace
	}
	mv.changesKey = mv.srcKeys.class != classUnchanged || mv.dstKeys.class != classUnchanged
	return true
}

func withPrincipal(kf *keysFile, principal string) []int {
	var out []int
	for i, p := range kf.principal {
		if kf.keys[i] != nil && p == principal {
			out = append(out, i)
		}
	}
	return out
}

func lineNumbers(idx []int) string {
	s := make([]string, len(idx))
	for i, n := range idx {
		s[i] = fmt.Sprint(n + 1)
	}
	return strings.Join(s, ", ")
}

// checkPolicy loads the moved line's policy for the destination account,
// as serve will load it there, and applies install's account rules for it
// (S8 Q5, D-020): a policy with privileged forwarding stays on the account
// in the helper's socket group, and the destination's supplementary groups
// are exactly those this policy allows (systemd-journal with a journal
// section, nothing else). move-key adds and removes no membership.
func (mv *mover) checkPolicy() bool {
	kl, err := ParseKeyLine(mv.line)
	if err != nil {
		mv.refuse("key", "keys_file_line", "the line to move: %v", err) // readKeys checked it
		return false
	}
	for _, o := range kl.Options {
		switch o.Name {
		case "command":
			mv.o.Policy, _, _ = ForcedCommand(o.Value)
		case "from":
			es, _, err := ParseFrom(strings.Split(o.Value, ","))
			if err != nil {
				mv.refuse("key", "from", "the line to move: from=: %v", err)
				return false
			}
			mv.installer.from = es
		}
	}
	p, err := mv.h.LoadPolicy(mv.o.Policy, mv.toAcct.Home)
	if err != nil {
		for _, l := range strings.Split(err.Error(), "\n") {
			mv.refuse("policy", "policy_invalid", "policy %s (the moved line's): %s", mv.o.Policy, l)
		}
		return false
	}
	mv.p = p
	mv.journal = len(p.Journal.Units) > 0
	mv.control = len(p.Services.ControlUnits) > 0
	mv.r.OK("policy %s: sha256 %s, max_tier %s", mv.o.Policy, p.SHA256, p.MaxTier)
	mv.dstKeys.rec.Policy, mv.dstKeys.rec.PolicySHA256 = mv.o.Policy, p.SHA256
	mv.srcKeys.rec.Policy, mv.srcKeys.rec.PolicySHA256 = mv.o.Policy, p.SHA256
	if p.Privileged.Enabled {
		mv.refuse("key", "forwarding", "policy %s has privileged.enabled: a key with privileged forwarding stays on the account in the helper's socket group; "+
			"to serve it from another account, install it there with shell-mcp-gate install (TARGET-SETUP §4)", mv.o.Policy)
		return false
	}
	ok := true
	if mv.journal {
		mv.allowed = []string{JournalGroup}
	}
	member := false
	for _, g := range mv.supp {
		if g.Name == JournalGroup {
			member = true
		}
		switch {
		case slices.Contains(install.DeniedGroups, g.Name):
			mv.refuse("account", "privileged_group", "account %s is a member of %s, a privileged group the gate refuses (D-020); remove the membership and run again", mv.toAcct.Name, g.Name)
			ok = false
		case g.GID == 0:
			mv.refuse("account", "privileged_group", "account %s is a member of group %s with gid 0; remove the membership and run again", mv.toAcct.Name, g.Name)
			ok = false
		case !slices.Contains(mv.allowed, g.Name):
			mv.refuse("account", "supplementary_group", "account %s is a member of %s; for policy %s its only supplementary groups may be %s "+
				"(a key without privileged forwarding never runs as the account in the helper's socket group: TARGET-SETUP §4)", mv.toAcct.Name, g.Name, mv.o.Policy, allowedText(mv.allowed))
			ok = false
		}
	}
	if mv.journal && !member {
		mv.refuse("account", "missing_group", "account %s is not a member of %s, which policy %s's journal section needs; move-key adds no membership: "+
			"run shell-mcp-gate install for this key on %s (it adds it), then move-key again", mv.toAcct.Name, JournalGroup, mv.o.Policy, mv.toAcct.Name)
		ok = false
	}
	return ok
}

// checkPolkit plans both accounts' polkit rules (TARGET-SETUP §8, "Per
// account"): the destination's rule for the moved policy when it has
// services.control; the source's rule removed when it is exactly the moved
// policy's and no line left in the source needs it, kept when one does,
// and the move refused when a line left needs another rule.
func (mv *mover) checkPolkit() {
	if !mv.control {
		return
	}
	if !mv.requireDir(PolkitDir, "install polkitd (TARGET-SETUP §8)") {
		return
	}
	rule, err := polkitRule(mv.m.ToUser, mv.p)
	if err != nil {
		mv.refuse("file", "polkit", "polkit rule: %v", err)
		return
	}
	mv.dstRule = mv.owned(PolkitRuleFor(mv.m.ToUser, mv.isFirst(mv.m.ToUser)), rule, 0o644, "polkit")
	moved, err := polkitRule(mv.m.FromUser, mv.p)
	if err != nil {
		mv.refuse("file", "polkit", "polkit rule: %v", err)
		return
	}
	path := PolkitRuleFor(mv.m.FromUser, mv.isFirst(mv.m.FromUser))
	st, ok := mv.state(path)
	if !ok || !st.Exists || !st.IsRegular() || !bytes.Equal(st.Data, moved) {
		return // not the moved policy's rule: not this move's to change
	}
	mv.srcRule = file{path: path, mode: 0o644, prev: st, object: "polkit", class: classUnchanged}
	if st.Perm() != 0o644 || st.Owner != setupx.Root {
		mv.refuse("file", "file_differs", "%s is %s %04o, not root:root 0644; fix it and run again", path, st.Owner, st.Perm())
		return
	}
	var conflict []string
	seen := map[string]bool{}
	for _, i := range mv.remaining {
		pp := mv.src.policies[i]
		if seen[pp] {
			continue
		}
		seen[pp] = true
		p2, err := mv.h.LoadPolicy(pp, mv.fromAcct.Home)
		if err != nil {
			mv.refuse("policy", "polkit_unknown", "cannot load %s (%s line %d) to tell whether account %s still needs %s: %v", pp, mv.src.path, i+1, mv.m.FromUser, path, err)
			return
		}
		if len(p2.Services.ControlUnits) == 0 {
			continue
		}
		r2, err := polkitRule(mv.m.FromUser, p2)
		if err != nil {
			mv.refuse("file", "polkit", "polkit rule for %s: %v", pp, err)
			return
		}
		if bytes.Equal(r2, st.Data) {
			mv.keepRule = true
		} else {
			conflict = append(conflict, pp)
		}
	}
	switch {
	case mv.keepRule:
	case len(conflict) > 0:
		mv.refuse("file", "polkit_conflict", "%s is the moved policy's rule, and account %s's remaining keys need another (policy %s); "+
			"one account has one rule: give those keys an account of their own, or make their services.control the same", path, mv.m.FromUser, strings.Join(conflict, ", "))
	default:
		mv.srcRule.class = classRemove
	}
}

// checkReload is install's: unless --no-reload, systemd must run, and when
// a keys file changes, ssh.service must be active (reload) or ssh.socket.
func (mv *mover) checkReload() {
	if mv.r.Failures > 0 {
		return
	}
	if mv.changesKey {
		_, base, err := mv.sshdT(mv.otherSpec())
		if err != nil {
			mv.refuse("sshd", "sshd_config", "sshd -T -C %s: %v", mv.otherSpec(), err)
			return
		}
		mv.baseline = base
	}
	if mv.o.NoReload {
		return
	}
	if !mv.h.SystemdRunning() {
		mv.refuse("sshd", "no_systemd", "systemd is not running as PID 1, so move-key cannot reload; run with --no-reload and reload sshd yourself")
		return
	}
	if !mv.changesKey {
		return
	}
	switch {
	case mv.active("ssh.service"):
		mv.reloadSSH = "ssh.service"
	case mv.active("ssh.socket"):
		mv.reloadSSH = ""
	default:
		mv.refuse("sshd", "no_sshd", "neither ssh.service nor ssh.socket is active, so sshd would not be reloaded; start sshd, or run with --no-reload and reload it yourself")
	}
}

// files are the run's file steps, in the order written: the destination's
// rule, its keys file, the source's keys file, the source's rule.
func (mv *mover) files() []*file {
	var out []*file
	for _, f := range []*file{&mv.dstRule, &mv.dstKeys, &mv.srcKeys, &mv.srcRule} {
		if f.path != "" {
			out = append(out, f)
		}
	}
	return out
}

func (mv *mover) describe() {
	r := mv.r
	r.Info("would run %s check-policy --policy %s as %s (uid %d, gid %d, groups %v)", GatePath, mv.o.Policy, mv.m.ToUser, mv.cred.UID, mv.cred.GID, mv.cred.Groups)
	for _, f := range mv.files() {
		if f.class == classRemove {
			r.Info("file %s: remove", f.path)
			continue
		}
		mv.describeFiles(*f)
	}
	r.Info("would check %s -t and %s -T -C %s and -C %s", setupx.Sshd, setupx.Sshd, mv.checkSpecs(), mv.otherSpec())
	switch {
	case !mv.changesKey:
		r.Info("sshd: no keys file changes, no reload")
	case mv.o.NoReload:
		r.Info("would print the reload to run (--no-reload)")
	case mv.reloadSSH != "":
		r.Info("would run %s reload %s", setupx.Systemctl, mv.reloadSSH)
	default:
		r.Info("sshd: ssh.socket starts sshd per connection; no reload needed")
	}
}

// apply makes the move: check-policy as the destination account, then the
// writes in order, both keys files read back, sshd checked, and the reload;
// every file is rolled back on a failure after the first write.
func (mv *mover) apply() int {
	r, h := mv.r, mv.h
	j := setupx.NewJournal(h, mv.a)
	fail := func(format string, a ...any) int {
		r.Fail(format, a...)
		mv.a.Log(&setupx.Record{Action: setupx.ActionRefuse, Object: "move", Reason: "check_failed", Detail: fmt.Sprintf(format, a...)})
		mv.rollback(j, false)
		return 1
	}
	for _, f := range mv.files() {
		left, err := h.RemoveLeftovers(f.path)
		for _, l := range left {
			r.Warn("removed %s, a temp file a killed run left", l)
		}
		if err != nil {
			return fail("%v", err)
		}
	}
	if err := mv.checkPolicyAsAccount(mv.cred); err != nil {
		return fail("%v", err)
	}
	for _, f := range mv.files() {
		if f.class == classRemove {
			if err := j.Remove(f.path, f.prev, &setupx.Record{Object: f.object, User: mv.m.FromUser, Reason: "move"}); err != nil {
				return fail("%s: %v", f.path, err)
			}
			r.OK("%s: removed (account %s's remaining keys have no services.control that needs it)", f.path, mv.m.FromUser)
			continue
		}
		if err := mv.write(j, f); err != nil {
			return fail("%v", err)
		}
	}
	if err := mv.verifyKeys(); err != nil {
		return fail("%v", err)
	}
	if err := mv.verifySSHD(); err != nil {
		return fail("%v", err)
	}
	switch {
	case !mv.changesKey:
		r.OK("sshd: no keys file changed; no reload")
	case mv.o.NoReload:
		r.Note("--no-reload: reload sshd yourself (systemctl reload ssh.service, or restart the sshd you run)")
	case mv.reloadSSH != "":
		if err := mv.systemctl("reload", mv.reloadSSH); err != nil {
			r.Warn("%v; the files are in place and verified: reload sshd yourself", err)
		}
	default:
		r.OK("sshd: ssh.socket starts sshd per connection; the next connection reads the keys files")
	}
	if !j.Changed() {
		r.OK("nothing to do: every item unchanged (the line for --principal %s is in %s)", mv.m.Principal, mv.dst.path)
		return 0
	}
	if mv.moving {
		r.Note("set the target user of the server instance with principal %s to %s now (SHELL_MCP_TARGET_USER, or user in the targets file): "+
			"its key no longer logs in as %s", mv.m.Principal, mv.m.ToUser, mv.m.FromUser)
	}
	r.OK("moved: the key %s (principal %s) from %s to %s; %d file(s) changed", mv.key.Fingerprint, mv.m.Principal, mv.m.FromUser, mv.m.ToUser, len(j.Paths()))
	return 0
}

// verifyKeys re-reads both keys files after the writes: the destination
// holds the line exactly once, the source holds its key nowhere.
func (mv *mover) verifyKeys() error {
	count := func(p string) (same, key int, err error) {
		st, err := mv.h.State(p, maxKeysFile)
		if err != nil {
			return 0, 0, fmt.Errorf("reading %s back: %w", p, err)
		}
		for _, l := range keyLines(st.Data) {
			if l == mv.line {
				same++
			}
			if kl, err := ParseKeyLine(l); err == nil && kl.Base64 == mv.key.Base64 {
				key++
			}
		}
		return same, key, nil
	}
	same, key, err := count(mv.dst.path)
	if err != nil {
		return err
	}
	if same != 1 || key != 1 {
		return fmt.Errorf("%s holds the moved line %d time(s) and its key %d time(s) after the move, want once", mv.dst.path, same, key)
	}
	_, key, err = count(mv.src.path)
	if err != nil {
		return err
	}
	if key != 0 {
		return fmt.Errorf("%s still holds the moved key after the move", mv.src.path)
	}
	mv.r.OK("%s holds the line once; %s does not hold its key", mv.dst.path, mv.src.path)
	return nil
}
