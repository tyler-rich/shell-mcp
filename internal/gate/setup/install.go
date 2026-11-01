//go:build linux

package setup

import (
	"errors"

	"io"
	"io/fs"

	"github.com/tyler-rich/shell-mcp/internal/gate/execx"

	"github.com/tyler-rich/shell-mcp/internal/gate/policy"

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
	var stub0 int
	return stub0
}

func (in *installer) refuse(object, reason, format string, args ...any) {}

func (in *installer) run() int { var stub0 int; return stub0 }

// checks is step 1 (TARGET-SETUP §12.1): everything is checked, and every
// problem reported, before anything is written.
func (in *installer) checks() {}

func (in *installer) checkBinaries() {}

func (in *installer) checkPolicy() {}

// hostKey is one of the host's own public keys.
type hostKey struct {
	path, typ, fingerprint string
	marshal                []byte
}

// hostKeys reads /etc/ssh/ssh_host_*_key.pub.
func hostKeys(h setupx.Host) ([]hostKey, error) {
	var stub0 []hostKey
	var stub1 error
	return stub0, stub1
}

func (in *installer) checkKey() {}

func (in *installer) checkFrom() {}

// sshdT runs sshd -T (with -C spec when given) and parses it.
func (in *installer) sshdT(spec string) (m map[string][]string, raw []byte, err error) {
	var stub0 map[string][]string
	var stub1 []byte
	var stub2 error
	return stub0, stub1, stub2
}

func firstLine(b []byte) string { var stub0 string; return stub0 }

func (in *installer) checkSSHD() {}

// state reads a managed path.
func (in *installer) state(p string) (setupx.FileState, bool) {
	var stub0 setupx.FileState
	var stub1 bool
	return stub0, stub1
}

// owned classifies an owned file (handoff §3.2): absent → create,
// identical → unchanged, anything else refused with a diff.
func (in *installer) owned(p string, data []byte, mode fs.FileMode, object string) file {
	var stub0 file
	return stub0
}

// ownedDir classifies a directory install creates: absent → create, a
// root:root directory of exactly mode → unchanged, anything else refused.
func (in *installer) ownedDir(p string, mode fs.FileMode) file { var stub0 file; return stub0 }

// requireDir requires an existing directory that passes the chain rule.
func (in *installer) requireDir(p, why string) bool { var stub0 bool; return stub0 }

func (in *installer) checkAccount() {}

// The primary group: named after the account, with --gid.

// The account.

// The socket group: given exactly when the policy forwards to the helper.

// Supplementary groups (handoff §7 Q5): only the allowed ones; never
// removed by install.

func allowedText(a []string) string { var stub0 string; return stub0 }

func (in *installer) checkSocketGroup(db *setupx.Accounts) {}

func (in *installer) checkSlice() {}

func (in *installer) checkPolkit() {}

func (in *installer) checkSSHFiles() {}

// The drop-in: one service account per host.

// checkKeysFile plans the keys file (line-keyed, handoff §3.2): every
// existing line parsed and checked, the key's own line added, kept or, with
// --replace-key, rewritten.
func (in *installer) checkKeysFile() {}

func policySHA(p *policy.Policy) string { var stub0 string; return stub0 }

func (in *installer) checkOwnerScan() {}

// The ids are refused already; a scan would only take time.

func limited(l []string, n int) string { var stub0 string; return stub0 }

// checkReload is step 1's reload check: unless --no-reload, systemd must
// run, and when the drop-in changes, ssh.service must be active (reload)
// or ssh.socket (no reload needed: the next connection starts sshd).
// Before the drop-in changes, the other name's effective configuration is
// recorded, to compare after.
func (in *installer) checkReload() {}

func (in *installer) active(unit string) bool { var stub0 bool; return stub0 }

func (in *installer) checkSpec() string { var stub0 string; return stub0 }

func (in *installer) otherSpec() string { var stub0 string; return stub0 }

// accountRuns are step 2's programs, in order.
func (in *installer) accountRuns() [][]string { var stub0 [][]string; return stub0 }

// managed is every file and directory step, in the order written: the key
// line last.
func (in *installer) managed() []*file { var stub0 []*file; return stub0 }

// describe prints the run for --dry-run (TARGET-SETUP §12.4).
func (in *installer) describe() {}

func (in *installer) describeFiles(files ...file) {}

func (in *installer) describeReload() {}

// apply makes the run (steps 2 to 9), rolling every file back on a
// failure after the first write.
func (in *installer) apply() int { var stub0 int; return stub0 }

// Step 2: groups, the account, its lock and its memberships.

// Step 3: the slice drop-in, systemd reloaded, its values in force.

// Step 4: check-policy as the account.

// Steps 5 and 6: the polkit rule, the sshd drop-in, the keys directory
// and, last, the key line.

// Step 7: sshd's own check and its effective configuration.

// Step 8: the reload.

// Step 9: the pin and what is left to the operator.

// write applies one file step through the journal.
func (in *installer) write(j *setupx.Journal, f *file) error { var stub0 error; return stub0 }

func (in *installer) systemctl(args ...string) error { var stub0 error; return stub0 }

// verifyAccount re-reads the databases after step 2: the account, its
// primary group and exactly the allowed supplementary groups, which become
// the credential check-policy runs with.
func (in *installer) verifyAccount() (*execx.Credential, error) {
	var stub0 *execx.Credential
	var stub1 error
	return stub0, stub1
}

func (in *installer) checkSliceShow() error { var stub0 error; return stub0 }

// checkPolicyAsAccount is step 4: the installed gate's check-policy, run as
// the account through execx's credential option.
func (in *installer) checkPolicyAsAccount(cred *execx.Credential) error {
	var stub0 error
	return stub0
}

// verifySSHD is step 7.
func (in *installer) verifySSHD() error { var stub0 error; return stub0 }

func (in *installer) reload() {}

func (in *installer) rollback(j *setupx.Journal, reloaded bool) {}

// ErrNoHostKey is a host without host keys.
var ErrNoHostKey = errors.New("no host key in " + SSHDir)
