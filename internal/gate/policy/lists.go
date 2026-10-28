package policy

import (
	"path"
	"slices"
	"strings"
)

// builtinDeny is the built-in read deny list (POLICY §3); policy `deny`
// patterns are added to it and cannot remove any of these.
var builtinDeny = []string{
	"/etc/shadow*", "/etc/gshadow*", "/etc/sudoers", "/etc/sudoers.d/**",
	"/etc/ssh/*_key", "/etc/ssh/authorized_keys.d/**", "/root/**", "/home/*/.ssh/**",
	"**/.ssh/**", "**/.gnupg/**", "**/.docker/config.json", "**/.kube/config",
	"**/.netrc", "**/.git-credentials", "**/.pgpass", "/var/lib/shell-mcp/**",
	// Other processes' environment and memory, and the kernel's memory image:
	// defence in depth behind Landlock and the rule that no root may be or be
	// inside /proc (POLICY §3).
	"/proc/*/environ", "/proc/*/mem", "/proc/*/task/*/environ", "/proc/*/task/*/mem", "/proc/kcore",
}

// builtinProtected is the built-in protected set (POLICY §3). The gate
// binary, the service user's home and the policy file itself are added at
// load time. Nothing covered by it is ever writable, and a write root equal
// to, inside, or containing an entry is a policy error. For "**/.ssh" and
// "**/.git", "containing" cannot be decided statically, so it is enforced
// per request (a write root may contain a repository; never its .git).
var builtinProtected = []string{
	"/etc/shell-mcp", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/pam.d",
	"/etc/security", "/etc/systemd", "/usr/lib/systemd", "/lib/systemd", "/run/systemd",
	"/etc/cron*", "/var/spool/cron", "/etc/profile", "/etc/profile.d", "/etc/environment",
	"/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ld.so.preload", "/etc/passwd",
	"/etc/group", "/etc/shadow*", "/etc/gshadow*", "/etc/fstab", "/boot", "/usr", "/bin",
	"/sbin", "/lib", "/lib64", "/root", "**/.ssh",
	// Every .git directory (POLICY §3): its config, hooks and attributes can
	// make git run commands or fetch from another host. The gate's git ops
	// write there through git itself, never through fsx.
	"**/.git",
}

// forbiddenRoots may not be roots or contain roots' paths (POLICY §3).
var forbiddenRoots = []string{"/proc", "/sys", "/dev", "/run"}

// hardDeny is the non-removable hard-deny list (POLICY §5), matched against
// the base name of a command's path as written and after resolving
// symlinks. Entries are path.Match patterns over base names.
var hardDeny = []struct {
	group int
	name  string
	bins  []string
}{
	{1, "shells", []string{"sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "ash", "rbash", "busybox", "toybox"}},
	{2, "interpreters", []string{"python", "python2", "python3", "python3.*", "pypy*", "perl", "perl5.*", "ruby", "irb", "node", "nodejs", "deno", "bun", "php", "php*", "lua", "lua5.*", "luajit", "tclsh", "wish", "Rscript", "julia"}},
	{3, "text-program languages", []string{"awk", "gawk", "mawk", "nawk"}},
	// Everything that runs another program it is given (S4c-9, handoff
	// N-13): such a command's argv no longer says what runs. setarch's
	// personality aliases (linux32, linux64, i386, x86_64) are setarch;
	// coreutils' runcon runs a program in another SELinux context (S-MC).
	{4, "launchers and wrappers", []string{"env", "xargs", "nohup", "setsid", "timeout", "nice", "ionice", "stdbuf", "flock", "watch", "parallel", "runcon",
		"systemd-run", "systemd-cat", "systemd-inhibit", "systemd-socket-activate", "run-parts", "start-stop-daemon", "taskset", "chrt",
		"prlimit", "setarch", "linux32", "linux64", "i386", "x86_64", "numactl", "time", "logsave", "dbus-run-session", "dbus-launch",
		"ssh-agent", "chronic", "rlwrap", "unbuffer", "xvfb-run", "fakeroot", "faketime", "daemonize", "cgexec"}},
	{5, "debuggers and tracers", []string{"strace", "ltrace", "gdb", "lldb", "valgrind", "perf", "catchsegv"}},
	{6, "pagers and editors", []string{"less", "more", "most", "man", "pg", "vi", "vim", "vim.*", "nvim", "view", "ex", "ed", "nano", "pico", "emacs", "joe", "mcedit"}},
	{7, "privilege changers", []string{"su", "sudo", "doas", "pkexec", "runuser", "setpriv", "chroot", "nsenter", "unshare", "capsh", "newgrp", "sg",
		"run0", "machinectl", "systemd-nspawn", "bwrap", "firejail", "schroot", "proot", "lxc-attach", "lxc-execute"}},
	{8, "tunnels and transfer", []string{"ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "tftp"}},
	{9, "session tools", []string{"script", "expect", "screen", "tmux"}},
	{10, "identity and scheduling administration", []string{"useradd", "usermod", "userdel", "groupadd", "groupmod", "passwd", "chpasswd", "chage", "visudo", "vipw", "vigr", "crontab", "at", "batch"}},
	{11, "power", []string{"reboot", "shutdown", "poweroff", "halt", "kexec", "init", "telinit"}},
	{12, "kernel and storage", []string{"insmod", "rmmod", "modprobe", "sysctl", "mount", "umount", "mkfs", "mkfs.*", "fdisk", "sfdisk", "parted", "wipefs", "dd"}},
	{13, "firewall", []string{"iptables", "ip6tables", "nft", "ufw", "firewall-cmd"}},
}

// builtinOps may not be declared as commands: their safe forms are
// built-in operations (POLICY §5).
var builtinOps = []string{"systemctl", "journalctl", "git"}

// busClients may not be declared as commands either: a D-Bus client can
// ask PID 1 to start any unit or logind to power off (S4c-9, handoff N-13),
// which the built-in operations do only bounded.
var busClients = []string{"busctl", "dbus-send", "gdbus", "qdbus", "loginctl"}

// notCommand reports whether a base name may never be a policy command,
// because it is a built-in operation's binary or a D-Bus client.
func notCommand(base string) bool {
	return slices.Contains(builtinOps, base) || slices.Contains(busClients, base)
}

// containerCLIs need `root_equivalent: true` (POLICY §4).
var containerCLIs = []string{"docker", "podman", "ctr", "nerdctl", "kubectl"}

// hardDenied returns the group that denies a base name, if any. A GNU
// coreutils program installed under a "gnu" prefix (Ubuntu 26.04's
// /usr/bin/gnuenv beside uutils) is the program it is (S-MC, F1).
func hardDenied(base string) (group int, name string, denied bool) {
	if g, n, ok := hardDeniedName(base); ok {
		return g, n, true
	}
	if rest, ok := GNUUnprefixed(base); ok {
		return hardDeniedName(rest)
	}
	return 0, "", false
}

// hardDeniedName looks one base name up. It runs for every entry of the
// system binary directories (the identity check), so literal names are
// looked up in a map and only the few globs are matched.
func hardDeniedName(base string) (group int, name string, denied bool) {
	if i, ok := hardDenyLiteral[base]; ok {
		return hardDeny[i].group, hardDeny[i].name, true
	}
	for _, g := range hardDenyGlobs {
		if ok, _ := path.Match(g.pattern, base); ok {
			return hardDeny[g.index].group, hardDeny[g.index].name, true
		}
	}
	return 0, "", false
}

// hardDenyLiteral and hardDenyGlobs index hardDeny (read-only after init).
var hardDenyLiteral, hardDenyGlobs = indexHardDeny()

type denyGlob struct {
	pattern string
	index   int
}

func indexHardDeny() (map[string]int, []denyGlob) {
	lit := map[string]int{}
	var globs []denyGlob
	for i, g := range hardDeny {
		for _, b := range g.bins {
			if strings.ContainsAny(b, "*?[") {
				globs = append(globs, denyGlob{b, i})
			} else if _, dup := lit[b]; !dup {
				lit[b] = i
			}
		}
	}
	return lit, globs
}

// defaultReadExec are the system directories the sandbox grants read and
// execute on (POLICY §4a), before sandbox.system_read_exec.
var defaultReadExec = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}

// DefaultSystemBinDirs are the directories the binary identity check scans.
var DefaultSystemBinDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}

// deniedFile is a file under a system binary directory with a hard-denied
// name (after following symlinks).
type deniedFile struct {
	name, path string
	dev, ino   uint64
	size       int64
	sum        *[32]byte // computed on demand
	sumErr     error     // why it could not be, once tried
	// scanned: a name the identity check refuses or classifies, so a
	// failed comparison fails the load; listed: a GTFOBins-listed name, so
	// a failed comparison only skips the warning (N-33). A file may be both.
	scanned, listed bool
}

// DefaultReadExec returns the sandbox's built-in read+execute directories.
func DefaultReadExec() []string { return append([]string(nil), defaultReadExec...) }
