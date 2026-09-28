package policy

import "path"

// builtinDeny is the built-in read deny list (POLICY §3); policy `deny`
// patterns are added to it and cannot remove any of these.
var builtinDeny = []string{
	"/etc/shadow*", "/etc/gshadow*", "/etc/sudoers", "/etc/sudoers.d/**",
	"/etc/ssh/*_key", "/etc/ssh/authorized_keys.d/**", "/root/**", "/home/*/.ssh/**",
	"**/.ssh/**", "**/.gnupg/**", "**/.docker/config.json", "**/.kube/config",
	"**/.netrc", "**/.git-credentials", "**/.pgpass", "/var/lib/shell-mcp/**",
}

// builtinProtected is the built-in protected set (POLICY §3). The gate
// binary, the service user's home and the policy file itself are added at
// load time. Nothing covered by it is ever writable, and a write root equal
// to, inside, or containing an entry is a policy error. For "**/.ssh",
// "containing" cannot be decided statically, so it is enforced per request.
var builtinProtected = []string{
	"/etc/shell-mcp", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/pam.d",
	"/etc/security", "/etc/systemd", "/usr/lib/systemd", "/lib/systemd", "/run/systemd",
	"/etc/cron*", "/var/spool/cron", "/etc/profile", "/etc/profile.d", "/etc/environment",
	"/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ld.so.preload", "/etc/passwd",
	"/etc/group", "/etc/shadow*", "/etc/gshadow*", "/etc/fstab", "/boot", "/usr", "/bin",
	"/sbin", "/lib", "/lib64", "/root", "**/.ssh",
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
	{4, "launchers and wrappers", []string{"env", "xargs", "nohup", "setsid", "timeout", "nice", "ionice", "stdbuf", "flock", "watch", "parallel"}},
	{5, "debuggers and tracers", []string{"strace", "ltrace", "gdb", "lldb", "valgrind"}},
	{6, "pagers and editors", []string{"less", "more", "most", "man", "pg", "vi", "vim", "vim.*", "nvim", "view", "ex", "ed", "nano", "pico", "emacs", "joe", "mcedit"}},
	{7, "privilege changers", []string{"su", "sudo", "doas", "pkexec", "runuser", "setpriv", "chroot", "nsenter", "unshare", "capsh", "newgrp", "sg"}},
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

// containerCLIs need `root_equivalent: true` (POLICY §4).
var containerCLIs = []string{"docker", "podman", "ctr", "nerdctl", "kubectl"}

// hardDenied returns the group that denies a base name, if any.
func hardDenied(base string) (group int, name string, denied bool) {
	for _, g := range hardDeny {
		for _, pat := range g.bins {
			if ok, _ := path.Match(pat, base); ok {
				return g.group, g.name, true
			}
		}
	}
	return 0, "", false
}

// defaultReadExec are the system directories the sandbox grants read and
// execute on (POLICY §4a), before sandbox.system_read_exec.
var defaultReadExec = []string{"/usr", "/bin", "/sbin", "/lib", "/lib64"}

// DefaultReadExec returns the sandbox's built-in read+execute directories.
func DefaultReadExec() []string { return append([]string(nil), defaultReadExec...) }
