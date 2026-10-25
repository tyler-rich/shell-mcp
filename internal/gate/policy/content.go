package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

// Multi-call binaries and what a command's file holds (S-MC). A command's
// binary is recognised by its content as well as by its names: the uutils
// multi-call binary, BusyBox and toybox, GNU coreutils built as one binary,
// and GNU coreutils' single-purpose programs, each by a marker string it
// carries; and a #! script by its first line.
//
// Verified at the source (POLICY §5): the uutils multi-call binary runs as
// the name of the file it is executed by. uutils 0.10.0 on glibc Linux
// takes the kernel's AT_EXECFN (the path given to execve) unless argv[0]'s
// base name is the same (validation::binary_path), and Ubuntu's build also
// requires that name to be the base name of /proc/self/exe
// (require-utility-to-be-invoked-at-matching-path.patch); a name ending in
// "utils" or "box" takes the utility from the first argument, and upstream
// matches any name that ends with a utility's name. The gate and the helper
// execute the resolved file with argv[0] set to its path, so every one of
// these agrees on its base name, which therefore must be exactly one of
// the utilities. GNU coreutils as one binary (--enable-single-binary) and
// BusyBox choose their program from argv[0] or, under their own name, from
// the first argument; neither is supported.

// The markers are stored reversed, so that the binaries built from this
// package (the gate, the helper, every test binary that links it) never
// carry them: otherwise a policy naming one of those binaries would be
// taken for BusyBox or uutils.
var markers = map[string]string{
	"uutils":     rev(")slitueroc slituu("),         // every uutils utility's --version
	"gnu":        rev("slitueroc UNG"),              // GNU coreutils' --version and help
	"gnu-note":   rev(`"slitueroc":"eman"`),         // the ELF package note of Ubuntu's GNU coreutils
	"gnu-multi":  rev("=gorp-slitueroc--"),          // GNU coreutils built with --enable-single-binary
	"busybox":    rev("v xoBysuB"),                  // BusyBox's banner
	"toybox":     rev("yranib llacitlum s% xobyoT"), // toybox's --help
	"toybox-url": rev("xobyot/ten.yeldnal"),
}

func rev(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// MarkerForTesting returns the content marker of a kind, so that tests
// build invented fixtures without the marker appearing in their source.
func MarkerForTesting(kind string) string { return markers[kind] }

// uutilsApplets are the utilities of Ubuntu 26.04's uutils multi-call
// binary (rust-coreutils 0.10.0, `coreutils --list`). The e2e job compares
// them with the runner's own list, so a uutils that adds or drops one fails
// CI until this table follows; a name not on it is refused.
var uutilsApplets = []string{
	"[", "arch", "b2sum", "base32", "base64", "basename", "basenc", "cat", "chcon", "chgrp", "chmod", "chown",
	"chroot", "cksum", "comm", "cp", "csplit", "cut", "date", "dd", "df", "dir", "dircolors", "dirname", "du",
	"echo", "env", "expand", "expr", "factor", "false", "fmt", "fold", "groups", "head", "hostid", "hostname",
	"id", "install", "join", "kill", "link", "ln", "logname", "ls", "md5sum", "mkdir", "mkfifo", "mknod",
	"mktemp", "more", "mv", "nice", "nl", "nohup", "nproc", "numfmt", "od", "paste", "pathchk", "pinky", "pr",
	"printenv", "printf", "ptx", "pwd", "readlink", "realpath", "rm", "rmdir", "runcon", "seq", "sha1sum",
	"sha224sum", "sha256sum", "sha384sum", "sha512sum", "shred", "shuf", "sleep", "sort", "split", "stat",
	"stdbuf", "stty", "sum", "sync", "tac", "tail", "tee", "test", "timeout", "touch", "tr", "true",
	"truncate", "tsort", "tty", "uname", "unexpand", "uniq", "unlink", "uptime", "users", "vdir", "wc", "who",
	"whoami", "yes",
}

// gnuPrograms are GNU coreutils' programs (coreutils 9.4 on Ubuntu 24.04,
// 9.7 on Debian 13 and, gnu-prefixed, on Ubuntu 26.04).
var gnuPrograms = []string{
	"[", "arch", "b2sum", "base32", "base64", "basename", "basenc", "cat", "chcon", "chgrp", "chmod", "chown",
	"chroot", "cksum", "comm", "cp", "csplit", "cut", "date", "dd", "df", "dir", "dircolors", "dirname", "du",
	"echo", "env", "expand", "expr", "factor", "false", "fmt", "fold", "groups", "head", "hostid", "id",
	"install", "join", "link", "ln", "logname", "ls", "md5sum", "md5sum.textutils", "mkdir", "mkfifo", "mknod",
	"mktemp", "mv", "nice", "nl", "nohup", "nproc", "numfmt", "od", "paste", "pathchk", "pinky", "pr",
	"printenv", "printf", "ptx", "pwd", "readlink", "realpath", "rm", "rmdir", "runcon", "seq", "sha1sum",
	"sha224sum", "sha256sum", "sha384sum", "sha512sum", "shred", "shuf", "sleep", "sort", "split", "stat",
	"stdbuf", "stty", "sum", "sync", "tac", "tail", "tee", "test", "timeout", "touch", "tr", "true",
	"truncate", "tsort", "tty", "uname", "unexpand", "uniq", "unlink", "users", "vdir", "wc", "who",
	"whoami", "yes",
}

// UutilsApplets returns the names of the uutils multi-call binary's
// utilities, sorted.
func UutilsApplets() []string {
	s := slices.Clone(uutilsApplets)
	slices.Sort(s)
	return s
}

// IsUutilsApplet reports whether name is exactly one of uutils' utilities.
func IsUutilsApplet(name string) bool { return slices.Contains(uutilsApplets, name) }

// GNUUnprefixed returns a GNU coreutils program's name without the "gnu"
// prefix Ubuntu installs GNU coreutils under beside uutils (/usr/bin/gnuenv
// is GNU env), or ok false for any other name (F1).
func GNUUnprefixed(base string) (name string, ok bool) {
	if rest, found := strings.CutPrefix(base, "gnu"); found && slices.Contains(gnuPrograms, rest) {
		return rest, true
	}
	return base, false
}

// CanonicalName is base without a GNU coreutils "gnu" prefix.
func CanonicalName(base string) string {
	n, _ := GNUUnprefixed(base)
	return n
}

// IsGNUProgram reports whether base, without a "gnu" prefix, is a GNU coreutils
// program.
func IsGNUProgram(base string) bool { return slices.Contains(gnuPrograms, CanonicalName(base)) }

// ContentKind is what a command's file was recognised as by its content.
type ContentKind int

// Content kinds.
const (
	ContentPlain ContentKind = iota
	ContentScript
	ContentUutils
	ContentGNU
	ContentGNUMulti
	ContentBusyBox
	ContentToybox
)

func (k ContentKind) String() string {
	switch k {
	case ContentScript:
		return "a #! script"
	case ContentUutils:
		return "the uutils multi-call binary"
	case ContentGNU:
		return "a GNU coreutils program"
	case ContentGNUMulti:
		return "GNU coreutils built as one multi-call binary"
	case ContentBusyBox:
		return "BusyBox"
	case ContentToybox:
		return "toybox"
	}
	return "an ordinary program"
}

// Content is what a command's file holds.
type Content struct {
	Kind ContentKind
	// Names are, for a GNU coreutils program, the listed GNU coreutils
	// programs (POLICY §5) whose names it carries as a whole string: the
	// program it is, unless the linker merged that string into a longer one.
	Names []string
	// Interpreter and Arg are a script's #! line.
	Interpreter, Arg string
}

const (
	// shebangBytes is how much of a file the kernel reads for a #! line
	// (BINPRM_BUF_SIZE; execve(2): 255 characters since Linux 5.1).
	shebangBytes = 256
	// maxContentBytes bounds the content scan; a larger file is refused.
	maxContentBytes = 1 << 30
	// contentChunk is the scan's read size.
	contentChunk = 1 << 20
)

var (
	errContentTooLarge = errors.New("is too large to scan for what it is (more than 1 GiB)")
	errShebangLong     = errors.New("is a #! script whose first line does not end within the first 256 bytes, which the kernel reads")
	errShebangNUL      = errors.New("is a #! script whose first line holds a NUL byte")
	errShebangEmpty    = errors.New("is a #! script whose first line names no interpreter")
)

func spacetab(c byte) bool { return c == ' ' || c == '\t' }

// parseShebang returns the interpreter and its optional argument from a
// file's first bytes, or ok false when the file is not a #! script. As in
// Linux's binfmt_script, blanks are spaces and tabs, the interpreter ends
// at the first one, and the rest of the line, trimmed, is one argument.
// A line the kernel would read differently (no newline within its 256
// bytes, a NUL byte) is an error, never a guess.
func parseShebang(b []byte) (interp, arg string, ok bool, err error) {
	if len(b) < 2 || b[0] != '#' || b[1] != '!' {
		return "", "", false, nil
	}
	b = b[:min(len(b), shebangBytes)]
	nl := bytes.IndexByte(b, '\n')
	if nl < 0 {
		return "", "", true, errShebangLong
	}
	line := b[2:nl]
	if bytes.IndexByte(line, 0) >= 0 {
		return "", "", true, errShebangNUL
	}
	start, end := 0, len(line)
	for start < end && spacetab(line[start]) {
		start++
	}
	for end > start && spacetab(line[end-1]) {
		end--
	}
	line = line[start:end]
	if len(line) == 0 {
		return "", "", true, errShebangEmpty
	}
	i := bytes.IndexFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
	if i < 0 {
		return string(line), "", true, nil
	}
	rest := line[i:]
	for len(rest) > 0 && spacetab(rest[0]) {
		rest = rest[1:]
	}
	return string(line[:i]), string(rest), true, nil
}

// gnuListed are the GNU coreutils programs on POLICY §5's lists, whose
// names a GNU coreutils binary is searched for.
func gnuListed() []string {
	var out []string
	for _, n := range gnuPrograms {
		if _, _, denied := hardDeniedName(n); denied {
			out = append(out, n)
		}
	}
	return out
}

// ProbeContent reads the file at p (size bytes, from os.Stat) once, in
// bounded chunks, and returns what it holds. It fails closed: a file it
// cannot read whole, or one larger than 1 GiB, is an error.
func ProbeContent(p string, size int64) (Content, error) {
	if size > maxContentBytes {
		return Content{}, errContentTooLarge
	}
	f, err := os.Open(p) //nolint:gosec // G304: a resolved command binary or interpreter, ownership-checked before
	if err != nil {
		return Content{}, fmt.Errorf("cannot be read: %s", errReason(err))
	}
	defer func() { _ = f.Close() }()
	r := io.LimitReader(f, size)
	head := make([]byte, shebangBytes)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return Content{}, fmt.Errorf("cannot be read: %s", errReason(err))
	}
	head = head[:n]
	if interp, arg, ok, serr := parseShebang(head); ok {
		return Content{Kind: ContentScript, Interpreter: interp, Arg: arg}, serr
	}
	pats := make([][]byte, 0, len(markers))
	kinds := make([]string, 0, len(markers))
	for k, m := range markers {
		pats, kinds = append(pats, []byte(m)), append(kinds, k)
	}
	found, err := scanFor(io.MultiReader(bytes.NewReader(head), r), pats, contentChunk)
	if err != nil {
		return Content{}, err
	}
	has := func(k string) bool { return found[slices.Index(kinds, k)] }
	c := Content{}
	switch {
	case has("busybox"):
		c.Kind = ContentBusyBox
	case has("toybox") || has("toybox-url"):
		c.Kind = ContentToybox
	case has("uutils"):
		c.Kind = ContentUutils
	case (has("gnu") || has("gnu-note")) && has("gnu-multi"):
		c.Kind = ContentGNUMulti
	case has("gnu") || has("gnu-note"):
		// A second pass, for GNU coreutils programs only (they are small),
		// keeps the first one to the few markers for every other binary.
		c.Kind = ContentGNU
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return Content{}, fmt.Errorf("cannot be read: %s", errReason(err))
		}
		listed := gnuListed()
		names := make([][]byte, len(listed))
		for i, name := range listed {
			names[i] = []byte("\x00" + name + "\x00")
		}
		hit, err := scanFor(io.LimitReader(f, size), names, contentChunk)
		if err != nil {
			return Content{}, err
		}
		for i, name := range listed {
			if hit[i] {
				c.Names = append(c.Names, name)
			}
		}
	}
	return c, nil
}

// ContentCache remembers what each file holds, by device and inode, for one
// policy load: the commands on one multi-call binary (every uutils utility
// is a hard link to it) and the interpreters several scripts share are read
// once.
type ContentCache map[[2]uint64]Content

// Probe returns ProbeContent for a file that os.Stat described as fi, read
// once per load; dev and ino identify it.
func (cc ContentCache) Probe(p string, dev, ino uint64, size int64) (Content, error) {
	k := [2]uint64{dev, ino}
	if c, ok := cc[k]; ok {
		return c, nil
	}
	c, err := ProbeContent(p, size)
	if err != nil {
		return c, err
	}
	cc[k] = c
	return c, nil
}

// scanFor reports which of pats occur in r, reading it once in chunks of
// chunk bytes that overlap by the longest pattern less one byte, so a match
// across two reads is found.
func scanFor(r io.Reader, pats [][]byte, chunk int) ([]bool, error) {
	found := make([]bool, len(pats))
	keep := 0
	for _, p := range pats {
		keep = max(keep, len(p)-1)
	}
	buf := make([]byte, keep+max(chunk, 1))
	tail := 0
	for {
		n, err := io.ReadFull(r, buf[tail:])
		w := buf[:tail+n]
		for i, p := range pats {
			if !found[i] && bytes.Contains(w, p) {
				found[i] = true
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return found, nil
			}
			return nil, fmt.Errorf("cannot be read: %s", errReason(err))
		}
		tail = min(keep, len(w))
		copy(buf, w[len(w)-tail:])
	}
}
