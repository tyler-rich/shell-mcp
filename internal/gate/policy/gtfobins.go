package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// GTFOBins warnings (POLICY §6). check-policy warns about every policy
// command whose binary has documented escape techniques, so the owner
// reviews its templates. The warnings never block.
//
// Licensing: GTFOBins (https://gtfobins.org/) is GPL-3.0 and this
// repository is Apache-2.0, so nothing here is copied or generated from
// GTFOBins' text or data files. This is this project's own list: binary
// names a gate policy might plausibly declare (hard-denied binaries and the
// built-in operations are left out, since the policy already refuses
// them), each with this project's own four coarse categories, written from
// the binaries' documented behaviour. The names were checked against the
// public index (each has an entry there), which the warning links to.

// Our categories.
const (
	techExec  = "command execution"
	techRead  = "file read"
	techWrite = "file write"
	techSUID  = "SUID abuse"
)

// gtfobins maps a binary's base name to our categories.
var gtfobins = map[string][]string{
	"ansible-playbook": {techExec},
	"apt":              {techExec},
	"apt-get":          {techExec},
	"aria2c":           {techExec, techWrite},
	"base64":           {techRead, techSUID},
	"basenc":           {techRead},
	"bzip2":            {techRead, techSUID},
	"cat":              {techRead, techSUID},
	"chmod":            {techSUID},
	"chown":            {techSUID},
	"column":           {techRead},
	"comm":             {techRead},
	"composer":         {techExec},
	"cp":               {techRead, techWrite, techSUID},
	"cpan":             {techExec},
	"cpio":             {techRead, techWrite},
	"csplit":           {techRead, techWrite},
	"curl":             {techRead, techWrite, techSUID},
	"cut":              {techRead, techSUID},
	"date":             {techRead, techSUID},
	"diff":             {techRead, techSUID},
	"dmesg":            {techExec},
	"docker":           {techExec, techRead, techWrite, techSUID},
	"dpkg":             {techExec},
	"dstat":            {techExec},
	"easy_install":     {techExec},
	"expand":           {techRead},
	"facter":           {techExec},
	"file":             {techRead},
	"find":             {techExec, techWrite, techSUID},
	"fmt":              {techRead},
	"fold":             {techRead},
	"gcc":              {techExec, techRead, techWrite},
	"gem":              {techExec},
	"genisoimage":      {techRead},
	"grep":             {techRead, techSUID},
	"gzip":             {techRead, techSUID},
	"head":             {techRead, techSUID},
	"hexdump":          {techRead},
	"iconv":            {techRead, techWrite},
	"iftop":            {techExec},
	"ip":               {techExec, techRead, techSUID},
	"jq":               {techRead, techSUID},
	"kubectl":          {techRead, techSUID},
	"look":             {techRead},
	"mail":             {techExec},
	"make":             {techExec, techSUID},
	"mysql":            {techExec},
	"nl":               {techRead},
	"nmap":             {techExec, techRead, techWrite},
	"npm":              {techExec},
	"od":               {techRead},
	"openssl":          {techExec, techRead, techWrite, techSUID},
	"pip":              {techExec, techRead, techWrite},
	"psql":             {techExec},
	"puppet":           {techExec},
	"rev":              {techRead},
	"rpm":              {techExec},
	"sed":              {techExec, techRead, techWrite},
	"service":          {techExec},
	"shuf":             {techRead, techWrite},
	"sort":             {techRead},
	"split":            {techExec, techWrite},
	"sqlite3":          {techExec, techRead, techWrite},
	"ssh-keygen":       {techExec},
	"strings":          {techRead},
	"tac":              {techRead},
	"tail":             {techRead, techSUID},
	"tar":              {techExec, techRead, techWrite},
	"tcpdump":          {techExec},
	"tee":              {techWrite, techSUID},
	"timedatectl":      {techExec},
	"ul":               {techRead},
	"uniq":             {techRead},
	"unzip":            {techWrite},
	"wget":             {techExec, techRead, techWrite, techSUID},
	"xxd":              {techRead, techWrite, techSUID},
	"xz":               {techRead},
	"yum":              {techExec},
	"zip":              {techExec, techRead},
	"zsoelim":          {techRead},
	"zypper":           {techExec},
}

// gtfobinsURL is the public page for a listed binary.
func gtfobinsURL(name string) string { return "https://gtfobins.org/gtfobins/" + name + "/" }

// EscapeTechniques returns our categories for a binary's base name, or nil
// when it is not listed.
func EscapeTechniques(base string) []string {
	cats, ok := gtfobins[base]
	if !ok {
		return nil
	}
	return slices.Clone(cats)
}

// How a binary was found to be a listed program (the warning names it).
const (
	MatchKindWritten  = "written name"
	MatchKindResolved = "resolved name"
	MatchKindIdentity = "binary identity"
)

// ListedMatch is a GTFOBins-listed program that a binary is, and how it was
// found: by the name written, the name resolved, or its identity (the same
// file, by device and inode or by content, as a scanned system binary of that
// name; handoff N-33).
type ListedMatch struct {
	// Name is the listed (canonical) name.
	Name string
	// Kind is a MatchKind constant.
	Kind string
	// Detail says what the identity was found against, "" otherwise.
	Detail string
}

// listedOf is the listed name a path's base name has, or "".
func listedOf(p string) string {
	n := CanonicalName(filepath.Base(p))
	if EscapeTechniques(n) == nil {
		return ""
	}
	return n
}

// ListedMatches returns, in order, the listed programs a binary is: the one
// its written name or else its resolved name gives (as before N-33), then
// each other one it is by identity (ident), once per listed name.
func ListedMatches(written, resolved string, ident []ListedMatch) []ListedMatch {
	return matchesOf(written, resolved, ident, func(n string) bool { return EscapeTechniques(n) != nil })
}

// matchesOf is ListedMatches for the canonical names listed reports.
func matchesOf(written, resolved string, ident []ListedMatch, listed func(string) bool) []ListedMatch {
	var out []ListedMatch
	if n := CanonicalName(filepath.Base(written)); listed(n) {
		out = append(out, ListedMatch{Name: n, Kind: MatchKindWritten})
	} else if n := CanonicalName(filepath.Base(resolved)); listed(n) {
		out = append(out, ListedMatch{Name: n, Kind: MatchKindResolved})
	}
	for _, m := range ident {
		if listed(m.Name) && !slices.ContainsFunc(out, func(o ListedMatch) bool { return o.Name == m.Name }) {
			m.Kind = MatchKindIdentity
			out = append(out, m)
		}
	}
	return out
}

func (m ListedMatch) suffix() string {
	s := "; matched " + m.Name + " by " + m.Kind
	if m.Detail != "" {
		s += " (" + m.Detail + ")"
	}
	return s
}

// EscapeWarnings is check-policy's warnings for the command at field whose
// binary, written at written and resolved to resolved, is a program with
// documented escape techniques: one for the program its written name, else
// its resolved name gives, and one for each other listed program it is by
// identity (ident, from the identity scan). Each names the listed program
// and how it matched. The gate's and the privileged policy share it and
// this list (handoff N-16, N-33); asRoot says the command runs as root.
func EscapeWarnings(field string, asRoot bool, written, resolved string, ident []ListedMatch) []string {
	who := ""
	if asRoot {
		who = "it runs as root: "
	}
	var out []string
	for _, m := range ListedMatches(written, resolved, ident) {
		out = append(out, fmt.Sprintf("%s: %s has documented escape techniques (GTFOBins: %s); %sreview its templates and never pass {path:write} to it (%s)%s",
			field, m.Name, strings.Join(EscapeTechniques(m.Name), ", "), who, gtfobinsURL(m.Name), m.suffix()))
	}
	return out
}

// ScriptEscapeWarnings is check-policy's warnings for a #! script, at
// field, whose interpreter (written in the #! line as written, resolved to
// resolved, with identity matches ident as in EscapeWarnings) is a program
// with documented escape techniques, naming the script, the interpreter
// and the listed program (handoff N-31, N-33). The interpreter gets the
// template's arguments after the script, so a listed interpreter is as
// reachable through a script as when declared itself. asRoot is as in
// EscapeWarnings.
func ScriptEscapeWarnings(field string, asRoot bool, script, written, resolved string, ident []ListedMatch) []string {
	who := ""
	if asRoot {
		who = "it runs as root: "
	}
	var out []string
	for _, m := range ListedMatches(written, resolved, ident) {
		out = append(out, fmt.Sprintf("%s: %s is a #! script run by %s, which has documented escape techniques (GTFOBins: %s); %sreview the script and its templates, and never pass {path:write} to it (%s)%s",
			field, script, resolved, strings.Join(EscapeTechniques(m.Name), ", "), who, gtfobinsURL(m.Name), m.suffix()))
	}
	return out
}

// GTFOBinsNames returns the listed names, sorted.
func GTFOBinsNames() []string {
	names := make([]string, 0, len(gtfobins))
	for n := range gtfobins {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
