package policy

import (
	"slices"
	"sort"
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
	"ansible-playbook":  {techExec},
	"apt":               {techExec},
	"apt-get":           {techExec},
	"aria2c":            {techExec, techWrite},
	"base64":            {techRead, techSUID},
	"basenc":            {techRead},
	"busctl":            {techExec},
	"bzip2":             {techRead, techSUID},
	"cat":               {techRead, techSUID},
	"chmod":             {techSUID},
	"chown":             {techSUID},
	"column":            {techRead},
	"comm":              {techRead},
	"composer":          {techExec},
	"cp":                {techRead, techWrite, techSUID},
	"cpan":              {techExec},
	"cpio":              {techRead, techWrite},
	"csplit":            {techRead, techWrite},
	"curl":              {techRead, techWrite, techSUID},
	"cut":               {techRead, techSUID},
	"date":              {techRead, techSUID},
	"diff":              {techRead, techSUID},
	"dmesg":             {techExec},
	"docker":            {techExec, techRead, techWrite, techSUID},
	"dpkg":              {techExec},
	"dstat":             {techExec},
	"easy_install":      {techExec},
	"expand":            {techRead},
	"facter":            {techExec},
	"file":              {techRead},
	"find":              {techExec, techWrite, techSUID},
	"fmt":               {techRead},
	"fold":              {techRead},
	"gcc":               {techExec, techRead, techWrite},
	"gem":               {techExec},
	"genisoimage":       {techRead},
	"grep":              {techRead, techSUID},
	"gzip":              {techRead, techSUID},
	"head":              {techRead, techSUID},
	"hexdump":           {techRead},
	"iconv":             {techRead, techWrite},
	"iftop":             {techExec},
	"ip":                {techExec, techRead, techSUID},
	"jq":                {techRead, techSUID},
	"kubectl":           {techRead, techSUID},
	"logsave":           {techExec},
	"look":              {techRead},
	"mail":              {techExec},
	"make":              {techExec, techSUID},
	"mysql":             {techExec},
	"nl":                {techRead},
	"nmap":              {techExec, techRead, techWrite},
	"npm":               {techExec},
	"od":                {techRead},
	"openssl":           {techExec, techRead, techWrite, techSUID},
	"pip":               {techExec, techRead, techWrite},
	"psql":              {techExec},
	"puppet":            {techExec},
	"rev":               {techRead},
	"rpm":               {techExec},
	"run-parts":         {techExec},
	"sed":               {techExec, techRead, techWrite},
	"service":           {techExec},
	"shuf":              {techRead, techWrite},
	"sort":              {techRead},
	"split":             {techExec, techWrite},
	"sqlite3":           {techExec, techRead, techWrite},
	"ssh-keygen":        {techExec},
	"start-stop-daemon": {techExec},
	"strings":           {techRead},
	"tac":               {techRead},
	"tail":              {techRead, techSUID},
	"tar":               {techExec, techRead, techWrite},
	"taskset":           {techExec},
	"tcpdump":           {techExec},
	"tee":               {techWrite, techSUID},
	"timedatectl":       {techExec},
	"ul":                {techRead},
	"uniq":              {techRead},
	"unzip":             {techWrite},
	"wget":              {techExec, techRead, techWrite, techSUID},
	"xxd":               {techRead, techWrite, techSUID},
	"xz":                {techRead},
	"yum":               {techExec},
	"zip":               {techExec, techRead},
	"zsoelim":           {techRead},
	"zypper":            {techExec},
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

// GTFOBinsNames returns the listed names, sorted.
func GTFOBinsNames() []string {
	names := make([]string, 0, len(gtfobins))
	for n := range gtfobins {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
