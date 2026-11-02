// Package gen is `policy new` (docs/POLICY.md §9): the answers file, its
// strict decoder and the presets' rules, the rendering of a policy from an
// example file used as a template, and the run that loads the rendered
// policy strictly and writes it through the install commands' write
// helper. shell-mcp-gate renders the gate policy here; shell-mcp-privd
// renders its own (internal/privd/policy/gen) from the same answers, so
// the gate binary never links the privileged loader.
package gen

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// MaxAnswersBytes bounds the answers file.
const MaxAnswersBytes = 256 << 10

// Bounds on a carried comment (POLICY §9.3).
const (
	maxCommentLines    = 64
	maxCommentLineSize = 256
)

// Presets (POLICY §9.2).
const (
	PresetReadOnly = "read-only"
	PresetOperator = "operator"
	PresetAdmin    = "admin"
)

// Landlock modes an answers file may name.
const (
	LandlockRequired   = "required"
	LandlockBestEffort = "best-effort"
)

// Answers is a decoded answers file (POLICY §9.1). Empty lists are absent;
// a nil section is absent.
type Answers struct {
	Preset   string
	Account  Account
	Landlock string // "" for the preset's
	Read     []string
	Write    []string
	Deny     []string
	Services *Services
	Journal  *Journal
	Git      *Git
	Commands []Command
	Root     *Root
	// Header is the answers file's opening comment, as text lines (no "#").
	Header string
}

// Account is the service account.
type Account struct {
	User string
	UID  int64
}

// Services are the gate's service sections.
type Services struct {
	Status  []string
	Control *Control
}

// Control is services.control.
type Control struct {
	Units []string
	Verbs []string
}

// Journal is the gate's journal section.
type Journal struct{ Units []string }

// Git is the gate's git section.
type Git struct{ Repos []Repo }

// Repo is one repository.
type Repo struct{ Path, Remote string }

// Command is one gate command; Comment is the comment above its entry.
type Command struct {
	ID, Path, Tier, Description string
	RootEquivalent              bool
	ReadsPrivateKeys            bool
	Templates                   [][]string
	Comment                     string
}

// Root is the privileged half of the answers.
type Root struct {
	SocketGroup Group
	Read        []string
	Write       []string
	Persistence []Persistence
	Owners      *Owners
	Commands    []RootCommand
	Power       *Power
	Packages    *Packages
	// Comment is the comment directly above root:, as text lines.
	Comment string
}

// Group is the socket group.
type Group struct {
	Name string
	GID  int64
}

// Persistence is one persistence root and its acknowledge.
type Persistence struct{ Path, Acknowledge string }

// Owners are the privileged owners.
type Owners struct{ Users, Groups []string }

// RootCommand is one privileged command.
type RootCommand struct {
	ID, Path, Tier, Unit, Description string
	RootEquivalent                    bool
	ReadsPrivateKeys                  bool
	Capabilities                      []string
	Acknowledge                       string
	Templates                         [][]string
	Comment                           string
}

// Power is the privileged power section.
type Power struct {
	Allowed     []string
	Acknowledge string
}

// Packages is the privileged packages section.
type Packages struct {
	Install, Remove                              []string
	AllowUpdateIndex, AllowUpgrade, AllowRecover bool
}

// UsesBroad reports whether the privileged policy from these answers uses
// the broad unit (PRIVILEGED §2: packages, power, or a unit: broad command).
func (a *Answers) UsesBroad() bool {
	if a.Root == nil {
		return false
	}
	if a.Root.Packages != nil || a.Root.Power != nil {
		return true
	}
	for i := range a.Root.Commands {
		if a.Root.Commands[i].Unit == "broad" {
			return true
		}
	}
	return false
}

// Error is a refused answers file; Key is the answers key ("" for the file).
type Error struct{ Key, Msg string }

func (e *Error) Error() string {
	if e.Key == "" {
		return "answers: " + e.Msg
	}
	return "answers " + e.Key + ": " + e.Msg
}

// The raw schema: pointers tell "absent" from zero; KnownFields(true) makes
// any other key an error.
type rawAnswers struct {
	Preset   *string      `yaml:"preset"`
	Account  *rawAccount  `yaml:"account"`
	Landlock *string      `yaml:"landlock"`
	Read     []string     `yaml:"read"`
	Write    []string     `yaml:"write"`
	Deny     []string     `yaml:"deny"`
	Services *rawServices `yaml:"services"`
	Journal  *rawJournal  `yaml:"journal"`
	Git      *rawGit      `yaml:"git"`
	Commands []rawCommand `yaml:"commands"`
	Root     *rawRoot     `yaml:"root"`
}

type rawAccount struct {
	User *string `yaml:"user"`
	UID  *int64  `yaml:"uid"`
}

type rawServices struct {
	Status  []string    `yaml:"status"`
	Control *rawControl `yaml:"control"`
}

type rawControl struct {
	Units []string `yaml:"units"`
	Verbs []string `yaml:"verbs"`
}

type rawJournal struct {
	Units []string `yaml:"units"`
}

type rawGit struct {
	Repos []rawRepo `yaml:"repos"`
}

type rawRepo struct {
	Path   string `yaml:"path"`
	Remote string `yaml:"remote"`
}

type rawCommand struct {
	ID               string     `yaml:"id"`
	Path             string     `yaml:"path"`
	Tier             string     `yaml:"tier"`
	Description      string     `yaml:"description"`
	RootEquivalent   bool       `yaml:"root_equivalent"`
	ReadsPrivateKeys bool       `yaml:"reads_private_keys"`
	Templates        [][]string `yaml:"templates"`
}

type rawRoot struct {
	SocketGroup *rawGroup        `yaml:"socket_group"`
	Read        []string         `yaml:"read"`
	Write       []string         `yaml:"write"`
	Persistence []rawPersistence `yaml:"persistence"`
	Owners      *rawOwners       `yaml:"owners"`
	Commands    []rawRootCommand `yaml:"commands"`
	Power       *rawPower        `yaml:"power"`
	Packages    *rawPackages     `yaml:"packages"`
}

type rawGroup struct {
	Name *string `yaml:"name"`
	GID  *int64  `yaml:"gid"`
}

type rawPersistence struct {
	Path        string `yaml:"path"`
	Acknowledge string `yaml:"acknowledge"`
}

type rawOwners struct {
	Users  []string `yaml:"users"`
	Groups []string `yaml:"groups"`
}

type rawRootCommand struct {
	ID               string     `yaml:"id"`
	Path             string     `yaml:"path"`
	Tier             string     `yaml:"tier"`
	Unit             string     `yaml:"unit"`
	Description      string     `yaml:"description"`
	RootEquivalent   bool       `yaml:"root_equivalent"`
	ReadsPrivateKeys bool       `yaml:"reads_private_keys"`
	Capabilities     []string   `yaml:"capabilities"`
	Acknowledge      string     `yaml:"acknowledge"`
	Templates        [][]string `yaml:"templates"`
}

type rawPower struct {
	Allowed     []string `yaml:"allowed"`
	Acknowledge string   `yaml:"acknowledge"`
}

type rawPackages struct {
	Install          []string `yaml:"install"`
	Remove           []string `yaml:"remove"`
	AllowUpdateIndex bool     `yaml:"allow_update_index"`
	AllowUpgrade     bool     `yaml:"allow_upgrade"`
	AllowRecover     bool     `yaml:"allow_recover"`
}

var (
	userRE  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	groupRE = userRE
)

// Decode decodes an answers file strictly (unknown keys, wrong types,
// duplicate keys and more than one document are errors), applies the
// presets' rules (POLICY §9.2) and reads the carried comments (§9.3).
// Every value the policies need is checked by their own loaders later;
// Decode checks only what the answers file itself means.
func Decode(data []byte) (*Answers, error) {
	if len(data) > MaxAnswersBytes {
		return nil, &Error{"", fmt.Sprintf("the file is larger than %d bytes", MaxAnswersBytes)}
	}
	var raw rawAnswers
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &Error{"", "the file is empty"}
		}
		return nil, &Error{"", err.Error()}
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, &Error{"", "the file must be a single YAML document"}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, &Error{"", err.Error()}
	}
	a, err := fromRaw(&raw)
	if err != nil {
		return nil, err
	}
	if err := a.comments(&doc); err != nil {
		return nil, err
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return a, nil
}

func fromRaw(raw *rawAnswers) (*Answers, error) {
	a := &Answers{Read: raw.Read, Write: raw.Write, Deny: raw.Deny}
	if raw.Preset == nil {
		return nil, &Error{"preset", "is required (read-only, operator or admin)"}
	}
	a.Preset = *raw.Preset
	if raw.Account == nil || raw.Account.User == nil || raw.Account.UID == nil {
		return nil, &Error{"account", "is required: { user: <name>, uid: <n> }"}
	}
	a.Account = Account{User: *raw.Account.User, UID: *raw.Account.UID}
	if raw.Landlock != nil {
		a.Landlock = *raw.Landlock
		if a.Landlock == "" {
			return nil, &Error{"landlock", "is empty; give required or best-effort, or leave it out"}
		}
	}
	if s := raw.Services; s != nil && (len(s.Status) > 0 || s.Control != nil && (len(s.Control.Units) > 0 || len(s.Control.Verbs) > 0)) {
		a.Services = &Services{Status: s.Status}
		if c := s.Control; c != nil && (len(c.Units) > 0 || len(c.Verbs) > 0) {
			a.Services.Control = &Control{Units: c.Units, Verbs: c.Verbs}
		}
	}
	if j := raw.Journal; j != nil && len(j.Units) > 0 {
		a.Journal = &Journal{Units: j.Units}
	}
	if g := raw.Git; g != nil && len(g.Repos) > 0 {
		a.Git = &Git{}
		for _, r := range g.Repos {
			a.Git.Repos = append(a.Git.Repos, Repo(r))
		}
	}
	for _, c := range raw.Commands {
		a.Commands = append(a.Commands, Command{ID: c.ID, Path: c.Path, Tier: c.Tier, Description: c.Description,
			RootEquivalent: c.RootEquivalent, ReadsPrivateKeys: c.ReadsPrivateKeys, Templates: c.Templates})
	}
	if r := raw.Root; r != nil {
		root := &Root{Read: r.Read, Write: r.Write}
		if r.SocketGroup == nil || r.SocketGroup.Name == nil || r.SocketGroup.GID == nil {
			return nil, &Error{"root.socket_group", "is required: { name: <group>, gid: <n> }"}
		}
		root.SocketGroup = Group{Name: *r.SocketGroup.Name, GID: *r.SocketGroup.GID}
		for _, p := range r.Persistence {
			root.Persistence = append(root.Persistence, Persistence(p))
		}
		if o := r.Owners; o != nil && (len(o.Users) > 0 || len(o.Groups) > 0) {
			root.Owners = &Owners{Users: o.Users, Groups: o.Groups}
		}
		for i := range r.Commands {
			c := &r.Commands[i]
			root.Commands = append(root.Commands, RootCommand{ID: c.ID, Path: c.Path, Tier: c.Tier, Unit: c.Unit, Description: c.Description,
				RootEquivalent: c.RootEquivalent, ReadsPrivateKeys: c.ReadsPrivateKeys, Capabilities: c.Capabilities,
				Acknowledge: c.Acknowledge, Templates: c.Templates})
		}
		if p := r.Power; p != nil {
			root.Power = &Power{Allowed: p.Allowed, Acknowledge: p.Acknowledge}
		}
		if p := r.Packages; p != nil {
			root.Packages = &Packages{Install: p.Install, Remove: p.Remove,
				AllowUpdateIndex: p.AllowUpdateIndex, AllowUpgrade: p.AllowUpgrade, AllowRecover: p.AllowRecover}
		}
		a.Root = root
	}
	return a, nil
}

// comments reads the carried comments (POLICY §9.3) from the document:
// its opening comment, the comment above each commands entry, the comment
// above root: and above each root.commands entry.
func (a *Answers) comments(doc *yaml.Node) error {
	var err error
	if a.Header, err = commentText("the opening comment", doc.HeadComment); err != nil {
		return err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return &Error{"", "the file must be a mapping"}
	}
	top := doc.Content[0]
	err = entryComments("commands", value(top, "commands"), len(a.Commands), func(i int, c string) { a.Commands[i].Comment = c })
	if err != nil {
		return err
	}
	k, v := keyValue(top, "root")
	if a.Root == nil || k == nil {
		return nil
	}
	if a.Root.Comment, err = commentText("the comment above root", k.HeadComment); err != nil {
		return err
	}
	return entryComments("root.commands", value(v, "commands"), len(a.Root.Commands), func(i int, c string) { a.Root.Commands[i].Comment = c })
}

func entryComments(key string, seq *yaml.Node, n int, set func(int, string)) error {
	if seq == nil || seq.Kind != yaml.SequenceNode || len(seq.Content) != n {
		return nil
	}
	for i, item := range seq.Content {
		c, err := commentText(fmt.Sprintf("%s[%d]'s comment", key, i), item.HeadComment)
		if err != nil {
			return err
		}
		set(i, c)
	}
	return nil
}

func keyValue(m *yaml.Node, key string) (k, v *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

func value(m *yaml.Node, key string) *yaml.Node {
	_, v := keyValue(m, key)
	return v
}

// commentText turns a YAML comment ("# a\n#\n# b") into its text lines
// ("a\n\nb"): one "#" and one following space removed from each line. The
// text is then checked as any carried comment is.
func commentText(what, c string) (string, error) {
	if c == "" {
		return "", nil
	}
	lines := strings.Split(c, "\n")
	for i, l := range lines {
		l = strings.TrimLeft(l, " \t")
		if strings.HasPrefix(l, "#") {
			l = strings.TrimPrefix(l[1:], " ")
		}
		lines[i] = l
	}
	text := strings.Join(lines, "\n")
	if err := CheckComment(text); err != nil {
		return "", &Error{"", what + ": " + err.Error()}
	}
	return text, nil
}

// CommentLines splits a carried comment into its lines: CR, LF and CRLF
// are line breaks.
func CommentLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.Split(text, "\n")
}

// CheckComment applies POLICY §9.3's rules to a carried comment: valid
// UTF-8, no control character (CR and LF only as line breaks), none of
// U+0085, U+2028, U+2029 and U+FEFF, at most maxCommentLines lines of at
// most maxCommentLineSize bytes.
func CheckComment(text string) error {
	lines := CommentLines(text)
	if len(lines) > maxCommentLines {
		return fmt.Errorf("has more than %d lines", maxCommentLines)
	}
	for i, l := range lines {
		if len(l) > maxCommentLineSize {
			return fmt.Errorf("line %d is longer than %d bytes", i+1, maxCommentLineSize)
		}
		if err := checkText(l); err != nil {
			return fmt.Errorf("line %d %w", i+1, err)
		}
	}
	return nil
}

// checkText refuses invalid UTF-8, control characters and the characters
// some YAML readers take as line breaks or a byte-order mark.
func checkText(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("is not valid UTF-8")
	}
	for _, r := range s {
		switch {
		case r == 0x85 || r == 0x2028 || r == 0x2029 || r == 0xfeff:
			return fmt.Errorf("holds U+%04X, which is refused", r)
		case unicode.IsControl(r):
			return fmt.Errorf("holds the control character U+%04X", r)
		}
	}
	return nil
}

// Validate applies the presets' rules (POLICY §9.2) and the answers file's
// own (account, landlock, the socket group, text values).
func (a *Answers) Validate() error {
	switch a.Preset {
	case PresetReadOnly, PresetOperator, PresetAdmin:
	default:
		return &Error{"preset", fmt.Sprintf("is %q; want read-only, operator or admin", a.Preset)}
	}
	if !userRE.MatchString(a.Account.User) {
		return &Error{"account.user", fmt.Sprintf("%q is not a user name (%s)", a.Account.User, userRE)}
	}
	if a.Account.UID < 1 || a.Account.UID > 4294967294 {
		return &Error{"account.uid", fmt.Sprintf("%d is not in 1..4294967294 (the service account is never root)", a.Account.UID)}
	}
	switch a.Landlock {
	case "", LandlockRequired, LandlockBestEffort:
	default:
		return &Error{"landlock", fmt.Sprintf("is %q; want required or best-effort", a.Landlock)}
	}
	refuse := func(key, why string) error {
		return &Error{key, fmt.Sprintf("is not allowed under the %s preset (%s)", a.Preset, why)}
	}
	if a.Preset == PresetReadOnly {
		switch {
		case len(a.Write) > 0:
			return refuse("write", "a read-only key writes nothing; use operator or admin")
		case a.Services != nil && a.Services.Control != nil:
			return refuse("services.control", "a read-only key changes no service; use operator or admin")
		}
	}
	if a.Root != nil && a.Preset != PresetAdmin {
		return refuse("root", "root actions need the admin preset")
	}
	if r := a.Root; r != nil {
		if !groupRE.MatchString(r.SocketGroup.Name) {
			return &Error{"root.socket_group.name", fmt.Sprintf("%q is not a group name (%s)", r.SocketGroup.Name, groupRE)}
		}
		if r.SocketGroup.GID < 1 || r.SocketGroup.GID > 4294967294 {
			return &Error{"root.socket_group.gid", fmt.Sprintf("%d is not in 1..4294967294", r.SocketGroup.GID)}
		}
		if p := r.Packages; p != nil && len(p.Install) == 0 && len(p.Remove) == 0 && !p.AllowUpdateIndex && !p.AllowUpgrade && !p.AllowRecover {
			return &Error{"root.packages", "allows nothing; leave it out (it would enable the root-equivalent broad unit for no operation)"}
		}
	}
	for _, t := range a.texts() {
		if err := checkText(t.s); err != nil {
			return &Error{t.key, fmt.Sprintf("%q %v", t.s, err)}
		}
	}
	for _, c := range []struct{ what, text string }{{"the opening comment", a.Header}} {
		if err := CheckComment(c.text); err != nil {
			return &Error{"", c.what + ": " + err.Error()}
		}
	}
	return nil
}

type keyed struct{ key, s string }

// texts lists every string value with its answers key.
func (a *Answers) texts() []keyed {
	var out []keyed
	list := func(key string, l []string) {
		for i, s := range l {
			out = append(out, keyed{fmt.Sprintf("%s[%d]", key, i), s})
		}
	}
	templates := func(key string, ts [][]string) {
		for i, t := range ts {
			list(fmt.Sprintf("%s.templates[%d]", key, i), t)
		}
	}
	list("read", a.Read)
	list("write", a.Write)
	list("deny", a.Deny)
	if s := a.Services; s != nil {
		list("services.status", s.Status)
		if c := s.Control; c != nil {
			list("services.control.units", c.Units)
			list("services.control.verbs", c.Verbs)
		}
	}
	if a.Journal != nil {
		list("journal.units", a.Journal.Units)
	}
	if a.Git != nil {
		for i, r := range a.Git.Repos {
			out = append(out, keyed{fmt.Sprintf("git.repos[%d].path", i), r.Path}, keyed{fmt.Sprintf("git.repos[%d].remote", i), r.Remote})
		}
	}
	for i, c := range a.Commands {
		k := fmt.Sprintf("commands[%d]", i)
		out = append(out, keyed{k + ".id", c.ID}, keyed{k + ".path", c.Path}, keyed{k + ".tier", c.Tier}, keyed{k + ".description", c.Description})
		templates(k, c.Templates)
	}
	if r := a.Root; r != nil {
		list("root.read", r.Read)
		list("root.write", r.Write)
		for i, p := range r.Persistence {
			k := fmt.Sprintf("root.persistence[%d]", i)
			out = append(out, keyed{k + ".path", p.Path}, keyed{k + ".acknowledge", p.Acknowledge})
		}
		if o := r.Owners; o != nil {
			list("root.owners.users", o.Users)
			list("root.owners.groups", o.Groups)
		}
		for i := range r.Commands {
			c := &r.Commands[i]
			k := fmt.Sprintf("root.commands[%d]", i)
			out = append(out, keyed{k + ".id", c.ID}, keyed{k + ".path", c.Path}, keyed{k + ".tier", c.Tier}, keyed{k + ".unit", c.Unit},
				keyed{k + ".description", c.Description}, keyed{k + ".acknowledge", c.Acknowledge})
			list(k+".capabilities", c.Capabilities)
			templates(k, c.Templates)
		}
		if p := r.Power; p != nil {
			list("root.power.allowed", p.Allowed)
			out = append(out, keyed{"root.power.acknowledge", p.Acknowledge})
		}
		if p := r.Packages; p != nil {
			list("root.packages.install", p.Install)
			list("root.packages.remove", p.Remove)
		}
	}
	return out
}
