// Package compose renders `shell-mcp init compose`: the reference deployment
// (deploy/docker-compose.yml, embedded as a byte copy that a test holds equal
// to it) with one deployment's values in place, in the secrets form (compose
// secrets: next to init's directory) or the bind form (one read-only bind
// mount of that directory, for stack editors). Handoff §4.C.
//
// The hardening flags are not parameters: rendering replaces exactly the
// values below, each at an anchor that must occur once in the template, and
// rendering the reference values reproduces the template byte for byte.
package compose

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/tyler-rich/shell-mcp/internal/config"
	"github.com/tyler-rich/shell-mcp/internal/tools"
)

//go:embed docker-compose.yml
var template []byte

// Form is the output form.
type Form string

// The two forms.
const (
	FormSecrets Form = "secrets"
	FormBind    Form = "bind"
)

// maxHostKeys bounds --host-key.
const maxHostKeys = 8

// Values are one deployment's values.
type Values struct {
	Image       string
	HostKeys    []string
	TargetName  string
	TargetHost  string
	TargetUser  string
	MCPHost     string
	Subnet      string
	ServerAddr  string
	ProxyAddr   string
	Profile     string
	ApproveHost string
	Form        Form
	Dir         string
}

func (v *Values) equal(w *Values) bool {
	return v.Image == w.Image && slices.Equal(v.HostKeys, w.HostKeys) && v.TargetName == w.TargetName &&
		v.TargetHost == w.TargetHost && v.TargetUser == w.TargetUser && v.MCPHost == w.MCPHost && v.Subnet == w.Subnet &&
		v.ServerAddr == w.ServerAddr && v.ProxyAddr == w.ProxyAddr && v.Profile == w.Profile &&
		v.ApproveHost == w.ApproveHost && v.Form == w.Form && v.Dir == w.Dir
}

// UsageError is a flag error (exit 2); any other error from Check is a
// refusal (exit 1).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func usagef(format string, a ...any) error { return &UsageError{Msg: fmt.Sprintf(format, a...)} }

// Image is a parsed --image reference.
type Image struct{ Repository, Tag, Digest string }

// Template is the embedded copy of deploy/docker-compose.yml.
func Template() []byte { return append([]byte(nil), template...) }

// Reference is the values deploy/docker-compose.yml holds.
func Reference() Values {
	return Values{
		Image:      "ghcr.io/tyler-rich/shell-mcp:0.2.0@sha256:323149155f5be042949ec5291812104351f365a693dbdfb8cd2171b95ee30e6a",
		HostKeys:   []string{"ssh-ed25519 SHA256:placeholder"},
		TargetName: "app-host", TargetHost: "target-a.example.test", TargetUser: "svc-shell",
		MCPHost: "mcp.example.test", Subnet: "172.30.80.0/24", ServerAddr: "172.30.80.10", ProxyAddr: "172.30.80.5",
		Profile: "read-only", Form: FormSecrets,
	}
}

// Usage is init compose's usage text.
const Usage = `usage: shell-mcp init compose --image <repository>[:<tag>]@sha256:<digest> --host-key '<type> SHA256:<fingerprint>' [--host-key …]
    --target-name <name> --target-host <host> [--target-user <user>] --mcp-host <name>
    --subnet <IPv4 prefix> --server-addr <address> --proxy-addr <address>
    [--profile read-only|operator|admin] [--approve-host <name>] [--form secrets|bind] [--dir <absolute host path>]

Prints deploy/docker-compose.yml with these values in place, on stdout.
`

type pins struct{ list *[]string }

func (p pins) String() string     { return "" }
func (p pins) Set(s string) error { *p.list = append(*p.list, s); return nil }

// ParseFlags parses init compose's flags. A missing required flag, an
// unknown flag or argument, an unknown --form and --dir without --form bind
// are usage errors.
func ParseFlags(args []string) (*Values, error) {
	v := &Values{}
	fs := flag.NewFlagSet("init compose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&v.Image, "image", "", "")
	fs.Var(pins{&v.HostKeys}, "host-key", "")
	fs.StringVar(&v.TargetName, "target-name", "", "")
	fs.StringVar(&v.TargetHost, "target-host", "", "")
	fs.StringVar(&v.TargetUser, "target-user", "svc-shell", "")
	fs.StringVar(&v.MCPHost, "mcp-host", "", "")
	fs.StringVar(&v.Subnet, "subnet", "", "")
	fs.StringVar(&v.ServerAddr, "server-addr", "", "")
	fs.StringVar(&v.ProxyAddr, "proxy-addr", "", "")
	fs.StringVar(&v.Profile, "profile", "read-only", "")
	fs.StringVar(&v.ApproveHost, "approve-host", "", "")
	form := fs.String("form", string(FormSecrets), "")
	dirSet := false
	fs.Func("dir", "", func(s string) error { v.Dir, dirSet = s, true; return nil })
	if err := fs.Parse(args); err != nil {
		return nil, usagef("%v", err)
	}
	if fs.NArg() != 0 {
		return nil, usagef("unexpected argument %q", fs.Arg(0))
	}
	for _, r := range []struct{ name, val string }{{"--image", v.Image}, {"--target-name", v.TargetName}, {"--target-host", v.TargetHost},
		{"--mcp-host", v.MCPHost}, {"--subnet", v.Subnet}, {"--server-addr", v.ServerAddr}, {"--proxy-addr", v.ProxyAddr}} {
		if r.val == "" {
			return nil, usagef("missing %s", r.name)
		}
	}
	if len(v.HostKeys) == 0 {
		return nil, usagef("missing --host-key: the pin shell-mcp-gate install or host-key printed on the target")
	}
	switch Form(*form) {
	case FormSecrets, FormBind:
		v.Form = Form(*form)
	default:
		return nil, usagef("--form must be secrets or bind (got %q)", *form)
	}
	if dirSet && v.Form != FormBind {
		return nil, usagef("--dir is only for --form bind: the secrets form reads ./secrets next to the compose file")
	}
	return v, nil
}

var (
	component = `[a-z0-9]+(?:[._-][a-z0-9]+)*`
	imageRE   = regexp.MustCompile(`^((?:` + component + `(?::[0-9]{1,5})?/)?` + component + `(?:/` + component + `)*)` +
		`(?::([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?@sha256:([0-9a-f]{64})$`)
	dirRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

// ParseImage parses <repository>[:<tag>]@sha256:<64 lower-case hex>.
func ParseImage(ref string) (Image, error) {
	m := imageRE.FindStringSubmatch(ref)
	if m == nil {
		return Image{}, errors.New("--image must be <repository>[:<tag>]@sha256:<64 lower-case hex digits>: pinned by digest, a tag alone is refused")
	}
	return Image{Repository: m[1], Tag: m[2], Digest: m[3]}, nil
}

// dnsName is a host name the server accepts that is not an IP address.
func dnsName(h string) bool {
	_, err := netip.ParseAddr(h)
	return err != nil && config.ValidHost(h)
}

// Check refuses values the server, Docker or CLIENTS §1 would not accept,
// and returns the notes to print. All refusals are returned, joined.
func (v *Values) Check() (notes []string, err error) {
	var errs []error
	refuse := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if img, err := ParseImage(v.Image); err != nil {
		errs = append(errs, err)
	} else if strings.Count(img.Digest, img.Digest[:1]) == len(img.Digest) {
		refuse("--image: the digest %s is a placeholder; use the image's digest from its release notes", img.Digest)
	}
	if len(v.HostKeys) > maxHostKeys {
		refuse("--host-key: at most %d pins", maxHostKeys)
	}
	for i, p := range v.HostKeys {
		if _, ok := config.ParseHostKeyPin(p); !ok {
			refuse("--host-key %q %s", p, config.HostKeyPinFormat)
		} else if slices.Contains(v.HostKeys[:i], p) {
			refuse("--host-key %q is given twice", p)
		}
	}
	if !config.ValidTargetName(v.TargetName) {
		refuse("--target-name must match ^[a-z0-9][a-z0-9_-]{0,62}$")
	}
	if !config.ValidHost(v.TargetHost) {
		refuse("--target-host must be a DNS name or an IP address")
	}
	if !config.ValidUser(v.TargetUser) {
		refuse("--target-user must match ^[a-z_][a-z0-9_-]{0,31}$")
	}
	if !dnsName(v.MCPHost) {
		refuse("--mcp-host must be a DNS name (the name clients use, added to SHELL_MCP_ALLOWED_HOSTS)")
	}
	if v.ApproveHost != "" && !dnsName(v.ApproveHost) {
		refuse("--approve-host must be a DNS name (the approval page is https://<name>)")
	}
	errs = append(errs, v.checkAddresses()...)

	profile, perr := tools.ParseProfile(v.Profile)
	switch {
	case perr != nil:
		refuse("--profile must be read-only, operator or admin")
	case profile == tools.ProfileAdmin && v.ApproveHost == "":
		refuse("--profile admin needs --approve-host: every destructive and privileged tool needs an approval, " +
			"so admin without the approval page would only refuse those calls")
	case profile == tools.ProfileOperator && v.ApproveHost == "":
		notes = append(notes, "--profile operator without --approve-host: operator tools then run without approval "+
			"under the default SHELL_MCP_APPROVAL_TIERS (destructive); add --approve-host to require an approver's code "+
			"for them, which also sets SHELL_MCP_APPROVAL_TIERS: operator,destructive")
	case profile == tools.ProfileAdmin:
		notes = append(notes, "--profile admin: destructive and privileged operations need an approver's code; operator tools "+
			"run without approval under the default SHELL_MCP_APPROVAL_TIERS (destructive): add "+
			"SHELL_MCP_APPROVAL_TIERS: operator,destructive to the environment by hand if they should too")
	case profile == tools.ProfileReadOnly && v.ApproveHost != "":
		notes = append(notes, "--profile read-only never needs an approval; the approval page is configured but unused")
	}
	if v.ApproveHost != "" {
		notes = append(notes, "the approval page reads /run/secrets/approvers: enrol the approver with shell-mcp init --approver first")
	}

	if v.Form == FormBind {
		switch {
		case v.Dir == "":
			refuse("--form bind needs --dir, the absolute host path of init's directory")
		case !path.IsAbs(v.Dir) || path.Clean(v.Dir) != v.Dir:
			refuse("--dir %q must be an absolute, clean host path", v.Dir)
		case v.Dir == "/":
			refuse("--dir must be init's directory, not /")
		case !dirRE.MatchString(v.Dir):
			refuse("--dir holds characters other than A-Z a-z 0-9 . _ / -")
		default:
			notes = append(notes, "the bind form mounts "+v.Dir+": it must be 0700 and owned by uid 65532, as shell-mcp init makes it")
		}
	}
	return notes, errors.Join(errs...)
}

// checkAddresses: --subnet a canonical IPv4 prefix from /16 to /28, the two
// addresses distinct hosts inside it, neither its network or broadcast
// address nor its first host, which Docker gives the network's gateway (the
// trusted proxy must never be the gateway, CLIENTS §1).
func (v *Values) checkAddresses() []error {
	p, err := netip.ParsePrefix(v.Subnet)
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < 16 || p.Bits() > 28 {
		return []error{fmt.Errorf("--subnet %q must be an IPv4 prefix in canonical form (no host bits), from /16 to /28", v.Subnet)}
	}
	network := p.Addr()
	gateway := network.Next()
	broadcast := network
	for a := network; p.Contains(a); a = a.Next() {
		broadcast = a
	}
	var errs []error
	addrs := map[string]netip.Addr{}
	for _, f := range []struct{ name, val string }{{"--server-addr", v.ServerAddr}, {"--proxy-addr", v.ProxyAddr}} {
		a, err := netip.ParseAddr(f.val)
		switch {
		case err != nil || !a.Is4():
			errs = append(errs, fmt.Errorf("%s %q must be an IPv4 address", f.name, f.val))
			continue
		case !p.Contains(a):
			errs = append(errs, fmt.Errorf("%s %s is outside --subnet %s", f.name, a, p))
		case a == network:
			errs = append(errs, fmt.Errorf("%s %s is the subnet's network address", f.name, a))
		case a == broadcast:
			errs = append(errs, fmt.Errorf("%s %s is the subnet's broadcast address", f.name, a))
		case a == gateway:
			errs = append(errs, fmt.Errorf("%s %s is the subnet's first host, which Docker gives the network's gateway; "+
				"the trusted proxy must never be the gateway (CLIENTS §1)", f.name, a))
		}
		addrs[f.name] = a
	}
	if s, ok := addrs["--server-addr"]; ok && s == addrs["--proxy-addr"] {
		errs = append(errs, errors.New("--server-addr and --proxy-addr are the same address"))
	}
	return errs
}

// Anchors in the template. Each must occur exactly once.
const (
	headerRef     = "# All names, hosts and fingerprints are placeholders.\n"
	headerPrinted = "# Printed by `shell-mcp init compose` from deploy/docker-compose.yml with this deployment's values.\n"
	imageStart    = "    # The 0.2.0 image index"
	imageEnd      = "    restart:"
	mountLine     = "    secrets: [mcp_token, ssh_key]\n"
	mountBlock    = "secrets:\n  mcp_token: { file: ./secrets/mcp_token }\n  ssh_key: { file: ./secrets/ssh_key }\n"
	proxyLine     = "      SHELL_MCP_TRUSTED_PROXIES: "
)

type renderer struct {
	s   string
	err error
}

func (r *renderer) one(old, repl string) {
	if r.err != nil {
		return
	}
	if n := strings.Count(r.s, old); n != 1 {
		r.err = fmt.Errorf("template: %q occurs %d times, not once (deploy/docker-compose.yml changed: update the renderer)", old, n)
		return
	}
	r.s = strings.Replace(r.s, old, repl, 1)
}

// scalar is s as a YAML scalar: plain when YAML reads it back as exactly s,
// as every reference value does, otherwise double-quoted (a name such as
// 00000000, true or null that the server's rules accept would else reach
// Compose as a number, a boolean or null). The values rendered hold no
// quote, backslash or control character, so strconv.Quote is YAML's
// double-quoted form.
func scalar(s string) string {
	var v map[string]any
	if yaml.Unmarshal([]byte("v: "+s+"\n"), &v) == nil {
		if got, ok := v["v"].(string); ok && got == s {
			return s
		}
	}
	return strconv.Quote(s)
}

func imageBlock(img Image, ref string) string {
	if img.Tag == "" {
		return "    # The image index, pinned by digest: the digest in its release notes.\n" +
			"    # Verify it before you deploy it (README, \"Verifying a release\").\n" +
			"    image: " + scalar(ref) + "\n"
	}
	return "    # The " + img.Tag + " image index, pinned by digest: the digest in its release notes,\n" +
		"    # which is what this prints:\n" +
		"    #   docker buildx imagetools inspect " + img.Repository + ":" + img.Tag + " --format '{{.Manifest.Digest}}'\n" +
		"    # Verify it before you deploy it (README, \"Verifying a release\").\n" +
		"    image: " + scalar(ref) + "\n"
}

// Render returns the compose file for v, which Check has accepted.
func Render(v *Values) ([]byte, error) {
	img, err := ParseImage(v.Image)
	if err != nil {
		return nil, err
	}
	ref := Reference()
	r := &renderer{s: string(template)}
	if !v.equal(&ref) {
		r.one(headerRef, headerPrinted)
	}
	i, j := strings.Index(r.s, imageStart), strings.Index(r.s, imageEnd)
	if i < 0 || j < i {
		return nil, errors.New("template: the image block is not where the renderer expects it")
	}
	r.one(r.s[i:j], imageBlock(img, v.Image))
	r.one("    # 172.30.80.5 and is the only service", "    # "+v.ProxyAddr+" and is the only service")
	r.one(proxyLine+"172.30.80.5 #", proxyLine+v.ProxyAddr+" #")
	r.one("ipv4_address: 172.30.80.10\n", "ipv4_address: "+v.ServerAddr+"\n")
	r.one("- subnet: 172.30.80.0/24\n", "- subnet: "+v.Subnet+"\n")
	r.one("SHELL_MCP_PROFILE: read-only\n", "SHELL_MCP_PROFILE: "+v.Profile+"\n")
	r.one("SHELL_MCP_TARGET_NAME: app-host\n", "SHELL_MCP_TARGET_NAME: "+scalar(v.TargetName)+"\n")
	r.one("SHELL_MCP_TARGET_HOST: target-a.example.test\n", "SHELL_MCP_TARGET_HOST: "+scalar(v.TargetHost)+"\n")
	r.one("SHELL_MCP_TARGET_USER: svc-shell\n", "SHELL_MCP_TARGET_USER: "+scalar(v.TargetUser)+"\n")
	r.one(`SHELL_MCP_TARGET_HOST_KEYS: "ssh-ed25519 SHA256:placeholder"`+"\n", `SHELL_MCP_TARGET_HOST_KEYS: "`+strings.Join(v.HostKeys, ",")+`"`+"\n")
	r.one("SHELL_MCP_ALLOWED_HOSTS: localhost,127.0.0.1,mcp.example.test\n", "SHELL_MCP_ALLOWED_HOSTS: "+scalar("localhost,127.0.0.1,"+v.MCPHost)+"\n")
	if r.err != nil {
		return nil, r.err
	}
	mounted := "[mcp_token, ssh_key]"
	if v.ApproveHost != "" {
		// Operator with the approval page: the deployer wants operator tools
		// behind an approver's code, which the server's default tiers
		// (destructive) would not give. Admin keeps the default (Check's note).
		tiers := ""
		if v.Profile == string(tools.ProfileOperator) {
			tiers = "      SHELL_MCP_APPROVAL_TIERS: operator,destructive  # --profile operator with the approval page: operator tools need an approver's code too\n"
		}
		at := strings.Index(r.s, proxyLine)
		end := at + strings.Index(r.s[at:], "\n") + 1
		r.s = r.s[:end] +
			"      SHELL_MCP_APPROVAL_METHOD: web\n" +
			"      SHELL_MCP_APPROVAL_PUBLIC_URL: " + scalar("https://"+v.ApproveHost) + "\n" +
			"      SHELL_MCP_APPROVERS_FILE: /run/secrets/approvers\n" +
			"      SHELL_MCP_APPROVAL_BIND: 0.0.0.0  # inside the container; the proxy forwards the approval host to port 8081 on `front`\n" +
			tiers + r.s[end:]
		mounted = "[mcp_token, ssh_key, approvers]"
	}
	if v.Form == FormBind {
		r.one(mountLine, "    volumes:\n      - "+scalar(v.Dir+":/run/secrets:ro")+" # init's directory: 0700, owned by the server's uid\n")
		r.one(mountBlock, "")
	} else {
		r.one(mountLine, "    secrets: "+mounted+"\n")
		if v.ApproveHost != "" {
			r.one("  ssh_key: { file: ./secrets/ssh_key }\n", "  ssh_key: { file: ./secrets/ssh_key }\n  approvers: { file: ./secrets/approvers }\n")
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	return []byte(r.s), nil
}
