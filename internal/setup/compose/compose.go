// Package compose renders `shell-mcp init compose`: the reference deployment
// (deploy/docker-compose.yml, embedded as a byte copy that a test holds equal
// to it) with one deployment's values in place, in the secrets form (compose
// secrets: next to init's directory) or the bind form (one read-only bind
// mount of that directory, for stack editors). Handoff §4.C.
package compose

import (
	_ "embed"
	"errors"
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

// UsageError is a flag error (exit 2); any other error from Check is a
// refusal (exit 1).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// Image is a parsed --image reference.
type Image struct{ Repository, Tag, Digest string }

// Template is the embedded copy of deploy/docker-compose.yml.
func Template() []byte { return append([]byte(nil), template...) }

// Reference is the values deploy/docker-compose.yml holds.
func Reference() Values { return Values{} }

// ParseFlags parses init compose's flags.
func ParseFlags(args []string) (*Values, error) { return &Values{}, nil }

// ParseImage parses <repository>[:<tag>]@sha256:<64 hex>.
func ParseImage(ref string) (Image, error) { return Image{}, errors.New("stub") }

// Check refuses values the server, Docker or CLIENTS §1 would not accept,
// and returns the notes to print.
func (v *Values) Check() (notes []string, err error) { return nil, nil }

// Render returns the compose file for v.
func Render(v *Values) ([]byte, error) { return nil, nil }
