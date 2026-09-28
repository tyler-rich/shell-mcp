//go:build linux

package ops

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"os"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

const defaultListLimit = 500

type noArgs struct{}

type pathArgs struct {
	Path string `json:"path"`
}

type listArgs struct {
	Path          string `json:"path"`
	IncludeHidden bool   `json:"include_hidden"`
	Limit         int    `json:"limit"`
}

type readArgs struct {
	Path      string `json:"path"`
	Offset    int64  `json:"offset"`
	MaxBytes  int    `json:"max_bytes"`
	TailLines int    `json:"tail_lines"`
}

type findArgs struct {
	Path            string `json:"path"`
	NameGlob        string `json:"name_glob"`
	Type            string `json:"type"`
	MaxDepth        int    `json:"max_depth"`
	Limit           int    `json:"limit"`
	ModifiedWithinS int64  `json:"modified_within_s"`
}

type writeArgs struct {
	Path           string `json:"path"`
	ContentB64     string `json:"content_b64"`
	Mode           string `json:"mode"`
	Create         *bool  `json:"create"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type mkdirArgs struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Parents bool   `json:"parents"`
}

type srcDstArgs struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Overwrite   bool   `json:"overwrite"`
}

type chmodArgs struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type deleteArgs struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

func decode(raw jsontext.Value, v any) error {
	if err := protocol.DecodeArgs(raw, v); err != nil {
		return badArgs()
	}
	return nil
}

// parseMode parses an optional octal mode argument.
func parseMode(s string) (*os.FileMode, error) {
	if s == "" {
		return nil, nil
	}
	m, err := fsx.ParseMode(s)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *server) listDir(raw jsontext.Value) (data any, warns []string, failure error) {
	var a listArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if a.Limit == 0 {
		a.Limit = defaultListLimit
	}
	r, err := s.fs.ListDir(a.Path, a.IncludeHidden, a.Limit)
	return r, nil, err
}

func (s *server) stat(raw jsontext.Value) (data any, warns []string, failure error) {
	var a pathArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Stat(a.Path)
	return r, nil, err
}

func (s *server) readFile(raw jsontext.Value) (data any, warns []string, failure error) {
	var a readArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.ReadFile(a.Path, fsx.ReadOptions{Offset: a.Offset, MaxBytes: a.MaxBytes, TailLines: a.TailLines})
	if err != nil {
		return nil, nil, err
	}
	var warnings []string
	if red := s.red.String(r.Content); red != r.Content {
		r.Content = red
		warnings = append(warnings, "content was redacted")
	}
	return r, warnings, nil
}

func (s *server) find(raw jsontext.Value) (data any, warns []string, failure error) {
	var a findArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Find(a.Path, fsx.FindOptions{NameGlob: a.NameGlob, Type: a.Type, MaxDepth: a.MaxDepth, Limit: a.Limit, ModifiedWithinS: a.ModifiedWithinS})
	return r, nil, err
}

func (s *server) writeFile(raw jsontext.Value) (data any, warns []string, failure error) {
	var a writeArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	maxW := s.p.Limits.MaxWriteBytes
	if len(a.ContentB64) > base64.StdEncoding.EncodedLen(maxW) {
		return nil, nil, errf(protocol.CodeTooLarge, "content exceeds max_write_bytes (%d)", maxW)
	}
	content, err := base64.StdEncoding.Strict().DecodeString(a.ContentB64)
	if err != nil {
		return nil, nil, errf(protocol.CodeBadRequest, "content_b64 is not standard base64")
	}
	mode, err := parseMode(a.Mode)
	if err != nil {
		return nil, nil, err
	}
	create := true
	if a.Create != nil {
		create = *a.Create
	}
	r, err := s.fs.WriteFile(a.Path, content, fsx.WriteOptions{Mode: mode, Create: create, ExpectedSHA256: a.ExpectedSHA256})
	return r, nil, err
}

func (s *server) mkdir(raw jsontext.Value) (data any, warns []string, failure error) {
	var a mkdirArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	mode, err := parseMode(a.Mode)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Mkdir(a.Path, mode, a.Parents)
	return r, nil, err
}

func (s *server) copy(raw jsontext.Value) (data any, warns []string, failure error) {
	var a srcDstArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Copy(a.Source, a.Destination, a.Overwrite)
	return r, nil, err
}

func (s *server) move(raw jsontext.Value) (data any, warns []string, failure error) {
	var a srcDstArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Move(a.Source, a.Destination, a.Overwrite)
	return r, nil, err
}

func (s *server) chmod(raw jsontext.Value) (data any, warns []string, failure error) {
	var a chmodArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if a.Mode == "" {
		return nil, nil, errf(protocol.CodeBadRequest, "mode is required")
	}
	mode, err := parseMode(a.Mode)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Chmod(a.Path, *mode)
	return r, nil, err
}

func (s *server) delete(raw jsontext.Value) (data any, warns []string, failure error) {
	var a deleteArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Delete(a.Path, a.Recursive)
	return r, nil, err
}

func (s *server) deletePreview(raw jsontext.Value) (data any, warns []string, failure error) {
	var a deleteArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.DeletePreview(a.Path, a.Recursive)
	return r, nil, err
}
