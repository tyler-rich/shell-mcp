//go:build linux

package ops

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"os"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// Defaults for new files and directories, capped by modes.max.
const (
	defaultFileMode  = 0o640
	defaultDirMode   = 0o750
	defaultListLimit = 500
)

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

type writeArgs struct {
	Path           string `json:"path"`
	ContentB64     string `json:"content_b64"`
	Mode           string `json:"mode"`
	Owner          string `json:"owner"`
	Group          string `json:"group"`
	Create         *bool  `json:"create"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type mkdirArgs struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Parents bool   `json:"parents"`
	Owner   string `json:"owner"`
	Group   string `json:"group"`
}

type chownArgs struct {
	Path  string `json:"path"`
	Owner string `json:"owner"`
	Group string `json:"group"`
}

type chmodArgs struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type srcDstArgs struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Overwrite   bool   `json:"overwrite"`
}

type deleteArgs struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

// Write-class results carry the ids of the backups written first.
type writeData struct {
	fsx.WriteResult `json:",inline"`
	BackupIDs       []string `json:"backup_ids"`
}

type moveData struct {
	fsx.MoveResult `json:",inline"`
	BackupIDs      []string `json:"backup_ids"`
}

type deleteData struct {
	fsx.DeleteResult `json:",inline"`
	BackupIDs        []string `json:"backup_ids"`
}

func (s *server) ids() []string { return append([]string{}, s.backupIDs...) }

// mode parses an optional mode and requires it within modes.max (fsx
// itself refuses setuid, setgid, sticky and world-write).
func (s *server) mode(str string) (*os.FileMode, error) {
	if str == "" {
		return nil, nil
	}
	m, err := fsx.ParseMode(str)
	if err != nil {
		return nil, err
	}
	if m&^s.p.ModesMax != 0 {
		return nil, errf(protocol.CodePolicyDenied, "mode %04o exceeds the privileged policy's modes.max %04o", uint32(m), uint32(s.p.ModesMax))
	}
	return &m, nil
}

// owner resolves owner and group names against the allow-lists.
func (s *server) owner(user, group string) (*fsx.Owner, error) {
	if user == "" && group == "" {
		return nil, nil
	}
	o := &fsx.Owner{}
	if user != "" {
		found := false
		for _, u := range s.p.Owners.Users {
			if u.Name == user {
				id := u.ID
				o.UID, found = &id, true
			}
		}
		if !found {
			return nil, errf(protocol.CodePolicyDenied, "owner is not in the privileged policy's owners.users")
		}
	}
	if group != "" {
		found := false
		for _, g := range s.p.Owners.Groups {
			if g.Name == group {
				id := g.ID
				o.GID, found = &id, true
			}
		}
		if !found {
			return nil, errf(protocol.CodePolicyDenied, "group is not in the privileged policy's owners.groups")
		}
	}
	return o, nil
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
	mode, err := s.mode(a.Mode)
	if err != nil {
		return nil, nil, err
	}
	owner, err := s.owner(a.Owner, a.Group)
	if err != nil {
		return nil, nil, err
	}
	create := true
	if a.Create != nil {
		create = *a.Create
	}
	r, err := s.fs.WriteFile(a.Path, content, fsx.WriteOptions{
		Mode: mode, Create: create, ExpectedSHA256: a.ExpectedSHA256, Owner: owner,
		DefaultMode: defaultFileMode & s.p.ModesMax,
	})
	if err != nil {
		return nil, nil, err
	}
	return writeData{WriteResult: r, BackupIDs: s.ids()}, nil, nil
}

func (s *server) mkdir(raw jsontext.Value) (data any, warns []string, failure error) {
	var a mkdirArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	mode, err := s.mode(a.Mode)
	if err != nil {
		return nil, nil, err
	}
	if mode == nil {
		m := os.FileMode(defaultDirMode) & s.p.ModesMax
		mode = &m
	}
	owner, err := s.owner(a.Owner, a.Group)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.fs.MkdirAs(a.Path, mode, a.Parents, owner)
	return r, nil, err
}

func (s *server) chown(raw jsontext.Value) (data any, warns []string, failure error) {
	var a chownArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	owner, err := s.owner(a.Owner, a.Group)
	if err != nil {
		return nil, nil, err
	}
	if owner == nil {
		return nil, nil, errf(protocol.CodeBadRequest, "owner or group is required")
	}
	r, err := s.fs.Chown(a.Path, *owner)
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
	mode, err := s.mode(a.Mode)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Chmod(a.Path, *mode)
	return r, nil, err
}

func (s *server) copy(raw jsontext.Value) (data any, warns []string, failure error) {
	var a srcDstArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Copy(a.Source, a.Destination, a.Overwrite)
	if err != nil {
		return nil, nil, err
	}
	return writeData{WriteResult: r, BackupIDs: s.ids()}, nil, nil
}

func (s *server) move(raw jsontext.Value) (data any, warns []string, failure error) {
	var a srcDstArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Move(a.Source, a.Destination, a.Overwrite)
	if err != nil {
		return nil, nil, err
	}
	return moveData{MoveResult: r, BackupIDs: s.ids()}, nil, nil
}

func (s *server) delete(raw jsontext.Value) (data any, warns []string, failure error) {
	var a deleteArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.fs.Delete(a.Path, a.Recursive)
	if err != nil {
		return nil, nil, err
	}
	return deleteData{DeleteResult: r, BackupIDs: s.ids()}, nil, nil
}
