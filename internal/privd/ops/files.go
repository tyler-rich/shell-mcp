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
	ExpectAbsent   bool   `json:"expect_absent"`
}

type mkdirArgs struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Parents bool   `json:"parents"`
	Owner   string `json:"owner"`
	Group   string `json:"group"`
}

type srcDstArgs struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Overwrite   bool   `json:"overwrite"`
	// ExpectedDestinationSHA256 binds an overwrite to the destination's
	// content (handoff P-9): only with overwrite.
	ExpectedDestinationSHA256 string `json:"expected_destination_sha256"`
}

type deleteArgs struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

// Write-class results carry the ids of the backups written first, and a
// new inode's owner and group (handoff P-12): the ids fsx read from its
// descriptor, and their names when they are on the owners lists.
type writeData struct {
	fsx.WriteResult `json:",inline"`
	ownerData       `json:",inline"`
	BackupIDs       []string `json:"backup_ids"`
}

type ownerData struct {
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Owner string `json:"owner,omitempty"`
	Group string `json:"group,omitempty"`
}

type mkdirData struct {
	fsx.MkdirResult `json:",inline"`
	ownerData       `json:",inline"`
}

// ownerOf names uid and gid from the owners lists.
func (s *server) ownerOf(uid, gid uint32) ownerData {
	o := ownerData{UID: uid, GID: gid}
	for _, u := range s.p.Owners.Users {
		if u.ID == uid {
			o.Owner = u.Name
			break
		}
	}
	for _, g := range s.p.Owners.Groups {
		if g.ID == gid {
			o.Group = g.Name
			break
		}
	}
	return o
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

// newInodeMode is the mode for an inode the helper creates from a recorded
// mode (a restore): without setuid, setgid, sticky or world-write, and
// masked by modes.max. fsx masks every new inode by modes.max too
// (Config.ModesMax), so this only makes the recorded mode acceptable.
func (s *server) newInodeMode(m uint32) os.FileMode {
	return os.FileMode(m&0o775) & s.p.ModesMax
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
	s.precondition = a.ExpectedSHA256
	r, err := s.fs.WriteFile(a.Path, content, fsx.WriteOptions{
		Mode: mode, Create: create, ExpectedSHA256: a.ExpectedSHA256, ExpectAbsent: a.ExpectAbsent, Owner: owner,
		DefaultMode: defaultFileMode & s.p.ModesMax,
	})
	if err != nil {
		return nil, nil, err
	}
	return writeData{WriteResult: r, ownerData: s.ownerOf(r.UID, r.GID), BackupIDs: s.ids()}, nil, nil
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
	if err != nil {
		return nil, nil, err
	}
	return mkdirData{MkdirResult: r, ownerData: s.ownerOf(r.UID, r.GID)}, nil, nil
}

func (s *server) copy(raw jsontext.Value) (data any, warns []string, failure error) {
	var a srcDstArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	s.precondition = a.ExpectedDestinationSHA256
	r, err := s.fs.CopyExpecting(a.Source, a.Destination, a.Overwrite, a.ExpectedDestinationSHA256)
	if err != nil {
		return nil, nil, err
	}
	return writeData{WriteResult: r, ownerData: s.ownerOf(r.UID, r.GID), BackupIDs: s.ids()}, nil, nil
}

func (s *server) move(raw jsontext.Value) (data any, warns []string, failure error) {
	var a srcDstArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	s.precondition = a.ExpectedDestinationSHA256
	r, err := s.fs.MoveExpecting(a.Source, a.Destination, a.Overwrite, a.ExpectedDestinationSHA256)
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
