//go:build linux

package ops

import (
	"encoding/json/jsontext"
	"fmt"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The helper's chown and chmod (PRIVILEGED §6; handoff
// docs/handoff/S4C-PRIVILEGED.md S4c-3: P-2b, P-3, P-4, D4, N-1, Q8).
// priv_chown_preview and priv_chmod_preview (read) report what would
// change and preview_sha256, which binds the change, the tree and this
// policy's hash; priv_chown and priv_chmod require that hash
// (expected_preview_sha256), recompute it and change exactly that plan, or
// nothing (fsx.PreviewMeta, fsx.ApplyMeta). Both run through the same
// resolution: the owner allow-lists and modes.max first, then fsx.

type chownArgs struct {
	Path      string `json:"path"`
	Owner     string `json:"owner"`
	Group     string `json:"group"`
	Recursive bool   `json:"recursive"`
	// ExpectedPreviewSHA256 is priv_chown_preview's preview_sha256 (P-3).
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256"`
}

type chmodArgs struct {
	Path      string `json:"path"`
	Mode      string `json:"mode"`
	Recursive bool   `json:"recursive"`
	// ExpectedPreviewSHA256 is priv_chmod_preview's preview_sha256 (P-3).
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256"`
}

type chownPreviewArgs struct {
	Path      string `json:"path"`
	Owner     string `json:"owner"`
	Group     string `json:"group"`
	Recursive bool   `json:"recursive"`
}

type chmodPreviewArgs struct {
	Path      string `json:"path"`
	Mode      string `json:"mode"`
	Recursive bool   `json:"recursive"`
}

// metaPreviewEntry is one entry of a preview: its current owner, group and
// mode, and those it gets (names only when they are on the owners lists).
type metaPreviewEntry struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	Owner    string `json:"owner,omitempty"`
	Group    string `json:"group,omitempty"`
	Mode     string `json:"mode"`
	NewUID   uint32 `json:"new_uid"`
	NewGID   uint32 `json:"new_gid"`
	NewOwner string `json:"new_owner,omitempty"`
	NewGroup string `json:"new_group,omitempty"`
	NewMode  string `json:"new_mode"`
}

// metaPreviewData is priv_chown_preview's and priv_chmod_preview's data
// (P-2b).
type metaPreviewData struct {
	Path          string             `json:"path"`
	Type          string             `json:"type"`
	Entries       int                `json:"entries"`
	Changes       int                `json:"changes"`
	First         []metaPreviewEntry `json:"first"`
	Truncated     bool               `json:"truncated"`
	PolicySHA256  string             `json:"policy_sha256"`
	PreviewSHA256 string             `json:"preview_sha256"`
}

// chownChange resolves owner and group against the allow-lists.
func (s *server) chownChange(user, group string) (fsx.MetaChange, error) {
	o, err := s.owner(user, group)
	if err != nil {
		return fsx.MetaChange{}, err
	}
	if o == nil {
		return fsx.MetaChange{}, errf(protocol.CodeBadRequest, "owner or group is required")
	}
	return fsx.MetaChange{Op: fsx.MetaChown, UID: o.UID, GID: o.GID}, nil
}

// chmodChange requires a mode within modes.max.
func (s *server) chmodChange(mode string) (fsx.MetaChange, error) {
	if mode == "" {
		return fsx.MetaChange{}, errf(protocol.CodeBadRequest, "mode is required")
	}
	m, err := s.mode(mode)
	if err != nil {
		return fsx.MetaChange{}, err
	}
	return fsx.MetaChange{Op: fsx.MetaChmod, Mode: *m}, nil
}

func (s *server) metaPreview(r *fsx.MetaPlan) metaPreviewData {
	out := metaPreviewData{Path: r.Path, Type: r.Type, Entries: r.Entries, Changes: r.Changes, First: make([]metaPreviewEntry, 0, len(r.First)),
		Truncated: len(r.First) < r.Entries, PolicySHA256: s.p.SHA256, PreviewSHA256: r.PreviewSHA256}
	for _, e := range r.First {
		cur, next := s.ownerOf(e.UID, e.GID), s.ownerOf(e.NewUID, e.NewGID)
		out.First = append(out.First, metaPreviewEntry{Path: e.Path, Type: e.Type, UID: e.UID, GID: e.GID, Owner: cur.Owner, Group: cur.Group,
			Mode: fmt.Sprintf("%04o", e.Mode), NewUID: e.NewUID, NewGID: e.NewGID, NewOwner: next.Owner, NewGroup: next.Group,
			NewMode: fmt.Sprintf("%04o", e.NewMode)})
	}
	return out
}

func (s *server) chownPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	var a chownPreviewArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	ch, err := s.chownChange(a.Owner, a.Group)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.fs.PreviewMeta(a.Path, ch, a.Recursive, s.p.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return s.metaPreview(&r), nil, nil
}

func (s *server) chmodPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	var a chmodPreviewArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	ch, err := s.chmodChange(a.Mode)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.fs.PreviewMeta(a.Path, ch, a.Recursive, s.p.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return s.metaPreview(&r), nil, nil
}

func (s *server) chown(raw jsontext.Value) (data any, warns []string, failure error) {
	var a chownArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	ch, err := s.chownChange(a.Owner, a.Group)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.fs.ApplyMeta(a.Path, ch, a.Recursive, s.p.SHA256, a.ExpectedPreviewSHA256)
	s.recordChanges(r.Changed)
	if err != nil {
		return nil, nil, err
	}
	return fsx.ChownResult{Path: r.Path, OldUID: r.Top.UID, OldGID: r.Top.GID, UID: r.Top.NewUID, GID: r.Top.NewGID}, nil, nil
}

func (s *server) chmod(raw jsontext.Value) (data any, warns []string, failure error) {
	var a chmodArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	ch, err := s.chmodChange(a.Mode)
	if err != nil {
		return nil, nil, err
	}
	r, err := s.fs.ApplyMeta(a.Path, ch, a.Recursive, s.p.SHA256, a.ExpectedPreviewSHA256)
	s.recordChanges(r.Changed)
	if err != nil {
		return nil, nil, err
	}
	return fsx.ChmodResult{Path: r.Path, OldMode: fmt.Sprintf("%04o", r.Top.Mode), Mode: fmt.Sprintf("%04o", r.Top.NewMode)}, nil, nil
}
