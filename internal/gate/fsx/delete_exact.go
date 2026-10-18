//go:build linux

package fsx

// DeleteStep names a point of DeleteExact's deletion pass, for tests
// (Config.InjectDeleteStep).
type DeleteStep int

// Points of the deletion pass.
const (
	// DeleteStepAfterCompare: the preview hash matched; nothing is removed yet.
	DeleteStepAfterCompare DeleteStep = iota + 1
	// DeleteStepBeforeEntry: before an entry is checked under its name.
	DeleteStepBeforeEntry
	// DeleteStepBeforeRename: after that check, before the entry is set
	// aside under a temporary name in its directory.
	DeleteStepBeforeRename
	// DeleteStepAfterRename: after it was set aside, before it is checked
	// again under the temporary name.
	DeleteStepAfterRename
	// DeleteStepBeforeUnlink: after that check, before the temporary name
	// is removed.
	DeleteStepBeforeUnlink
)

// DeletePlan is the gate's delete_preview and delete result.
type DeletePlan struct {
	Path          string   `json:"path"`
	Type          string   `json:"type"`
	Entries       int      `json:"entries"`
	Bytes         int64    `json:"bytes"`
	First         []string `json:"first"`
	PreviewSHA256 string   `json:"preview_sha256"`
	Deleted       bool     `json:"deleted"`
}

// ValidPreviewSHA256 reports whether s is a preview hash: 64 lowercase hex
// digits.
func ValidPreviewSHA256(string) bool { return true } // stub

// PreviewDelete reports what DeleteExact would remove. Stub: the S1 preview.
func (f *FS) PreviewDelete(p string, recursive bool) (DeletePlan, error) {
	r, err := f.DeletePreview(p, recursive)
	return DeletePlan{Path: r.Path, Type: r.Type, Entries: r.Entries, Bytes: r.Bytes, First: r.First}, err
}

// DeleteExact removes what PreviewDelete reported. Stub: the S1 delete.
func (f *FS) DeleteExact(p string, recursive bool, _ string) (DeletePlan, error) {
	r, err := f.Delete(p, recursive)
	return DeletePlan{Path: r.Path, Type: r.Type, Entries: r.Entries, Bytes: r.Bytes, First: r.First, Deleted: r.Deleted}, err
}
