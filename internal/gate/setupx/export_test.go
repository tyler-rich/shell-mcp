//go:build linux

package setupx

import "io/fs"

// WriteFileFailingAt is WriteFile with step (one of WriteSteps) failing.
func WriteFileFailingAt(path string, data []byte, mode fs.FileMode, owner Owner, step string) error {
	return writeFile(path, data, mode, owner, &writeHooks{fail: func(s string) error {
		if s == step {
			return errInjected
		}
		return nil
	}})
}

// WriteSteps are the write helper's steps, in order.
var WriteSteps = []string{stepCreate, stepWrite, stepSync, stepChown, stepChmod, stepClose, stepRename, stepSyncDir, stepReadBack}

// CommittedFrom is the first step after the rename.
const CommittedFrom = stepSyncDir

// RemoveLeftoversOwnedBy is RemoveLeftovers for temp files owned by uid.
var RemoveLeftoversOwnedBy = removeLeftovers

type injected struct{}

func (injected) Error() string { return "injected failure" }

var errInjected error = injected{}
