//go:build linux

package gatetest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// The delete racers' checks (fsx TestDeleteConcurrentRacer and the
// helper's TestPrivDeleteConcurrentRacer), shared so that the gate's and
// the helper's delete are held to the same rules.

// SetAsidePrefix starts the name a delete sets an entry aside under.
const SetAsidePrefix = ".shell-mcp-delete-"

// RacerWrites records every file a racer put into a tree, by path, in the
// order it put them: each later one at a path replaced the one before.
type RacerWrites map[string][]string

// RacerPut puts content at p as a new inode, staged in staging, as the
// racers do: it creates p or replaces what is there, and is recorded in w
// only when its rename succeeded. An error means it could not stage it.
func RacerPut(staging, p, content string, w RacerWrites) error {
	f, err := os.CreateTemp(staging, "racer-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.WriteString(content)
	if err = errors.Join(err, f.Close()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if os.Rename(tmp, p) != nil {
		_ = os.Remove(tmp)
		return nil
	}
	w[p] = append(w[p], content)
	return nil
}

// TempNames lists every entry under dir whose name has the set-aside
// prefix.
func TempNames(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(filepath.Base(p), SetAsidePrefix) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// DeleteReport is what a delete told its caller: whether it was refused,
// the refusal's code and message, the entry it named as set aside (the
// gate's fsx.Error.SetAside, the helper's audit set_aside), and whether it
// reported the tree unchanged (fsx.Error.Unchanged; for the helper, its
// backup discarded).
type DeleteReport struct {
	Refused   bool
	Code      string
	Message   string
	SetAside  string
	Unchanged bool
}

// RacerRunProblem checks one racer run, after the delete returned rep:
// every file the racer put into the tree is still there with the content
// it put last (each earlier one was replaced by the racer itself), and no
// entry is left set aside anywhere under root, with one exception, the
// documented one (POLICY §3, "Entries set aside and not removed"). The
// racer replaced a listed file after its check under its name and before
// it was set aside, so what was set aside failed its check; and it took
// the name again before the put-back. The racer's earlier file then stays
// under its temporary name. That is accepted only when it is the one
// entry left set aside under root; the refusal is exists, not unchanged,
// and names it (SetAside, and the message with the listed file it was set
// aside from); that file is one of the tree's files, in the same
// directory; and the entry is a regular file holding one of the racer's
// earlier writes at that file, not its last (which holds the name). It
// returns the path of the entry it accepted ("" when there is none).
func RacerRunProblem(root string, files []string, w RacerWrites, rep DeleteReport) (string, error) {
	for p, cs := range w {
		if got, rerr := os.ReadFile(p); rerr != nil || string(got) != cs[len(cs)-1] { //nolint:gosec // G304: test fixture
			return "", fmt.Errorf("the racer's file %s was deleted or changed (%s): the deletion removed something it never saw", p, errText(rerr))
		}
	}
	left := TempNames(root)
	reported := rep.Refused && rep.SetAside != ""
	switch {
	case len(left) == 0 && !reported:
		return "", nil
	case len(left) == 0:
		return "", fmt.Errorf("the refusal names %s as set aside, but no temporary name was left", rep.SetAside)
	case len(left) > 1:
		return "", fmt.Errorf("%d temporary names were left behind: %v", len(left), left)
	case !reported:
		return "", fmt.Errorf("a temporary name was left behind without being reported: %s (%+v)", left[0], rep)
	}
	aside := left[0]
	if rep.SetAside != aside || rep.Code != protocol.CodeExists || rep.Unchanged || !strings.Contains(rep.Message, "it was left, not deleted, as "+aside) {
		return "", fmt.Errorf("the entry left as %s is not the one the refusal reports: %+v", aside, rep)
	}
	from := ""
	for _, p := range files {
		if strings.Contains(rep.Message, "the entry set aside from "+p+" could not be put back") {
			from = p
		}
	}
	if from == "" || filepath.Dir(from) != filepath.Dir(aside) {
		return "", fmt.Errorf("the entry left as %s was not set aside from a file of the tree in its directory: %s", aside, rep.Message)
	}
	fi, lerr := os.Lstat(aside)
	got, rerr := os.ReadFile(aside) //nolint:gosec // G304: test fixture
	if cs := w[from]; lerr != nil || rerr != nil || !fi.Mode().IsRegular() || len(cs) < 2 || !slices.Contains(cs[:len(cs)-1], string(got)) {
		return "", fmt.Errorf("the entry left as %s is not one of the racer's earlier files at %s (%q, %s)", aside, from, got, errText(errors.Join(lerr, rerr)))
	}
	return aside, nil
}

// errText is err's text for a check's message, "no error" for nil.
func errText(err error) string {
	if err == nil {
		return "no error"
	}
	return err.Error()
}
