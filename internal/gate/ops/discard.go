//go:build linux

package ops

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/tyler-rich/shell-mcp/internal/gate/fsx"
	"github.com/tyler-rich/shell-mcp/internal/gate/gitx"
	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// git_discard_preview and git_discard (POLICY §7, "Discarding changes").
//
// The preview lists every tracked path whose index entry or work-tree
// entry differs from HEAD (git status --no-renames, so a rename is a
// deletion and an addition), what is in the work tree at each (observed by
// fsx, following nothing), and, with include_untracked, every untracked
// path git clean -d would remove (never ignored files; nested repositories
// are skipped), each walked as a delete preview. Its preview_sha256 covers
// HEAD, every listed path's HEAD and index modes and object ids, its
// work-tree identity and content hash, and every untracked path's delete
// preview hash.
//
// The discard takes git's index lock first, recomputes that preview and
// refuses (exists, nothing changed) unless its hash is the one expected.
// It then sets aside every listed file and symlink (fsx.SetAside: checked
// before and after, put back if not what the preview saw), removes the
// untracked paths (fsx.DeleteExact with each path's hash), has git build
// HEAD's index in a temporary index and write the restored files with
// checkout-index without -f (which creates them and never replaces
// anything), refreshes that index and checks with git status that every
// restored path now matches HEAD, removes what it set aside, and renames
// the temporary index onto .git/index. A path that does not verify is not
// restored: what was set aside is put back, the index is left unchanged,
// and the discard stops with exists. Nothing outside the preview is ever
// discarded, and no hook runs (core.hooksPath=/dev/null on every git
// command, as for every git op).

const discardPreviewDomain = "shell-mcp git discard preview v1\x00"

// discardPreviewArgs are git_discard_preview's arguments.
type discardPreviewArgs struct {
	Repo             string `json:"repo"`
	IncludeUntracked bool   `json:"include_untracked"`
}

// discardArgs are git_discard's arguments.
type discardArgs struct {
	Repo                  string `json:"repo"`
	IncludeUntracked      bool   `json:"include_untracked"`
	ExpectedPreviewSHA256 string `json:"expected_preview_sha256"`
}

// discardEntry is one path a discard changes, as the result lists it.
type discardEntry struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Action string `json:"action"`
}

// gitDiscardData is git_discard_preview's and git_discard's result.
type gitDiscardData struct {
	Repo             string         `json:"repo"`
	Head             string         `json:"head"`
	IncludeUntracked bool           `json:"include_untracked"`
	Restore          int            `json:"restore"`
	Remove           int            `json:"remove"`
	Untracked        int            `json:"untracked"`
	UntrackedEntries int            `json:"untracked_entries"`
	Entries          int            `json:"entries"`
	First            []discardEntry `json:"first"`
	Skipped          []string       `json:"skipped"`
	Truncated        bool           `json:"truncated"`
	PreviewSHA256    string         `json:"preview_sha256"`
	Applied          bool           `json:"applied"`
	CleanAfter       *bool          `json:"clean_after,omitempty"`
}

// discardTracked is a tracked path the discard restores to HEAD (restore)
// or removes (staged as new: not in HEAD).
type discardTracked struct {
	e       gitx.DiscardEntry
	abs     string
	wt      fsx.WorktreeEntry
	restore bool
}

// discardUntracked is an untracked path the discard removes.
type discardUntracked struct {
	rel, abs string
	plan     fsx.DeletePlan
}

// discardPlan is a computed preview.
type discardPlan struct {
	repo      string
	head      string
	include   bool
	tracked   []discardTracked
	untracked []discardUntracked
	skipped   []string
	hash      string
}

// inProgress lists the state files of git operations that stop half-way.
var inProgress = []struct{ file, what string }{
	{"MERGE_HEAD", "a merge"}, {"CHERRY_PICK_HEAD", "a cherry-pick"}, {"REVERT_HEAD", "a revert"},
	{"BISECT_LOG", "a bisect"}, {"rebase-merge", "a rebase"}, {"rebase-apply", "a rebase or am"}, {"sequencer", "a cherry-pick or revert sequence"},
}

func (r *gitRepo) refuseInProgress() error {
	for _, st := range inProgress {
		_, err := r.s.fs.Stat(r.path + "/.git/" + st.file)
		switch {
		case err == nil:
			return errf(protocol.CodePolicyDenied, "%s is in progress in the repository (.git/%s exists); finish or abort it on the host first", st.what, st.file)
		case !notFound(err):
			return err
		}
	}
	return nil
}

// entryLimit bounds the paths and untracked entries of one discard.
func (r *gitRepo) entryLimit() int { return r.s.p.Limits.MaxDeleteEntries }

// shown bounds a host path for a one-line message.
func shown(p string) string { return fmt.Sprintf("%q", safeKey(p)) }

// plan computes the preview (see the file comment).
func (r *gitRepo) plan(include bool) (*discardPlan, error) {
	s := r.s
	if err := r.refuseInProgress(); err != nil {
		return nil, err
	}
	head, err := r.head()
	if err != nil {
		return nil, err
	}
	if head == "" {
		return nil, errf(protocol.CodeBadRequest, "the repository has no commits, so there is no HEAD to restore to")
	}
	out, err := r.output("status", "--porcelain=v2", "-z", "--no-renames", "--untracked-files=no", "--ignore-submodules=none")
	if err != nil {
		return nil, err
	}
	ents, truncated, err := gitx.ParseDiscardStatus(out, r.entryLimit())
	if err != nil {
		return nil, errf(protocol.CodeExecFailed, "git status output could not be parsed")
	}
	if truncated {
		return nil, errf(protocol.CodeTooLarge, "more than max_delete_entries (%d) changed paths", r.entryLimit())
	}
	cleanOut, err := r.output("clean", "-n", "-d")
	if err != nil {
		return nil, err
	}
	rm, skip, err := gitx.ParseClean(cleanOut)
	if err != nil {
		return nil, errf(protocol.CodeExecFailed, "git clean output could not be parsed")
	}
	untracked := map[string]bool{} // relative path → a directory
	for _, p := range rm {
		untracked[strings.TrimSuffix(p, "/")] = strings.HasSuffix(p, "/")
	}
	pl := &discardPlan{repo: r.path, head: head, include: include, skipped: []string{}}
	for _, p := range skip {
		pl.skipped = append(pl.skipped, strings.TrimSuffix(p, "/"))
	}
	slices.Sort(pl.skipped)
	budget := int64(fsx.MaxDiscardHashBytes)
	tracked := map[string]bool{}
	for _, e := range ents {
		switch {
		case e.Kind == "unmerged":
			return nil, errf(protocol.CodePolicyDenied, "the repository has an unmerged entry (%s); resolve or abort on the host first", shown(e.Path))
		case e.Sub != "N..." || e.ModeHead == "160000" || e.ModeIndex == "160000" || e.ModeWorktree == "160000":
			return nil, errf(protocol.CodePolicyDenied, "%s is a submodule with changes; repositories with submodule changes are refused", shown(e.Path))
		}
		t := discardTracked{e: e, abs: r.path + "/" + e.Path, restore: e.ModeHead != "000000"}
		if t.wt, err = s.fs.ObserveWorktree(t.abs, &budget); err != nil {
			return nil, pathRefusal(e.Path, err)
		}
		if err := pl.inTheWay(&t, untracked); err != nil {
			return nil, err
		}
		tracked[e.Path] = true
		pl.tracked = append(pl.tracked, t)
	}
	entries := len(pl.tracked)
	if include {
		for _, p := range rm {
			rel := strings.TrimSuffix(p, "/")
			if tracked[rel] && !untracked[rel] {
				continue // no longer in the index: a tracked path, set aside and restored as such
			}
			abs := r.path + "/" + rel
			dp, err := s.fs.PreviewDelete(abs, true)
			if err != nil {
				return nil, untrackedRefusal(rel, err)
			}
			if entries += dp.Entries; entries > r.entryLimit() {
				return nil, errf(protocol.CodeTooLarge, "more than max_delete_entries (%d) paths and untracked entries", r.entryLimit())
			}
			pl.untracked = append(pl.untracked, discardUntracked{rel: rel, abs: abs, plan: dp})
		}
	}
	pl.hash = pl.sum()
	return pl, nil
}

// inTheWay refuses a tracked path whose restore needs an untracked entry
// removed (a directory now at the path, or a file where one of its
// directories was), unless include_untracked removes exactly that entry.
func (pl *discardPlan) inTheWay(t *discardTracked, untracked map[string]bool) error {
	var rel string
	var isDir bool
	switch {
	case t.wt.State == "dir":
		rel, isDir = t.e.Path, true
	case t.wt.BlockedBy != "" && t.restore:
		rel = strings.TrimPrefix(t.wt.BlockedBy, pl.repo+"/")
	default:
		return nil
	}
	dir, listed := untracked[rel]
	switch {
	case listed && dir == isDir && pl.include:
		return nil
	case listed && dir == isDir:
		return errf(protocol.CodeBadRequest, "restoring %s needs the untracked %s removed; pass include_untracked to remove it", shown(t.e.Path), shown(rel))
	}
	return errf(protocol.CodeBadRequest, "restoring %s needs %s removed, which git clean does not list as untracked (it holds ignored "+
		"files or a nested repository, or sits where a tracked file is); a discard never removes it, so clear it on the host first", shown(t.e.Path), shown(rel))
}

// pathRefusal names the tracked path a refusal is about.
func pathRefusal(rel string, err error) error {
	var fe *fsx.Error
	if errors.As(err, &fe) {
		out := *fe
		out.Msg = shown(rel) + ": " + fe.Msg
		return &out
	}
	return err
}

// untrackedRefusal names the untracked path a refusal is about; an
// untracked symlink is never removed.
func untrackedRefusal(rel string, err error) error {
	var fe *fsx.Error
	if errors.As(err, &fe) && fe.Code == protocol.CodePathDenied && strings.Contains(fe.Msg, "symlink") {
		return errf(protocol.CodePathDenied, "the untracked %s is a symlink; a discard never removes untracked symlinks, so remove it on the host first", shown(rel))
	}
	if errors.As(err, &fe) {
		return errf(fe.Code, "untracked %s: %s", shown(rel), fe.Msg)
	}
	return err
}

func appendStr(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

// sum is preview_sha256: a domain string, include_untracked, HEAD, every
// tracked path (its status letters, submodule field, HEAD, index and
// work-tree modes, HEAD and index object ids, and its work-tree entry),
// every untracked path with its delete preview hash, and the skipped
// repositories, each length-prefixed and counted.
func (pl *discardPlan) sum() string {
	b := []byte(discardPreviewDomain)
	if pl.include {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	b = appendStr(b, pl.head)
	b = binary.AppendUvarint(b, uint64(len(pl.tracked)))
	for i := range pl.tracked {
		t := &pl.tracked[i]
		for _, f := range []string{t.e.Path, t.e.XY, t.e.Sub, t.e.ModeHead, t.e.ModeIndex, t.e.ModeWorktree, t.e.OIDHead, t.e.OIDIndex} {
			b = appendStr(b, f)
		}
		b = t.wt.AppendHash(b)
	}
	b = binary.AppendUvarint(b, uint64(len(pl.untracked)))
	for _, u := range pl.untracked {
		b = appendStr(appendStr(b, u.rel), u.plan.PreviewSHA256)
	}
	b = binary.AppendUvarint(b, uint64(len(pl.skipped)))
	for _, p := range pl.skipped {
		b = appendStr(b, p)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// data is the plan as the result reports it.
func (pl *discardPlan) data() gitDiscardData {
	d := gitDiscardData{Repo: pl.repo, Head: pl.head, IncludeUntracked: pl.include, Skipped: pl.skipped, PreviewSHA256: pl.hash, First: []discardEntry{}}
	all := []discardEntry{}
	for _, t := range pl.tracked {
		action := "remove"
		if t.restore {
			action = "restore"
			d.Restore++
		} else {
			d.Remove++
		}
		all = append(all, discardEntry{Path: t.e.Path, Status: t.e.XY, Action: action})
	}
	for _, u := range pl.untracked {
		d.Untracked++
		d.UntrackedEntries += u.plan.Entries
		all = append(all, discardEntry{Path: u.rel, Status: "??", Action: "remove"})
	}
	slices.SortFunc(all, func(a, b discardEntry) int { return strings.Compare(a.Path, b.Path) })
	d.Entries = len(all)
	d.First = append(d.First, all[:min(len(all), previewFirst)]...)
	d.Truncated = len(all) > previewFirst
	return d
}

// previewFirst is how many entries a result lists.
const previewFirst = 50

func (s *server) discardStep(st fsx.DiscardStep, p string) {
	if s.o.InjectDiscardStep != nil {
		s.o.InjectDiscardStep(st, p)
	}
}

func (s *server) gitDiscardPreview(raw jsontext.Value) (data any, warns []string, failure error) {
	var a discardPreviewArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	r, err := s.gitRepo(a.Repo, true)
	if err != nil {
		return nil, nil, err
	}
	if _, err = r.checkConfig(); err != nil {
		return nil, nil, err
	}
	// A discard could not take the lock: say so now, and never touch it.
	locked, byGate, err := s.fs.GitIndexLockState(a.Repo)
	if err != nil {
		return nil, nil, err
	}
	if locked {
		return nil, nil, fsx.ErrIndexLocked(byGate)
	}
	pl, err := r.plan(a.IncludeUntracked)
	if err != nil {
		return nil, nil, err
	}
	return pl.data(), nil, nil
}

func (s *server) gitDiscard(raw jsontext.Value) (data any, warns []string, failure error) {
	var a discardArgs
	if err := decode(raw, &a); err != nil {
		return nil, nil, err
	}
	if !fsx.ValidPreviewSHA256(a.ExpectedPreviewSHA256) {
		return nil, nil, errf(protocol.CodeBadRequest, "expected_preview_sha256 must be the preview_sha256 (64 lowercase hex digits) that git_discard_preview returned")
	}
	r, err := s.gitRepo(a.Repo, true)
	if err != nil {
		return nil, nil, err
	}
	if _, err = r.checkConfig(); err != nil {
		return nil, nil, err
	}
	lock, err := s.fs.LockGitIndex(a.Repo)
	if err != nil {
		return nil, nil, err
	}
	defer lock.Release()
	pl, err := r.plan(a.IncludeUntracked)
	if err != nil {
		return nil, nil, err
	}
	if pl.hash != a.ExpectedPreviewSHA256 {
		return nil, nil, errf(protocol.CodeExists, "the repository changed since the preview (its preview_sha256 differs); nothing was changed")
	}
	s.discardStep(fsx.DiscardStepAfterCompare, a.Repo)
	run := &discardRun{s: s, r: r, pl: pl, lock: lock, aside: map[int]*fsx.AsideEntry{}}
	return run.apply()
}

// discardRun is one discard's progress.
type discardRun struct {
	s     *server
	r     *gitRepo
	pl    *discardPlan
	lock  *fsx.GitIndexLock
	aside map[int]*fsx.AsideEntry // tracked entries set aside and not yet removed or put back
	done  int                     // entries discarded (restored, removed, untracked removed)
	// partial: an untracked path was deleted in part before its deletion
	// stopped (its own message says how much).
	partial bool
	// stranded are entries set aside that could not be put back.
	stranded  []string
	strandMsg []string
}

func (d *discardRun) apply() (data any, warns []string, failure error) {
	s, pl := d.s, d.pl
	// 1. Set aside every listed file and symlink.
	for i := range pl.tracked {
		t := &pl.tracked[i]
		if t.wt.State != "file" && t.wt.State != "symlink" {
			continue
		}
		a, err := s.fs.SetAside(&t.wt)
		if err != nil {
			d.noteStranded(err)
			return d.stop(err)
		}
		d.aside[i] = a
	}
	// 2. Remove the untracked paths, each exactly as its preview listed it.
	s.discardStep(fsx.DiscardStepBeforeUntracked, pl.repo)
	for _, u := range pl.untracked {
		if _, err := s.fs.DeleteExact(u.abs, true, u.plan.PreviewSHA256); err != nil {
			d.noteStranded(err)
			d.partial = strings.Contains(err.Error(), "were deleted and")
			return d.stop(untrackedRefusal(u.rel, err))
		}
		d.done++
	}
	// 3. HEAD's index in a temporary index; git writes the restored files
	// from it, creating each and replacing nothing.
	tmp, err := d.lock.NewTempIndex()
	if err != nil {
		return d.stop(err)
	}
	env := []string{"GIT_INDEX_FILE=" + tmp}
	if _, err := d.r.outputWith(env, nil, "read-tree", pl.head); err != nil {
		return d.stop(err)
	}
	var paths []byte
	for _, t := range pl.tracked {
		if t.restore {
			paths = append(append(paths, t.e.Path...), 0)
		}
	}
	s.discardStep(fsx.DiscardStepBeforeCheckout, pl.repo)
	if len(paths) > 0 {
		// Exit status 1 when a path exists already (something took the
		// name): the verification below finds it.
		if _, err := d.r.runWith(env, paths, s.p.Limits.MaxOutputBytes, "checkout-index", "-q", "--stdin", "-z"); err != nil {
			return d.stop(err)
		}
	}
	s.discardStep(fsx.DiscardStepAfterCheckout, pl.repo)
	// 4. Verify with git: every restored path matches HEAD's index entry.
	if _, err := d.r.outputWith(env, nil, "update-index", "-q", "--refresh"); err != nil {
		return d.stop(err)
	}
	out, err := d.r.outputWith(env, nil, "status", "--porcelain=v2", "-z", "--no-renames", "--untracked-files=no", "--ignore-submodules=none")
	if err != nil {
		return d.stop(err)
	}
	dirty, _, err := gitx.ParseDiscardStatus(out, 1<<20)
	if err != nil {
		return d.stop(errf(protocol.CodeExecFailed, "git status output could not be parsed"))
	}
	notRestored := map[string]bool{}
	for _, e := range dirty {
		notRestored[e.Path] = true
	}
	var firstFail string
	for i := range pl.tracked {
		t := &pl.tracked[i]
		a := d.aside[i]
		if t.restore && notRestored[t.e.Path] {
			if firstFail == "" {
				firstFail = t.e.Path
			}
			if a != nil {
				d.noteStranded(a.PutBack())
				delete(d.aside, i)
			}
			continue
		}
		if a != nil {
			if err := a.Remove(); err != nil {
				d.noteStranded(err)
				delete(d.aside, i)
				if firstFail == "" {
					firstFail = t.e.Path
				}
				continue
			}
			delete(d.aside, i)
		}
		d.done++
	}
	if firstFail != "" || len(d.stranded) > 0 {
		return d.stop(errf(protocol.CodeExists, "%s changed while it was being restored (something else wrote it, or took its name)", shown(firstFail)))
	}
	// 5. The new index.
	s.discardStep(fsx.DiscardStepBeforeCommit, pl.repo)
	if err := d.lock.CommitTempIndex(); err != nil {
		return d.stop(err)
	}
	d.lock.Release()
	res := pl.data()
	res.Applied = true
	var warnings []string
	if h, err := d.r.head(); err == nil && h != pl.head {
		warnings = append(warnings, "HEAD moved while the discard ran; the index and files were restored to the HEAD the preview named")
	}
	st, _, err := d.r.status("normal", false)
	if err != nil {
		return nil, nil, err
	}
	clean := len(st.Entries) == 0
	res.CleanAfter = &clean
	return res, warnings, nil
}

// noteStranded records an entry an error says was left set aside.
func (d *discardRun) noteStranded(err error) {
	var fe *fsx.Error
	if err != nil && errors.As(err, &fe) && fe.SetAside != "" {
		d.stranded = append(d.stranded, fe.SetAside)
		if d.s.setAside == "" {
			d.s.setAside = fe.SetAside
		}
	}
}

// stop ends a discard that cannot go on: whatever is still set aside is put
// back (or, when its name was taken again, left under its temporary name),
// the index is left as it was, and the error says what was and was not
// discarded.
func (d *discardRun) stop(reason error) (data any, warns []string, failure error) {
	for i := len(d.pl.tracked) - 1; i >= 0; i-- {
		if a, ok := d.aside[i]; ok {
			d.noteStranded(a.PutBack())
			delete(d.aside, i)
		}
	}
	code, msg := protocol.CodeInternal, "internal error"
	var oe *opError
	var fe *fsx.Error
	switch {
	case errors.As(reason, &oe):
		code, msg = oe.code, oe.msg
	case errors.As(reason, &fe):
		code, msg = fe.Code, fe.Msg
	}
	total := d.pl.data().Entries
	out := fmt.Sprintf("discard stopped: %s; nothing was changed", msg)
	if d.done > 0 || d.partial {
		out = fmt.Sprintf("discard stopped: %s; %d of %d entries were discarded and %d were not; the index was not changed "+
			"(preview the repository again to see what remains); nothing outside the preview was discarded", msg, d.done, total, total-d.done)
	}
	if len(d.stranded) > 0 && !strings.Contains(msg, d.stranded[0]) {
		out += "; entries set aside could not be put back because their names were taken again, and were left, not discarded, as " +
			strings.Join(d.stranded, ", ")
	}
	return nil, nil, errf(code, "%s", out)
}
