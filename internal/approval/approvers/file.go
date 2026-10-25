package approvers

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// The operations behind `shell-mcp approver add|remove|list`. Each reads the
// file under the same checks as Load (a missing file counts as empty for
// Add only), and Add and Remove replace it atomically: the new content goes
// to a 0600 temporary file in the same directory, which is synced and
// renamed over the old one. A refused operation leaves the file untouched.
// They are meant for one operator at a time; two concurrent writers can
// lose one's change, never corrupt the file.

// Add enrols name with seed. It refuses a duplicate name, a second approver
// unless allowMultiple, more than MaxApprovers, and any file Load would
// refuse for its mode or content.
func Add(path, name string, seed []byte, allowMultiple bool) error {
	if !ValidName(name) {
		return errorf("approver name must match %s", namePattern)
	}
	if len(seed) < MinSeedBytes || len(seed) > MaxSeedBytes {
		return errorf("seed must be %d to %d bits", MinSeedBytes*8, MaxSeedBytes*8)
	}
	data, err := readChecked(path)
	switch {
	case errors.Is(err, errMissing):
		data = nil
	case err != nil:
		return err
	}
	list, _, err := parse(data)
	if err != nil {
		return prefixed(err)
	}
	switch {
	case slices.ContainsFunc(list, func(a Approver) bool { return a.Name == name }):
		return ErrDuplicate
	case len(list) >= MaxApprovers:
		return ErrFull
	case len(list) > 0 && !allowMultiple:
		return ErrMultiple
	}
	content := string(data)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return writeAtomic(path, content+name+" "+EncodeSeed(seed)+"\n")
}

// Remove removes name, keeping every other line as written.
func Remove(path, name string) error {
	data, err := readChecked(path)
	if err != nil {
		return err
	}
	list, lines, err := parse(data)
	if err != nil {
		return prefixed(err)
	}
	i := slices.IndexFunc(list, func(a Approver) bool { return a.Name == name })
	if i < 0 {
		return ErrUnknown
	}
	lines = slices.Delete(lines, i, i+1)
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	return writeAtomic(path, content)
}

// List returns the enrolled names, in file order.
func List(path string) ([]string, error) {
	data, err := readChecked(path)
	if err != nil {
		return nil, err
	}
	list, _, err := parse(data)
	if err != nil {
		return nil, prefixed(err)
	}
	names := make([]string, 0, len(list))
	for _, a := range list {
		names = append(names, a.Name)
	}
	return names, nil
}

func writeAtomic(path, content string) (err error) {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".approvers-*.tmp")
	if err != nil {
		return errorf("approvers file: cannot create a temporary file next to it")
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return errorf("approvers file: cannot set the temporary file's mode")
	}
	if _, err = f.WriteString(content); err != nil {
		return errorf("approvers file: cannot write the temporary file")
	}
	if err = f.Sync(); err != nil {
		return errorf("approvers file: cannot sync the temporary file")
	}
	if err = f.Close(); err != nil {
		return errorf("approvers file: cannot close the temporary file")
	}
	if err = os.Rename(tmp, path); err != nil {
		return errorf("approvers file: cannot replace the file")
	}
	syncDir(dir)
	return nil
}

// syncDir makes the rename durable where the platform allows syncing a
// directory; elsewhere it does nothing.
func syncDir(dir string) {
	d, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
