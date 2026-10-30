//go:build linux

package units

// SetHomeDirs replaces the directories ProtectHome=yes hides, for tests whose
// scratch directories must stand in for them (CI's TMPDIR is itself under
// /home), and returns the function that restores them.
func SetHomeDirs(dirs []string) (restore func()) {
	old := homeDirs
	homeDirs = dirs
	return func() { homeDirs = old }
}
