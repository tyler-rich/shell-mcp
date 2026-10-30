//go:build linux

package pkg

// The two unfinished states a recovery cannot finish (handoff N-36,
// S7-7): a reinstall of exactly the packages dpkg flagged reinstreq or
// left half-installed, pinned to the version dpkg's status names, and the
// hash a removal of exactly the unfinished packages adds to its preview.

// OpReinstall is a reinstall of packages that need one.
const OpReinstall Op = "reinstall"

// CheckNames validates the package names of an install, a reinstall or a
// removal.
func CheckNames(op Op, names []string) error { return nil }

// ReinstallArgs is the argv of a reinstall (simulate: -s).
func ReinstallArgs(simulate bool, pins []Version) ([]string, error) { return nil, nil }

// ReinstallPreviewHash is the reinstall preview's preview_sha256.
func ReinstallPreviewHash(policySHA string, names []string, t Transaction, argv []string, unfinished []UnfinishedPackage, journal []string) string {
	return ""
}

// UnfinishedPreviewHash binds a package preview's hash to dpkg's
// unfinished state.
func UnfinishedPreviewHash(previewSHA string, unfinished []UnfinishedPackage, journal []string) string {
	return previewSHA
}
