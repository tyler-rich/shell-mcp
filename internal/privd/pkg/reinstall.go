//go:build linux

package pkg

// The two unfinished states a recovery cannot finish (handoff N-36,
// S7-7): a reinstall of exactly the packages dpkg flagged reinstreq or
// left half-installed, pinned to the version dpkg's status names, and the
// hash a removal of exactly the unfinished packages adds to its preview.
// Inert stubs: the tests that need them fail first.

// OpReinstall is a reinstall of packages that need one.
const OpReinstall Op = "reinstall"

// CheckNames validates the package names of an install, a reinstall or a
// removal.
func CheckNames(_ Op, _ []string) error { return nil }

// ReinstallArgs is the argv of a reinstall (simulate: -s).
func ReinstallArgs(_ bool, _ []Version) ([]string, error) { return nil, nil }

// ReinstallPreviewHash is the reinstall preview's preview_sha256.
func ReinstallPreviewHash(_ string, _ []string, _ Transaction, _ []string, _ []UnfinishedPackage, _ []string) string {
	return ""
}

// UnfinishedPreviewHash binds a package preview's hash to dpkg's
// unfinished state.
func UnfinishedPreviewHash(previewSHA string, _ []UnfinishedPackage, _ []string) string {
	return previewSHA
}
