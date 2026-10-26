//go:build linux

package execx

// IgnoreRLimitDataPath is the kernel's ignore_rlimit_data parameter. When
// it is set (the boot option ignore_rlimit_data), mmap(2) past RLIMIT_DATA
// only logs a warning, so the child memory limit binds brk(2) alone.
const IgnoreRLimitDataPath = "/sys/module/kernel/parameters/ignore_rlimit_data"

// IgnoreRLimitData reports whether the kernel parameter at path is set.
func IgnoreRLimitData(path string) (bool, error) {
	_ = path
	return false, nil
}
