//go:build linux

package execx

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// IgnoreRLimitDataPath is the kernel's ignore_rlimit_data parameter. When
// it is set (the boot option ignore_rlimit_data), mmap(2) past RLIMIT_DATA
// only logs a warning (may_expand_vm, mm/mmap.c), so the child memory limit
// binds brk(2) alone.
const IgnoreRLimitDataPath = "/sys/module/kernel/parameters/ignore_rlimit_data"

// IgnoreRLimitData reports whether the kernel parameter at path is set
// (Y or 1) or not (N or 0); anything else, or no parameter, is an error.
func IgnoreRLimitData(path string) (bool, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a fixed kernel parameter (tests pass their own)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 16))
	if err != nil {
		return false, err
	}
	switch v := strings.TrimSpace(string(b)); v {
	case "Y", "1":
		return true, nil
	case "N", "0":
		return false, nil
	default:
		return false, fmt.Errorf("ignore_rlimit_data is %q, not Y or N", v)
	}
}
