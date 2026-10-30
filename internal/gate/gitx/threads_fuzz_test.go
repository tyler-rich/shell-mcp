package gitx_test

import (
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/gate/gitx"
)

// FuzzThreadKeyName: the rule never panics and matches exactly the keys
// whose last component, lowercased, ends in threads, workers, jobs or
// parallel, or is preloadindex or thresholdforparallelism (handoff N-30).
func FuzzThreadKeyName(f *testing.F) {
	for _, k := range []string{"pack.threads", "core.preloadIndex", "checkout.workers", "hook.<event>.jobs", "fetch.parallel",
		"checkout.thresholdForParallelism", "user.name", "", ".", "a..b", "x.THREADS", "threads"} {
		f.Add(k)
	}
	f.Fuzz(func(t *testing.T, k string) {
		parts := strings.Split(k, ".")
		name := strings.ToLower(parts[len(parts)-1])
		want := name == "preloadindex" || name == "thresholdforparallelism"
		for _, s := range []string{"threads", "workers", "jobs", "parallel"} {
			want = want || strings.HasSuffix(name, s)
		}
		if got := gitx.ThreadKeyName(k); got != want {
			t.Fatalf("ThreadKeyName(%q) = %v, want %v", k, got, want)
		}
	})
}
