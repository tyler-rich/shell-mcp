//go:build linux

package fsx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tyler-rich/shell-mcp/internal/protocol"
)

// A copy's source is searched for a private key as read_file searches a
// file since S7-1: the whole source, not its first 64 KiB (S7-3), so a key
// that lies past them is refused, never copied. The gate's copy and the
// helper's priv_copy share CopyAs. Every layout and key is invented and
// assembled at run time (keyFixture).

func TestCopySourceKeyBeyondFirstWindow(t *testing.T) {
	e := newEnv(t)
	filler := strings.Repeat("log line of ordinary text\n", 4000) // about 100 KiB
	key := keyFixture(300)                                        // about 19 KiB
	pad := strings.Repeat("x", sniffKeyBytes-10)
	for name, content := range map[string]string{
		"a key after 100 KiB":                   filler + key + "after\n",
		"a header straddling the 64 KiB mark":   pad + "\n" + key,
		"a key in the last bytes of the source": filler + filler + key,
	} {
		t.Run(name, func(t *testing.T) {
			if len(content) > e.fs.cfg.Limits.MaxReadBytes {
				t.Fatalf("fixture of %d bytes is above max_read_bytes", len(content))
			}
			src := filepath.Join(e.read, "late.log")
			dst := filepath.Join(e.write, "late.copy")
			put(t, src, content)
			_ = os.Remove(dst)
			_, err := e.fs.Copy(src, dst, false)
			if err == nil {
				t.Fatal("a source holding a private key past its first 64 KiB was copied")
			}
			wantCode(t, err, protocol.CodePathDenied)
			if !strings.Contains(err.Error(), "private key") {
				t.Fatalf("refusal %v", err)
			}
			if _, serr := os.Lstat(dst); !os.IsNotExist(serr) {
				t.Fatalf("the destination exists: %v", serr)
			}
		})
	}
	// A source of the same size without a key is copied.
	src := filepath.Join(e.read, "plain.log")
	put(t, src, filler+filler)
	_, err := e.fs.Copy(src, filepath.Join(e.write, "plain.copy"), false)
	must(t, err)
}

// TestTooLargeMessagesAreNeutral: the gate and the helper share HashFile
// and the commit's destination hash, so their too_large refusals name the
// 256 MiB bound and no program (S7-3; they said "the helper").
func TestTooLargeMessagesAreNeutral(t *testing.T) {
	e := newEnv(t)
	sparse := filepath.Join(e.write, "sparse.bin")
	put(t, sparse, "")
	must(t, os.Truncate(sparse, maxHashBytes+1<<20))
	src := filepath.Join(e.write, "small.txt")
	put(t, src, "small\n")
	_, errHash := e.fs.HashFile(sparse)
	_, errWrite := e.fs.WriteFile(sparse, []byte("new\n"), WriteOptions{ExpectedSHA256: strings.Repeat("0", 64)})
	_, errMove := e.fs.MoveExpecting(src, sparse, true, strings.Repeat("0", 64))
	for name, err := range map[string]error{"HashFile": errHash, "a bound write": errWrite, "a bound move": errMove} {
		wantCode(t, err, protocol.CodeTooLarge)
		if msg := err.Error(); strings.Contains(msg, "helper") || strings.Contains(msg, "gate") || !strings.Contains(msg, "256 MiB") {
			t.Fatalf("%s: %q", name, msg)
		}
	}
}
