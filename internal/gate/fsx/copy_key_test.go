//go:build linux

package fsx

import (
	"bytes"
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
// and a bound move's destination hash (hashTarget), so their too_large
// refusals name the 256 MiB bound and no program (S7-3; they said "the
// helper"). A write or copy hashes the file it replaces without a cap.
func TestTooLargeMessagesAreNeutral(t *testing.T) {
	e := newEnv(t)
	sparse := filepath.Join(e.write, "sparse.bin")
	put(t, sparse, "")
	must(t, os.Truncate(sparse, maxHashBytes+1<<20))
	src := filepath.Join(e.write, "small.txt")
	put(t, src, "small\n")
	_, errHash := e.fs.HashFile(sparse)
	_, errMove := e.fs.MoveExpecting(src, sparse, true, strings.Repeat("0", 64))
	for name, err := range map[string]error{"HashFile": errHash, "a bound move": errMove} {
		wantCode(t, err, protocol.CodeTooLarge)
		if msg := err.Error(); strings.Contains(msg, "helper") || strings.Contains(msg, "gate") || !strings.Contains(msg, "256 MiB") {
			t.Fatalf("%s: %q", name, msg)
		}
	}
}

// FuzzCopySourceKey: for any source content, a copy is refused as holding a
// private key exactly when read_file refuses the same file for one, and a
// copy that is not refused writes the source unchanged. The key is
// assembled at run time.
func FuzzCopySourceKey(f *testing.F) {
	fs, root := fdEnv(f, selfTrust)
	key := keyFixture(4)
	filler := strings.Repeat("log line of ordinary text\n", 3000) // about 77 KiB
	for _, c := range []string{"", "key: value\n", key, filler + key, filler[:sniffKeyBytes-10] + "\n" + key,
		"-----BEGIN " + "CERTIFICATE-----\n", filler + "PRIVATE KEY\n", "\x00\x01" + key} {
		f.Add([]byte(c))
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		content = content[:min(len(content), 200<<10)]
		src, dst := root+"/src", root+"/dst"
		must(t, os.WriteFile(src, content, 0o644)) //nolint:gosec // G306: fixture
		_ = os.Remove(dst)
		_, errR := fs.ReadFile(src, ReadOptions{})
		_, errC := fs.Copy(src, dst, false)
		readKey := errR != nil && strings.Contains(errR.Error(), "file contains a private key")
		copyKey := errC != nil && strings.Contains(errC.Error(), "file contains a private key")
		if readKey != copyKey {
			t.Fatalf("read_file refused a key: %v (%v); copy: %v (%v)", readKey, errR, copyKey, errC)
		}
		if errC == nil {
			got, err := os.ReadFile(dst) //nolint:gosec // G304: fixture
			must(t, err)
			if !bytes.Equal(got, content) {
				t.Fatal("the copy differs from its source")
			}
		} else if _, err := os.Lstat(dst); !os.IsNotExist(err) {
			t.Fatalf("a refused copy left %s: %v", dst, err)
		}
	})
}
