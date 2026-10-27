//go:build linux

package fsx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// HashFile (handoff N-5, the helper's priv_hash_file): the same path rules
// as ReadFile, the same hash, binary verdict and line count as a preview
// over ReadFile's default read, and a file that ReadFile refuses because it
// holds a private key hashed with private_key set, never read back. Every
// layout is invented.

// FuzzHashFile: for any path under a fixture tree and any content of the
// file f, HashFile succeeds exactly where ReadFile does, or where ReadFile
// refuses a private key; it then agrees with ReadFile on size, SHA-256 and
// binary, counts lines exactly when ReadFile returned the whole file as
// text, and reports private_key exactly for ReadFile's private-key
// refusal; elsewhere it refuses as ReadFile does.
func FuzzHashFile(f *testing.F) {
	fs, root := fdEnv(f, selfTrust)
	mkdirMode(f, root+"/d", 0o755)
	putMode(f, root+"/d/g", "g\n", 0o644)
	must(f, unix.Mkfifo(root+"/fifo", 0o644))
	must(f, os.Symlink("f", root+"/link"))
	mkdirMode(f, root+"/denied", 0o755)
	putMode(f, root+"/denied/s", "s\n", 0o644)
	key := "-----BEGIN " + "PRIVATE KEY-----\nMIGHAgEAinvented\n-----END " + "PRIVATE KEY-----\n"
	for _, c := range []struct{ rel, content string }{
		{"f", "key: value\n"}, {"f", key}, {"f", "cert\n" + key}, {"f", "\x00\x01"}, {"f", ""}, {"f", "no newline"},
		{"f", strings.Repeat("x\n", 40000)}, {"f", strings.Repeat("é", 5000) + "\xff"}, {"d", "x"}, {"d/g", "x"},
		{"fifo", "x"}, {"link", key}, {"denied/s", "x"}, {"missing", "x"}, {"../x", "x"}, {"/etc/hostname", "x"},
	} {
		f.Add(c.rel, []byte(c.content))
	}
	f.Fuzz(func(t *testing.T, rel string, content []byte) {
		content = content[:min(len(content), 200<<10)]
		must(t, os.WriteFile(root+"/f", content, 0o644)) //nolint:gosec // G306: fixture
		p := rel
		if !strings.HasPrefix(rel, "/") {
			p = root + "/" + rel
		}
		h, errH := fs.HashFile(p)
		r, errR := fs.ReadFile(p, ReadOptions{})
		keyRefused := errR != nil && strings.Contains(errR.Error(), "file contains a private key")
		switch {
		case keyRefused:
			if errH != nil || !h.PrivateKey || h.Lines == nil && !h.Binary && h.Size <= 64<<10 {
				t.Fatalf("%q: a private key: %+v %v", p, h, errH)
			}
			sum := sha256.Sum256(content)
			if h.SHA256 != hex.EncodeToString(sum[:]) || h.Size != int64(len(content)) {
				t.Fatalf("%q: hash %+v of %d bytes", p, h, len(content))
			}
		case errR != nil:
			if errH == nil || errH.Error() != errR.Error() {
				t.Fatalf("%q: HashFile %v, ReadFile %v", p, errH, errR)
			}
		default:
			if errH != nil || h.PrivateKey || h.Size != r.Size || h.SHA256 != r.SHA256 || h.Binary != r.Binary {
				t.Fatalf("%q: HashFile %+v %v, ReadFile %+v", p, h, errH, r)
			}
			whole := !r.Binary && !r.Truncated && r.Offset == 0 && int64(len(r.Content)) == r.Size
			if whole != (h.Lines != nil) || whole && *h.Lines != lineCount([]byte(r.Content)) {
				t.Fatalf("%q: lines %v, ReadFile %+v", p, h.Lines, r)
			}
		}
	})
}

func lineCount(b []byte) int {
	n := bytes.Count(b, []byte("\n"))
	if len(b) > 0 && b[len(b)-1] != '\n' {
		n++
	}
	return n
}
