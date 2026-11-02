//go:build linux

package setup

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestParseMountinfo(t *testing.T) {
	// Invented lines in proc_pid_mountinfo(5)'s format.
	in := "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw\n" +
		"24 22 0:30 / /srv/with\\040space rw - xfs /dev/sdb1 rw\n" +
		"25 22 0:31 / /mnt/share rw - nfs4 192.0.2.30:/export rw\n" +
		"26 22 0:32 / /mnt/fuse rw - fuse.sshfs remote: rw\n"
	got, err := ParseMountinfo([]byte(in))
	want := []Mount{{"/", "ext4"}, {"/proc", "proc"}, {"/srv/with space", "xfs"}, {"/mnt/share", "nfs4"}, {"/mnt/fuse", "fuse.sshfs"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{"22 1 8:1 / / rw\n", "22 1 8:1 / rel rw - ext4 x rw\n", "22 1 8:1 / /a\\04 rw - ext4 x rw\n", "22 1 8:1 / /a\\999 rw - ext4 x rw\n"} {
		if _, err := ParseMountinfo([]byte(bad)); !errors.Is(err, ErrMountinfo) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// FuzzParseMountinfo: never panics; every accepted mount point is absolute.
func FuzzParseMountinfo(f *testing.F) {
	f.Add([]byte("22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n24 22 0:30 / /srv/a\\040b rw - xfs /dev/sdb1 rw\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ms, err := ParseMountinfo(b)
		if err != nil {
			return
		}
		for _, m := range ms {
			if !filepath.IsAbs(m.Point) || m.FSType == "" {
				t.Fatalf("accepted %+v", m)
			}
		}
	})
}

// TestOwnerScan walks a real tree: an entry owned by one of the ids is
// the hit (the test's own uid stands for the new id); pseudo and network
// filesystems are listed and skipped; a narrowed scan names what it does
// not cover.
func TestOwnerScan(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "owned"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	me := uint32(os.Getuid()) //nolint:gosec // G115: a uid
	mounts := []Mount{{root, "ext4"}, {"/proc", "proc"}, {"/mnt/share", "nfs4"}, {"/mnt/fuse", "fuse.sshfs"}}
	res, err := ownerScan(mounts, []uint32{me}, nil, nil)
	if err != nil || !strings.HasPrefix(res.Hit, root) {
		t.Fatalf("hit %q %v", res.Hit, err)
	}
	if want := []string{"/mnt/fuse (fuse.sshfs)", "/mnt/share (nfs4)", "/proc (proc)"}; !reflect.DeepEqual(res.Skipped, want) {
		t.Fatalf("skipped %v", res.Skipped)
	}
	res, err = ownerScan(mounts, []uint32{4200005}, []uint32{4200005}, nil)
	if err != nil || res.Hit != "" || !slices.Equal(res.Walked, []string{root}) {
		t.Fatalf("no owner: %+v %v", res, err)
	}
	res, err = ownerScan(append(mounts, Mount{"/srv", "xfs"}), []uint32{me}, nil, []string{deep})
	if err != nil || res.Hit != filepath.Join(deep, "owned") && res.Hit != deep {
		t.Fatalf("narrowed hit %+v %v", res, err)
	}
	if !slices.Equal(res.NotCovered, []string{root, "/srv"}) {
		t.Fatalf("not covered %v", res.NotCovered)
	}
}
