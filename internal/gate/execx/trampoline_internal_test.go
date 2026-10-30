//go:build linux

package execx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// goodEnv is how Run starts the trampoline: pid 4242 (main thread), parent
// 4000, uid 60123, no terminal, fd 3 a stream socket whose peer is the
// parent under the same uid.
func goodEnv() *trampolineEnv {
	return &trampolineEnv{
		args: []string{"/usr/local/bin/shell-mcp-gate", TrampolineArg},
		pid:  4242, tid: 4242, ppid: 4000, uid: 60123,
		atSecure:   func() (uintptr, error) { return 0, nil },
		isTerminal: func(int) bool { return false },
		control: func() (bool, *unix.Ucred, error) {
			return true, &unix.Ucred{Pid: 4000, Uid: 60123, Gid: 60123}, nil
		},
	}
}

// TestTrampolineRefusal covers every refusal, including the ones the
// process-level tests cannot set up: a terminal on fd 0, 1 or 2 (no test
// allocates a terminal), another thread, and a peer under another uid.
func TestTrampolineRefusal(t *testing.T) {
	if why := trampolineRefusal(goodEnv()); why != "" {
		t.Fatalf("as Run starts it: refused %q", why)
	}
	for _, c := range []struct {
		name string
		mod  func(*trampolineEnv)
		want string
	}{
		{"no argument", func(e *trampolineEnv) { e.args = e.args[:1] }, "exactly one argument"},
		{"extra argument", func(e *trampolineEnv) { e.args = append(e.args, "x") }, "exactly one argument"},
		{"other argument", func(e *trampolineEnv) { e.args[1] = "serve" }, "exactly one argument"},
		{"environment", func(e *trampolineEnv) { e.environ = []string{"SSH_CONNECTION=x"} }, "empty environment"},
		{"privileged exec (AT_SECURE)", func(e *trampolineEnv) { e.atSecure = func() (uintptr, error) { return 1, nil } }, "it gained privileges when executed (AT_SECURE)"},
		{"auxiliary vector unreadable", func(e *trampolineEnv) {
			e.atSecure = func() (uintptr, error) { return 0, errNoATSecure }
		}, "it gained privileges when executed (AT_SECURE)"},
		{"other thread", func(e *trampolineEnv) { e.tid = 4243 }, "main thread"},
		{"terminal on fd 0", func(e *trampolineEnv) { e.isTerminal = func(fd int) bool { return fd == 0 } }, "fd 0 is a terminal"},
		{"terminal on fd 1", func(e *trampolineEnv) { e.isTerminal = func(fd int) bool { return fd == 1 } }, "fd 1 is a terminal"},
		{"terminal on fd 2", func(e *trampolineEnv) { e.isTerminal = func(fd int) bool { return fd == 2 } }, "fd 2 is a terminal"},
		{"no fd 3", func(e *trampolineEnv) {
			e.control = func() (bool, *unix.Ucred, error) { return false, nil, unix.EBADF }
		}, "fd 3 is not an open socket"},
		{"fd 3 not a stream socket", func(e *trampolineEnv) {
			e.control = func() (bool, *unix.Ucred, error) { return false, nil, nil }
		}, "not a Unix stream socket"},
		{"no peer credentials", func(e *trampolineEnv) {
			e.control = func() (bool, *unix.Ucred, error) { return true, nil, nil }
		}, "peer is not the parent"},
		{"peer is another process", func(e *trampolineEnv) {
			e.control = func() (bool, *unix.Ucred, error) { return true, &unix.Ucred{Pid: 1234, Uid: 60123}, nil }
		}, "peer is not the parent"},
		{"reparented to init", func(e *trampolineEnv) {
			e.ppid = 1
			e.control = func() (bool, *unix.Ucred, error) { return true, &unix.Ucred{Pid: 1, Uid: 60123}, nil }
		}, "peer is not the parent"},
		{"peer under another uid", func(e *trampolineEnv) {
			e.control = func() (bool, *unix.Ucred, error) { return true, &unix.Ucred{Pid: 4000, Uid: 0}, nil }
		}, "peer runs as another user"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := goodEnv()
			c.mod(e)
			if why := trampolineRefusal(e); !strings.Contains(why, c.want) || why == "" {
				t.Fatalf("refusal %q, want %q", why, c.want)
			}
		})
	}
}

func validConfig() *trampolineConfig {
	return &trampolineConfig{
		Path: "/usr/bin/example-tool", Argv: []string{"/usr/bin/example-tool", "a b", "", "\xff\xfe"},
		Env: []string{"PATH=/usr/bin", "EMPTY="}, Dir: "/srv/app", Files: 2,
		Limits: []childLimit{{Resource: unix.RLIMIT_CORE, Max: 0}, {Resource: unix.RLIMIT_NPROC, Max: 300}},
	}
}

// TestConfigMagic: the command's encoding carries passed descriptors since
// SMX2, so a trampoline of another release refuses it instead of misreading
// it.
func TestConfigMagic(t *testing.T) {
	if string(configMagic[:]) != "SMX2" {
		t.Fatalf("magic %q", configMagic)
	}
	b, err := encodeConfig(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeConfig(append([]byte("SMX1"), b[4:]...)); !errors.Is(err, errConfig) {
		t.Fatalf("an SMX1 command: %v", err)
	}
}

// TestPassedFileRefusal: the trampoline passes a descriptor only when it is
// a regular file open read-only.
func TestPassedFileRefusal(t *testing.T) {
	for _, c := range []struct {
		name string
		mode uint32
		fl   int
		want string
	}{
		{"regular, read-only", unix.S_IFREG, unix.O_RDONLY | unix.O_NONBLOCK, ""},
		{"read-write", unix.S_IFREG, unix.O_RDWR, "open read-only"},
		{"write-only", unix.S_IFREG, unix.O_WRONLY, "open read-only"},
		{"directory", unix.S_IFDIR, unix.O_RDONLY, "regular file"},
		{"FIFO", unix.S_IFIFO, unix.O_RDONLY, "regular file"},
		{"socket", unix.S_IFSOCK, unix.O_RDWR, "regular file"},
		{"character device", unix.S_IFCHR, unix.O_RDONLY, "regular file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			why := passedFileRefusal(5, c.mode, c.fl)
			if (c.want == "") != (why == "") || !strings.Contains(why, c.want) || c.want != "" && !strings.Contains(why, "fd 5") {
				t.Fatalf("refusal %q, want %q", why, c.want)
			}
		})
	}
}

func TestConfigRoundTrip(t *testing.T) {
	c := validConfig()
	b, err := encodeConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip:\n%+v\nwant\n%+v", got, c)
	}
}

func TestConfigEncodeRefuses(t *testing.T) {
	c := validConfig()
	c.Argv = append(c.Argv, "a\x00b")
	if _, err := encodeConfig(c); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("NUL: %v", err)
	}
	c = validConfig()
	c.Argv = make([]string, maxConfigItems+1)
	if _, err := encodeConfig(c); !errors.Is(err, unix.E2BIG) {
		t.Fatalf("too many arguments: %v", err)
	}
	c = validConfig()
	c.Env = []string{"BIG=" + strings.Repeat("x", maxConfigBytes)}
	if _, err := encodeConfig(c); !errors.Is(err, unix.E2BIG) {
		t.Fatalf("too large: %v", err)
	}
}

// TestConfigDecodeStrict: anything but exactly one well-formed command is
// refused.
func TestConfigDecodeStrict(t *testing.T) {
	enc := func(mod func(*trampolineConfig)) []byte {
		c := validConfig()
		mod(c)
		// Encode without encodeConfig's own checks, to reach the decoder.
		b := append([]byte(nil), configMagic[:]...)
		str := func(s string) { b = binary.LittleEndian.AppendUint32(b, uint32(len(s))); b = append(b, s...) } //nolint:gosec // G115: test sizes
		list := func(l []string) {
			b = binary.LittleEndian.AppendUint32(b, uint32(len(l))) //nolint:gosec // G115: test sizes
			for _, s := range l {
				str(s)
			}
		}
		str(c.Path)
		list(c.Argv)
		list(c.Env)
		str(c.Dir)
		b = binary.LittleEndian.AppendUint32(b, c.Files)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(c.Limits))) //nolint:gosec // G115: test sizes
		for _, l := range c.Limits {
			b = binary.LittleEndian.AppendUint32(b, l.Resource)
			b = binary.LittleEndian.AppendUint64(b, l.Max)
		}
		return b
	}
	good := enc(func(*trampolineConfig) {})
	if _, err := decodeConfig(good); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"bad magic", append([]byte("SMX0"), good[4:]...)},
		{"trailing byte", append(bytes.Clone(good), 0)},
		{"truncated", good[:len(good)-1]},
		{"relative path", enc(func(c *trampolineConfig) { c.Path, c.Argv[0] = "bin/tool", "bin/tool" })},
		{"relative dir", enc(func(c *trampolineConfig) { c.Dir = "srv" })},
		{"argv0 is not the path", enc(func(c *trampolineConfig) { c.Argv[0] = "/usr/bin/other" })},
		{"no argv", enc(func(c *trampolineConfig) { c.Argv = nil })},
		{"NUL in an argument", enc(func(c *trampolineConfig) { c.Argv[1] = "a\x00b" })},
		{"NUL in the path", enc(func(c *trampolineConfig) { c.Path, c.Argv[0] = "/a\x00b", "/a\x00b" })},
		{"environment entry without =", enc(func(c *trampolineConfig) { c.Env = []string{"PATH"} })},
		{"environment entry without a name", enc(func(c *trampolineConfig) { c.Env = []string{"=x"} })},
		{"unknown resource", enc(func(c *trampolineConfig) { c.Limits = []childLimit{{Resource: rlimNLimits, Max: 1}} })},
		{"too many limits", enc(func(c *trampolineConfig) { c.Limits = make([]childLimit, maxConfigLimits+1) })},
		{"too many files", enc(func(c *trampolineConfig) { c.Files = MaxFiles + 1 })},
		{"huge count", append(append([]byte(nil), configMagic[:]...), 0xff, 0xff, 0xff, 0xff)},
		{"oversized", append(bytes.Clone(good), make([]byte, maxConfigBytes)...)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeConfig(c.b); !errors.Is(err, errConfig) {
				t.Fatalf("decoded: %v", err)
			}
		})
	}
}

// FuzzDecodeConfig: the decoder never panics, and whatever it accepts
// encodes back to exactly the same bytes.
func FuzzDecodeConfig(f *testing.F) {
	good, err := encodeConfig(validConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("SMX1"))
	f.Add([]byte("SMX2"))
	f.Add(append(bytes.Clone(good), 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := decodeConfig(b)
		if err != nil {
			return
		}
		again, err := encodeConfig(c)
		if err != nil {
			t.Fatalf("accepted %x but cannot encode it: %v", b, err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("accepted %x, re-encodes as %x", b, again)
		}
	})
}

// TestAuxvSecure reads AT_SECURE from fake auxiliary vectors: set, clear,
// and missing (which is an error, so the trampoline refuses).
func TestAuxvSecure(t *testing.T) {
	if v, err := auxvSecure([][2]uintptr{{6, 4096}, {atSecureTag, 1}, {0, 0}}); err != nil || v != 1 {
		t.Fatalf("set: %d %v", v, err)
	}
	if v, err := auxvSecure([][2]uintptr{{atSecureTag, 0}, {0, 0}}); err != nil || v != 0 {
		t.Fatalf("clear: %d %v", v, err)
	}
	if _, err := auxvSecure([][2]uintptr{{6, 4096}, {0, 0}}); !errors.Is(err, errNoATSecure) {
		t.Fatalf("missing: %v", err)
	}
}

// TestLiveAuxvNotSecure: control for the AT_SECURE refusal. This test
// binary is not set-user-ID and has no file capabilities, so the live
// check reads the vector and finds AT_SECURE clear, which is what lets the
// trampoline run in every other test.
func TestLiveAuxvNotSecure(t *testing.T) {
	v, err := liveTrampolineEnv().atSecure()
	if err != nil || v != 0 {
		t.Fatalf("AT_SECURE %d, %v", v, err)
	}
}
