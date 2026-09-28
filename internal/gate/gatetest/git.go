//go:build linux

package gatetest

import (
	"encoding/pem"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Git test support: a local HTTPS smart-HTTP server (net/http/httptest TLS
// in front of `git http-backend` through net/http/cgi) and helpers that run
// git for test setup. The server's certificate reaches the gate only as a
// CA file supplied through the test constructor. Everything is invented.

// GitBin is the git binary the tests use (root-owned in the test images).
const GitBin = "/usr/bin/git"

// Git runs git as test setup, never through the gate, isolated from user
// and system configuration.
func Git(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), GitBin, append([]string{"-c", "user.name=Example", "-c", "user.email=dev@example.test",
		"-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always"}, args...)...) //nolint:gosec // G204: test setup with fixed git
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C.UTF-8"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// GitServer serves the bare repositories under Root over HTTPS.
type GitServer struct {
	Root string
	srv  *httptest.Server
}

// NewGitServer starts a server for the test's lifetime.
func NewGitServer(t testing.TB) *GitServer {
	t.Helper()
	if _, err := os.Stat(GitBin); err != nil {
		t.Fatalf("git is required at %s: %v", GitBin, err)
	}
	g := &GitServer{Root: t.TempDir()}
	g.srv = httptest.NewTLSServer(&cgi.Handler{Path: GitBin, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + g.Root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}})
	t.Cleanup(g.srv.Close)
	return g
}

// URL is the server's base URL (https://127.0.0.1:port).
func (g *GitServer) URL() string { return g.srv.URL }

// RepoURL is the HTTPS URL of a bare repository.
func (g *GitServer) RepoURL(repo string) string { return g.srv.URL + "/" + repo }

// Port is the server's TCP port.
func (g *GitServer) Port() string {
	u, _ := url.Parse(g.srv.URL)
	return u.Port()
}

// WriteCA writes the server's certificate as a PEM CA file.
func (g *GitServer) WriteCA(t testing.TB, p string) {
	t.Helper()
	WriteFile(t, p, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.srv.Certificate().Raw})), 0o644)
}

// Seed creates bare repository name with one commit of files and returns a
// working copy whose origin is the bare repository, for later pushes.
func (g *GitServer) Seed(t testing.TB, name string, files map[string]string) string {
	t.Helper()
	work := filepath.Join(t.TempDir(), "seed")
	Mkdir(t, work, 0o755)
	Git(t, work, "init", "-q")
	for p, c := range files {
		WriteFile(t, filepath.Join(work, p), c, 0o644)
	}
	Git(t, work, "add", "-A")
	Git(t, work, "commit", "-q", "-m", "initial")
	Git(t, g.Root, "clone", "-q", "--bare", work, name)
	Git(t, work, "remote", "add", "origin", filepath.Join(g.Root, name))
	return work
}

// Push commits file in work and pushes it upstream.
func Push(t testing.TB, work, file, content, msg string) {
	t.Helper()
	WriteFile(t, filepath.Join(work, file), content, 0o644)
	Git(t, work, "add", "-A")
	Git(t, work, "commit", "-q", "-m", msg)
	Git(t, work, "push", "-q", "origin", "main")
}

// Clone makes a working copy at dst whose origin is the HTTPS URL.
func (g *GitServer) Clone(t testing.TB, name, dst string) {
	t.Helper()
	Git(t, filepath.Dir(dst), "clone", "-q", filepath.Join(g.Root, name), filepath.Base(dst))
	Git(t, dst, "remote", "set-url", "origin", g.RepoURL(name))
}
