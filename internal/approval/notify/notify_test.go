package notify

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every URL, topic and value below is an invented test fixture; the token
// is generated per test.

func TestParseTopicURL(t *testing.T) {
	for raw, want := range map[string][2]string{
		"https://ntfy.example.test/approvals":        {"https://ntfy.example.test/", "approvals"},
		"https://ntfy.example.test/sub/path/topic_1": {"https://ntfy.example.test/sub/path/", "topic_1"},
		"http://127.0.0.1:8090/approvals":            {"http://127.0.0.1:8090/", "approvals"},
		"http://[::1]:8090/approvals":                {"http://[::1]:8090/", "approvals"},
		"http://localhost:8090/approvals":            {"http://localhost:8090/", "approvals"},
	} {
		p, topic, err := ParseTopicURL(raw)
		if err != nil || p != want[0] || topic != want[1] {
			t.Fatalf("%s: %q %q %v", raw, p, topic, err)
		}
	}
	for _, bad := range []string{
		"", "ntfy.example.test/approvals", "http://ntfy.example.test/approvals", "https://user:pw@ntfy.example.test/approvals",
		"https://ntfy.example.test/approvals?x=1", "https://ntfy.example.test/approvals#f", "https://ntfy.example.test/",
		"https://ntfy.example.test", "https://ntfy.example.test/bad topic", "https://ntfy.example.test/" + strings.Repeat("t", 65),
		"ftp://ntfy.example.test/approvals", "https:///approvals",
	} {
		if _, _, err := ParseTopicURL(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

type captured struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func capture(t *testing.T, status int) (*httptest.Server, *captured) {
	t.Helper()
	c := &captured{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.reqs = append(c.reqs, r)
		c.body = append(c.body, b)
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(ts.Close)
	return ts, c
}

func TestPublishJSON(t *testing.T) {
	ts, c := capture(t, http.StatusOK)
	token := "tk_" + strings.Repeat("z", 30)
	var logs bytes.Buffer
	n, err := New(ts.URL+"/approvals", token, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	err = n.Publish(t.Context(), Message{Title: "Approval requested: Write file on app-host", Message: "Write 12 bytes …\nExpires 2026-10-16T12:05:00Z",
		ViewURL: "https://approve.example.test/approvals/aaaaaaaaaaaaaaaaaaaaaaaaaa", Tags: []string{"lock"}, Priority: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.reqs) != 1 {
		t.Fatalf("%d requests", len(c.reqs))
	}
	r := c.reqs[0]
	if r.Method != http.MethodPost || r.URL.Path != "/" || r.Header.Get("Authorization") != "Bearer "+token ||
		!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("request %s %s %v", r.Method, r.URL, r.Header)
	}
	var body map[string]any
	if err := json.Unmarshal(c.body[0], &body); err != nil {
		t.Fatal(err)
	}
	if body["topic"] != "approvals" || body["title"] != "Approval requested: Write file on app-host" || body["priority"] != float64(4) {
		t.Fatalf("body %v", body)
	}
	actions, _ := body["actions"].([]any)
	if len(actions) != 1 {
		t.Fatalf("actions %v", body["actions"])
	}
	a, _ := actions[0].(map[string]any)
	if a["action"] != "view" || a["url"] != "https://approve.example.test/approvals/aaaaaaaaaaaaaaaaaaaaaaaaaa" || a["label"] == "" {
		t.Fatalf("action %v", a)
	}
	// Never an http action, a method, headers or a body that could approve.
	for _, bad := range []string{`"http"`, `"method"`, `"headers"`, "approve?", "/approve"} {
		if strings.Contains(string(c.body[0]), bad) {
			t.Fatalf("notification carries %s: %s", bad, c.body[0])
		}
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("token logged")
	}
}

func TestFailureLoggedNeverBlocks(t *testing.T) {
	ts, _ := capture(t, http.StatusForbidden)
	token := "tk_" + strings.Repeat("y", 30)
	var mu sync.Mutex
	var logs bytes.Buffer
	n, err := New(ts.URL+"/approvals", token, slog.New(slog.NewJSONHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	}), nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Publish(t.Context(), Message{Title: "x", Message: "y"}); err == nil {
		t.Fatal("a 403 was not an error")
	}
	start := time.Now()
	n.Send(Message{Title: "x", Message: "y"})
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("Send blocked")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		s := logs.String()
		mu.Unlock()
		if strings.Contains(s, "approval notification failed") {
			if strings.Contains(s, token) {
				t.Fatal("token logged")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no failure line: %s", s)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNoRedirectFollowed(t *testing.T) {
	other, oc := capture(t, http.StatusOK)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(ts.Close)
	n, err := New(ts.URL+"/approvals", "tk_"+strings.Repeat("x", 30), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Publish(t.Context(), Message{Title: "x", Message: "y"}); err == nil {
		t.Fatal("a redirect was a success")
	}
	if len(oc.reqs) != 0 {
		t.Fatal("the redirect was followed")
	}
}

func TestNewRefuses(t *testing.T) {
	if _, err := New("https://ntfy.example.test/approvals", "", nil); err == nil {
		t.Fatal("no token accepted")
	}
	if _, err := New("http://ntfy.example.test/approvals", "tk", nil); err == nil {
		t.Fatal("plain http accepted")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
