// Package notify publishes approval notifications to an ntfy topic
// (docs/handoff/S4B-APPROVAL.md §3c, §6.7): JSON publish with a bearer
// token, carrying a title, a message and a view link to the approval page,
// never an action that approves or declines. A failure is logged and never
// blocks approval.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Timeout bounds one publish.
const Timeout = 10 * time.Second

// maxBody bounds a published message.
const maxBody = 8 << 10

// Message is one notification.
type Message struct {
	Title   string
	Message string
	// ViewURL, when set, becomes the notification's one "view" action.
	ViewURL string
	Tags    []string
	// Priority is ntfy's 1..5 (0: the server's default).
	Priority int
}

// Notifier publishes to one topic.
type Notifier struct {
	publish string
	topic   string
	token   string
	client  *http.Client
	logger  *slog.Logger
}

var topicRE = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)

// ParseTopicURL checks a topic URL: https (http only for a loopback host),
// no userinfo, query or fragment, and a last path segment that is a topic
// name. It returns the URL to publish to (without the topic) and the topic.
func ParseTopicURL(raw string) (publish, topic string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", "", errors.New("must be an absolute https:// URL of an ntfy topic, without userinfo, query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHost(u.Hostname()) {
			return "", "", errors.New("must use https:// (http:// only for a loopback host)")
		}
	default:
		return "", "", errors.New("must use https:// (http:// only for a loopback host)")
	}
	dir, last, _ := strings.Cut(reverse(u.Path), "/")
	topic, base := reverse(dir), reverse(last)
	if !topicRE.MatchString(topic) {
		return "", "", errors.New("its last path segment must be a topic name ([-_A-Za-z0-9], at most 64 characters)")
	}
	p := *u
	p.Path = base + "/"
	p.RawPath = ""
	return p.String(), topic, nil
}

func reverse(s string) string {
	r := []byte(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// New returns a notifier for the topic URL raw with the bearer token. It
// uses no proxy and follows no redirect, so the token goes only to the
// configured server.
func New(raw, token string, logger *slog.Logger) (*Notifier, error) {
	publish, topic, err := ParseTopicURL(raw)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("a bearer token is required")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Notifier{
		publish: publish, topic: topic, token: token, logger: logger,
		client: &http.Client{
			Timeout:       Timeout,
			Transport:     &http.Transport{Proxy: nil, TLSHandshakeTimeout: Timeout, ResponseHeaderTimeout: Timeout},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type action struct {
	Action string `json:"action"`
	Label  string `json:"label"`
	URL    string `json:"url"`
	Clear  bool   `json:"clear"`
}

type publishBody struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title,omitempty"`
	Message  string   `json:"message"`
	Tags     []string `json:"tags,omitempty"`
	Priority int      `json:"priority,omitempty"`
	Actions  []action `json:"actions,omitempty"`
}

// Publish sends m and waits for the answer (at most Timeout). Anything but
// a 2xx answer is an error.
func (n *Notifier) Publish(ctx context.Context, m *Message) error {
	body := publishBody{Topic: n.topic, Title: m.Title, Message: m.Message, Tags: m.Tags, Priority: m.Priority}
	if m.ViewURL != "" {
		// A view action only opens the page; nothing in a notification can
		// approve or decline (handoff Q13).
		body.Actions = []action{{Action: "view", Label: "Open approval page", URL: m.ViewURL}}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if len(b) > maxBody {
		return fmt.Errorf("notification of %d bytes exceeds %d", len(b), maxBody)
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.publish, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.token)
	res, err := n.client.Do(req)
	if err != nil {
		return errors.New("the notify server could not be reached")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	_ = res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("the notify server answered %d", res.StatusCode)
	}
	return nil
}

// Send publishes m in the background and logs a failure; it never blocks.
func (n *Notifier) Send(m *Message) {
	go func() {
		if err := n.Publish(context.Background(), m); err != nil {
			n.logger.Warn("approval notification failed", slog.String("reason", err.Error()))
		}
	}()
}
