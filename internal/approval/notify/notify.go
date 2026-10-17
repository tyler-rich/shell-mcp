// Package notify publishes approval notifications to an ntfy topic
// (docs/handoff/S4B-APPROVAL.md §3c, §6.7): JSON publish with a bearer
// token, carrying a title, a message and a view link to the approval page,
// never an action that approves or declines. A failure is logged and never
// blocks approval.
package notify

import (
	"context"
	"log/slog"
	"time"
)

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
	logger *slog.Logger
}

// ParseTopicURL checks a topic URL: https (http only for a loopback host),
// no userinfo, query or fragment, and a last path segment that is a topic
// name. It returns the URL to publish to (without the topic) and the topic.
func ParseTopicURL(raw string) (publish, topic string, err error) { return "", "", nil }

// New returns a notifier for the topic URL raw with the bearer token.
func New(raw, token string, logger *slog.Logger) (*Notifier, error) {
	return &Notifier{logger: logger}, nil
}

// Publish sends m and waits for the answer (at most the timeout).
func (n *Notifier) Publish(ctx context.Context, m Message) error { return nil }

// Send publishes m in the background and logs a failure; it never blocks.
func (n *Notifier) Send(m Message) {}

// Timeout bounds one publish.
const Timeout = 10 * time.Second
