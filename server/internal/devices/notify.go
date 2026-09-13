package devices

import (
	"sync"

	"github.com/aidotvpn/server/internal/domain"
)

// In-process notification for enrollment decisions.
//
// The phone was polling every three seconds while an admin stood next to
// it deciding — which is the one situation where a three-second delay is
// noticed, because both people are watching. The device is already
// waiting on a connection; the server can simply not answer until there
// is something to say.
//
// ## Why a channel and a ticker
//
// This map delivers the decision immediately when the approving request
// is handled by the same process. With more than one controller replica
// it will not be, so the waiting handler also re-reads the row on a
// short ticker. The channel is the fast path; the ticker is the one that
// is always correct.
//
// Getting this the other way round — treating the notifier as the source
// of truth — would work on one machine and fail quietly behind a load
// balancer, which is the kind of bug that only appears in production.
type decisionNotifier struct {
	mu   sync.Mutex
	subs map[domain.ID][]chan struct{}
}

var decisions = &decisionNotifier{subs: map[domain.ID][]chan struct{}{}}

// Subscribe returns a channel closed when this request is decided, and a
// function to release it.
//
// Buffered by one so Notify never blocks on a subscriber that has
// already gone away.
func (n *decisionNotifier) Subscribe(id domain.ID) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)

	n.mu.Lock()
	n.subs[id] = append(n.subs[id], ch)
	n.mu.Unlock()

	return ch, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		rest := n.subs[id][:0]
		for _, c := range n.subs[id] {
			if c != ch {
				rest = append(rest, c)
			}
		}
		if len(rest) == 0 {
			delete(n.subs, id)
		} else {
			n.subs[id] = rest
		}
	}
}

// Notify wakes everyone waiting on this request.
func (n *decisionNotifier) Notify(id domain.ID) {
	n.mu.Lock()
	subs := append([]chan struct{}(nil), n.subs[id]...)
	n.mu.Unlock()

	for _, c := range subs {
		select {
		case c <- struct{}{}:
		default: // already signalled; the waiter will re-read either way
		}
	}
}

// WatchDecision exposes the notifier to the HTTP layer.
func WatchDecision(id domain.ID) (<-chan struct{}, func()) { return decisions.Subscribe(id) }

// AnnounceDecision is called after a request is approved or rejected.
func AnnounceDecision(id domain.ID) { decisions.Notify(id) }
