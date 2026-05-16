// Package fake is an in-memory Reconciler for tests and unprivileged dry-runs.
// It records every State it is asked to reconcile and never touches the host.
package fake

import (
	"sync"

	"github.com/chun/gsnet/internal/dataplane"
)

type Reconciler struct {
	mu       sync.Mutex
	Applied  []dataplane.State
	Closed   bool
	FakeStats []dataplane.TrafficStats // set by tests; returned by Stats()
}

// Stats returns FakeStats (defaults to nil for an empty fake).
func (r *Reconciler) Stats() ([]dataplane.TrafficStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.FakeStats, nil
}

func New() *Reconciler { return &Reconciler{} }

func (r *Reconciler) Reconcile(s dataplane.State) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Applied = append(r.Applied, s)
	return nil
}

func (r *Reconciler) Shutdown() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Closed = true
	return nil
}

// Last returns the most recently applied state, if any.
func (r *Reconciler) Last() (dataplane.State, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.Applied) == 0 {
		return dataplane.State{}, false
	}
	return r.Applied[len(r.Applied)-1], true
}
