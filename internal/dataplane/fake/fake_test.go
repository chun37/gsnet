package fake

import (
	"testing"

	"github.com/chun/gsnet/internal/dataplane"
)

func TestRecordsState(t *testing.T) {
	r := New()
	s := dataplane.State{WGInterface: "wg0"}
	if err := r.Reconcile(s); err != nil {
		t.Fatal(err)
	}
	if got, ok := r.Last(); !ok || got.WGInterface != "wg0" {
		t.Errorf("Last = %+v, %v; want wg0,true", got, ok)
	}
	if err := r.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if !r.Closed {
		t.Errorf("Closed = false, want true")
	}
}
