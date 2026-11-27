package operatorlog

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestBudgetCountsEverySuppressedSample(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b := NewBudget(1, 2)
		for range 2 {
			if dropped, ok := b.Take(t.Context(), observability.IngressEarlyClose); !ok || dropped != 0 {
				t.Fatal("initial burst did not log", dropped, ok)
			}
		}
		for range 100 {
			if _, ok := b.Take(t.Context(), observability.IngressEarlyClose); ok {
				t.Fatal("exceeded configured burst")
			}
		}
		time.Sleep(time.Second)
		if dropped, ok := b.Take(t.Context(), observability.IngressEarlyClose); !ok || dropped != 100 {
			t.Fatal("lost count of dropped samples", dropped, ok)
		}
		time.Sleep(time.Second)
		if dropped, ok := b.Take(t.Context(), observability.IngressEarlyClose); !ok || dropped != 0 {
			t.Fatal("reported dropped samples twice", dropped, ok)
		}
	})
}
