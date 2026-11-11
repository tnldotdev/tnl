package publisher

import (
	"errors"
	"testing"
)

func TestPublicURLAssignedEventUsesCurrentName(t *testing.T) {
	wantErr := errors.New("observer failed")
	config := Config{Observe: func(event Event) error {
		if event.Type != "public_url_assigned" || event.PublicURLID != "public_url_test" {
			t.Fatalf("assigned event=%+v", event)
		}
		return wantErr
	}}
	if err := observe(config, Event{Type: EventPublicURLAssigned, PublicURLID: "public_url_test"}); !errors.Is(err, wantErr) {
		t.Fatalf("observer error=%v, want %v", err, wantErr)
	}
}
