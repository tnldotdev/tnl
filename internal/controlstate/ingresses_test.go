package controlstate

import (
	"testing"
	"time"
)

func TestVisitorNetworkHashKeysAreDateScoped(t *testing.T) {
	masterKey := [32]byte{1}
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	keys := visitorNetworkHashKeys(masterKey, now)
	if !keys[0].UTCDate.Equal(time.Date(2026, time.September, 4, 0, 0, 0, 0, time.UTC)) ||
		!keys[1].UTCDate.Equal(time.Date(2026, time.September, 5, 0, 0, 0, 0, time.UTC)) ||
		keys[0].Key == masterKey || keys[0].Key == keys[1].Key {
		t.Fatalf("visitor network hash keys = %#v", keys)
	}
	if repeated := visitorNetworkHashKeys(masterKey, now.Add(time.Minute)); repeated != keys {
		t.Fatalf("visitor network hash keys changed within date: %#v", repeated)
	}
}
