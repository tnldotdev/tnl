package maintenance

import (
	"context"
	"log"
	"time"
)

type deviceLoginStore interface {
	ExpireDeviceLogins(context.Context, time.Time) error
}

func RunDeviceLoginCleanup(lifetime context.Context, store deviceLoginStore) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-lifetime.Done():
			return nil
		case now := <-ticker.C:
			ctx, cancel := context.WithTimeout(lifetime, 10*time.Second)
			err := store.ExpireDeviceLogins(ctx, now)
			cancel()
			if err != nil && lifetime.Err() == nil {
				log.Print("device login expiry failed; retrying")
			}
		}
	}
}
