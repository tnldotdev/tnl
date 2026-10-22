package maintenance

import (
	"context"
	"log"
	"time"
)

type visitorPermissionStore interface {
	ExpireVisitorPermissions(context.Context, time.Time) error
	ExpireDeviceLogins(context.Context, time.Time) error
}

func RunVisitorPermissionCleanup(lifetime context.Context, store visitorPermissionStore) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-lifetime.Done():
			return nil
		case now := <-ticker.C:
			ctx, cancel := context.WithTimeout(lifetime, 10*time.Second)
			err := store.ExpireVisitorPermissions(ctx, now)
			if err == nil {
				err = store.ExpireDeviceLogins(ctx, now)
			}
			cancel()
			if err != nil && lifetime.Err() == nil {
				log.Print("visitor IP expiry failed; retrying")
			}
		}
	}
}
