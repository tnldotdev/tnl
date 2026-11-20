package local

import (
	"context"
	"sync"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// registrations opened by the same native process can have different
// management sessions. the watch uses only the run credentials, over the
// process's normal native transport. drop the client after its last wait.
type appPublisherWatches struct {
	mu      sync.Mutex
	origins map[string]*appWatchOrigin
}

type appWatchOrigin struct {
	client *clientcontrol.Client
	users  int
}

type appWatchControl struct {
	publisherservice.RunControl
	service string
	watches *appPublisherWatches
}

func (c appWatchControl) WaitPublisherRun(ctx context.Context, scope controlv1.PublisherWatchRun) (int64, error) {
	if scope.ServiceId != c.service {
		return 0, publisheridentity.ErrScope
	}
	url := c.ControlURL()
	w := c.watches
	w.mu.Lock()
	origin := w.origins[url]
	if origin == nil {
		client, err := clientcontrol.New(url, nil, "")
		if err != nil {
			w.mu.Unlock()
			return 0, err
		}
		origin = &appWatchOrigin{client: client}
		if w.origins == nil {
			w.origins = make(map[string]*appWatchOrigin)
		}
		w.origins[url] = origin
	}
	origin.users++
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		origin.users--
		if origin.users == 0 {
			delete(w.origins, url)
		}
	}()
	return origin.client.WaitPublisherRun(ctx, scope)
}
