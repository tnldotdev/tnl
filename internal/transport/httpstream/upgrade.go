package httpstream

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"

	"github.com/tnldotdev/tnl/internal/failure"
)

// ServeProxy keeps Go's reverse proxy responsible for HTTP and upgrade copying,
// but joins upgrade cleanup before its request handler returns. record is a
// required owner sink: cleanup failures survive even when ServeHTTP panics.
func ServeProxy(configured *httputil.ReverseProxy, w http.ResponseWriter, r *http.Request, record func(error)) {
	if record == nil {
		panic("httpstream: proxy requires a cleanup owner")
	}
	var upgrade *joinedUpgrade
	defer func() {
		if upgrade != nil {
			if err := upgrade.Close(); err != nil && !failure.Only(err, net.ErrClosed) {
				record(err)
			}
		}
	}()
	proxy := *configured
	proxy.ModifyResponse = func(response *http.Response) error {
		// capture the final body after existing hooks, including when a hook
		// fails or panics. Go still validates upgrade headers and hijacking.
		defer func() {
			if body, ok := response.Body.(io.ReadWriteCloser); ok && response.StatusCode == http.StatusSwitchingProtocols {
				upgrade, response.Body = newJoinedUpgrade(body)
			}
		}()
		if configured.ModifyResponse != nil {
			return configured.ModifyResponse(response)
		}
		return nil
	}
	proxy.ServeHTTP(w, r)
}

type joinedUpgrade struct {
	body io.ReadWriteCloser
	mu   sync.Mutex
	work sync.WaitGroup
	done chan struct{}
	// closing fences entry before the underlying close unblocks current IO.
	closing bool
	err     error
}

func newJoinedUpgrade(body io.ReadWriteCloser) (*joinedUpgrade, io.ReadWriteCloser) {
	joined := &joinedUpgrade{body: body, done: make(chan struct{})}
	if writer, ok := body.(interface{ CloseWrite() error }); ok {
		return joined, &joinedUpgradeHalfClose{joinedUpgrade: joined, writer: writer}
	}
	return joined, joined
}

func (u *joinedUpgrade) enter() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closing {
		return false
	}
	u.work.Add(1)
	return true
}

func (u *joinedUpgrade) Read(value []byte) (int, error) {
	if !u.enter() {
		return 0, net.ErrClosed
	}
	defer u.work.Done()
	return u.body.Read(value)
}

func (u *joinedUpgrade) Write(value []byte) (int, error) {
	if !u.enter() {
		return 0, net.ErrClosed
	}
	defer u.work.Done()
	return u.body.Write(value)
}

func (u *joinedUpgrade) Close() error {
	u.mu.Lock()
	if u.closing {
		u.mu.Unlock()
		<-u.done
		return u.err
	}
	u.closing = true
	u.mu.Unlock()
	err := u.body.Close()
	u.work.Wait()
	u.mu.Lock()
	u.err = errors.Join(u.err, err)
	u.mu.Unlock()
	close(u.done)
	return u.err
}

type joinedUpgradeHalfClose struct {
	*joinedUpgrade
	writer interface{ CloseWrite() error }
}

func (u *joinedUpgradeHalfClose) CloseWrite() error {
	if !u.enter() {
		return net.ErrClosed
	}
	defer u.work.Done()
	err := u.writer.CloseWrite()
	if err != nil && !failure.Only(err, net.ErrClosed) {
		u.mu.Lock()
		u.err = errors.Join(u.err, err)
		u.mu.Unlock()
	}
	return err
}
