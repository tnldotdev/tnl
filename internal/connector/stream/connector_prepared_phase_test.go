package stream

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestPreparedConnectorPermissionPhasesFenceWrites(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{"acknowledged", nil},
		{"denied", errors.New("permission denied")},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := &PreparedConnector{ctx: t.Context(), stream: streamPrepared{}, permission: permissionUsable{}}
			entered, release := make(chan struct{}), make(chan struct{})
			result := make(chan error, 1)
			go func() {
				result <- p.renewPermission(t.Context(), func() error {
					close(entered)
					<-release
					return test.err
				}, time.Now().Add(time.Minute))
			}()
			<-entered
			p.mu.Lock()
			_, renewing := p.permission.(permissionRenewing)
			p.mu.Unlock()
			if !renewing {
				t.Fatal("writes were not fenced during permission renewal")
			}
			waiting := make(chan error, 1)
			go func() { waiting <- p.waitPermission(t.Context()) }()
			select {
			case <-waiting:
				t.Fatal("write proceeded before permission was acknowledged")
			default:
			}
			close(release)
			if err := <-result; !errors.Is(err, test.err) {
				t.Fatal("renewal lost the acknowledgement", err)
			}
			if err := <-waiting; (err == nil) != (test.err == nil) {
				t.Fatal("write permission did not follow the terminal renewal decision", err)
			}
			if test.err != nil {
				if err := p.renewPermission(t.Context(), func() error { return nil }, time.Now().Add(time.Minute)); err == nil {
					t.Fatal("denied permission returned to the usable phase")
				}
			}
		})
	}
}

func TestPreparedConnectorCloseJoinsPermissionFailure(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	p := &PreparedConnector{ctx: t.Context(), conn: local, stream: streamPrepared{}, permission: permissionUsable{}, permissionUntil: time.Now().Add(10 * time.Millisecond), stop: func() bool { return true }}
	p.work.Add(1)
	done := make(chan struct{})
	go func() { p.renewPermissions(t.Context(), make(chan preparedPermissionRenewal)); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("permission worker did not stop at its deadline")
	}
	if err := p.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("closing the prepared stream lost its permission failure", err)
	}
}
