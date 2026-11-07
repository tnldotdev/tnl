package stream

import (
	"errors"
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
