package tnldruntime

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	tnldconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestIngressConstructorConcurrentMetricCollection(t *testing.T) {
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := observability.New("ingress")
			defer m.Shutdown(context.Background())
			d := &daemon{ctx: ctx, cancel: cancel, componentDone: make(chan error, 1)}
			defer d.shutdown(time.Second)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			stop, done, collecting := make(chan struct{}), make(chan struct{}), make(chan struct{})
			collectorStarted := false
			defer func() {
				if collectorStarted {
					close(stop)
					<-done
				}
			}()
			settings := ingressSettingsFrom(tnldconfig.Config{VisitorConnectionLimit: 16, LeaseRenewalInterval: time.Minute, ControlRetryInterval: time.Millisecond, RoutingTableWait: time.Second})
			err = d.startIngressRuntime(ctx, settings, m, ingressRuntimeConfig{client: &wiringControl{}, ingressID: "ingress", listener: listener, clusterSecret: "0123456789abcdef0123456789abcdef", configure: func(*ingress.Config) {
				// collection begins after the actual constructor registers its
				// callbacks, before it publishes and starts the ingress runtime.
				collectorStarted = true
				go func() {
					defer close(done)
					close(collecting)
					for {
						select {
						case <-stop:
							return
						default:
							if _, err := m.Gather(); err != nil {
								t.Error(err)
								return
							}
						}
					}
				}()
				<-collecting
				time.Sleep(10 * time.Millisecond)
			}})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
