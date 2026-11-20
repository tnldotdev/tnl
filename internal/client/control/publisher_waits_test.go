package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherWaitsShareOneRequestAndJoinCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type call struct {
			runs []controlv1.PublisherWatchRun
			send chan string
			done chan struct{}
		}
		requests := make(chan call, 4)
		client, err := New("https://control.example", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			defer r.Body.Close()
			var body controlv1.PublisherWatchRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			c := call{body.Runs, make(chan string), make(chan struct{})}
			requests <- c
			defer close(c.done)
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case reply := <-c.send:
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(reply))}, nil
			}
		})}, "")
		if err != nil {
			t.Fatal(err)
		}
		a := controlv1.PublisherWatchRun{ServiceRunId: "srun_1234567890123456789012", RunToken: "a"}
		b := controlv1.PublisherWatchRun{ServiceRunId: "srun_2234567890123456789012", RunToken: "b"}
		wait := func(ctx context.Context, scope controlv1.PublisherWatchRun) <-chan publisherNotice {
			done := make(chan publisherNotice, 1)
			go func() {
				rev, err := client.WaitPublisherRun(ctx, scope)
				done <- publisherNotice{rev, err}
			}()
			return done
		}
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		readyA := wait(ctx, a)
		first := <-requests
		readyB := wait(ctx, b)
		second := <-requests
		<-first.done
		if len(second.runs) != 2 || !(second.runs[0] == a && second.runs[1] == b || second.runs[0] == b && second.runs[1] == a) {
			t.Fatal("two scopes did not share the same HTTP wait with their own credentials")
		}
		second.send <- `{"changes":[{"service_run_id":"` + b.ServiceRunId + `","connector_revision":"3"}]}`
		if got := <-readyB; got.err != nil || got.revision != 3 {
			t.Fatal("notice did not reach its owner", got)
		}
		third := <-requests
		if len(third.runs) != 1 || third.runs[0] != a {
			t.Fatal("unchanged run lost its wait")
		}
		stop()
		if result := <-readyA; !errors.Is(result.err, context.Canceled) {
			t.Fatal(result.err)
		}
		select {
		case <-third.done:
		default:
			t.Fatal("wait returned before canceled HTTP call joined")
		}
		synctest.Wait()
		client.publisherWaits.mu.Lock()
		defer client.publisherWaits.mu.Unlock()
		if len(client.publisherWaits.groups) != 0 {
			t.Fatal("last wait retained its group")
		}
	})
}
