package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestServiceRunPendingPhysicalCloseKeepsOwnerResponsiveThroughOriginalDeadline(t *testing.T) {
	states := make(chan RunStatus, 1)
	var reported sync.Once
	cleanup := errors.New("independent held pending physical close failure")
	runCleanup := errors.New("independent final run cleanup failure")
	f := newActiveHTTPFailureFixture(t, activeHTTPFailureOptions{
		expire: true, runCleanup: runCleanup,
		observe: func(status RunStatus) {
			if status.Draining {
				reported.Do(func() { states <- status })
			}
		},
	})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	wire := &httpAdmissionTestConn{release: release, closeErr: cleanup}
	a, client := openHTTPAdmissionTest(t, f.bound, 0, wire)
	defer client.Close()
	// use the actual setup reader and admission retirement operations. raw Close
	// interrupts that reader immediately, while the once-owned physical return
	// and pending permit remain held below it.
	setupJoined := make(chan error, 1)
	header := privateHeader(t, a.ref)
	header.PublicService.DestinationPort = 443
	go func() {
		err := f.bound.serveBody(a.ctx, a.ref, wire, header, nil, nil, a.visitor)
		setupJoined <- errors.Join(err, a.retire())
	}()
	f.cancel()
	status := activeHTTPFailureAwait(t, f.ctx, states)
	if status.Ready || !status.Draining {
		t.Fatal("run did not report unavailable/draining before pending physical cleanup", status)
	}
	activeHTTPFailureAwait(t, f.ctx, wire.entered)
	f.bound.mu.Lock()
	original := f.bound.drainUntil
	f.bound.mu.Unlock()
	if !f.notAfter.Before(original) {
		t.Fatal("fixture certificate does not expire inside the original drain bound", f.notAfter, original)
	}
	assertHTTPAdmissionCharges(t, a, 1, 0, 0)
	// certificate expiry must be consumed by Publish while physical cleanup is
	// held. the synchronous closed fence is observable before the drain deadline;
	// no Close return is used as evidence that authority ended.
	awaitPublisherBinding(t, f.ctx, func() bool {
		f.bound.mu.Lock()
		defer f.bound.mu.Unlock()
		return f.bound.closed
	})
	if !time.Now().Before(original) {
		t.Fatal("certificate failure was not observed until the original drain deadline")
	}
	timer := time.NewTimer(time.Until(original))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
		t.Fatal("run owner did not reach its original deadline", f.ctx.Err())
	}
	assertHTTPAdmissionCharges(t, a, 1, 0, 0)
	select {
	case err := <-f.published:
		t.Fatal("Publish returned before the held physical close joined", err)
	default:
	}
	f.bound.mu.Lock()
	unchanged := f.bound.drainUntil == original
	f.bound.mu.Unlock()
	if !unchanged {
		t.Fatal("failure or deadline restarted the run's drain budget")
	}
	unblock()
	if err := activeHTTPFailureAwait(t, f.ctx, setupJoined); !errors.Is(err, cleanup) {
		t.Fatal("actual setup owner lost the independent physical failure", err)
	}
	err := activeHTTPFailureAwait(t, f.ctx, f.published)
	for _, cause := range []error{errCertificateExpired, cleanup, runCleanup} {
		if !errors.Is(err, cause) {
			t.Error("run cleanup lost a joined independent cause", cause, err)
		}
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Error("held cleanup lost the original run deadline", err)
	}
	assertHTTPAdmissionCharges(t, a, 0, 0, 0)
	activeHTTPFailureAwait(t, f.ctx, f.publishJoined)
	for _, slot := range f.slots {
		activeHTTPFailureAwait(t, f.ctx, slot.closed)
	}
}
