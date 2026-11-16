package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
)

// use the admission and byte owners without listeners, routing or control i/o.
func pendingHTTPCopyFixture(t *testing.T) (*Server, *visitorAdmission) {
	t.Helper()
	traffic := trafficFixture(t)
	server := &Server{traffic: traffic, config: Config{
		MaxConnections: 8, Traffic: traffic.config, Pending: traffic.pending,
	}}
	admission := serviceTrafficVisitor(t, server, trafficKey{service: "service", id: "run", run: 1}, traffic.config.Default)
	return server, admission
}

type pendingHTTPRecorder struct {
	net.Conn
	read       func([]byte) (int, error)
	write      func([]byte) (int, error)
	data       []byte
	writes     []int
	halfCloses int
	closes     int
	closeErr   error
}

func (c *pendingHTTPRecorder) Read(p []byte) (int, error) {
	if c.read == nil {
		return 0, io.EOF
	}
	return c.read(p)
}

func (c *pendingHTTPRecorder) Write(p []byte) (int, error) {
	c.writes = append(c.writes, len(p))
	n, err := len(p), error(nil)
	if c.write != nil {
		n, err = c.write(p)
	}
	c.data = append(c.data, p[:n]...)
	return n, err
}

func (c *pendingHTTPRecorder) Close() error {
	c.closes++
	return c.closeErr
}

func (c *pendingHTTPRecorder) CloseWrite() error {
	c.halfCloses++
	return nil
}

func pendingHTTPBudget(ctx context.Context, admission *visitorAdmission, connection net.Conn, upload bool) *budgetConn {
	return &budgetConn{Conn: connection, reserveWrite: func(size int) (int, error) {
		return admission.reserveHTTPCopy(ctx, upload, size)
	}}
}

func pendingHTTPAllowance(admission *visitorAdmission, upload bool) int64 {
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if upload {
		return admission.upload
	}
	return admission.download
}

func TestPendingHTTPCopyFragmentsBothDirectionsUntilAcknowledged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server, admission := pendingHTTPCopyFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		prefixes := [2]int{7, 11}
		payloads := [2][]byte{
			bytes.Repeat([]byte("upload!"), 360448/7+1)[:360448],
			bytes.Repeat([]byte("download!"), 20000),
		}
		var records [2]*pendingHTTPRecorder
		var written [2]int
		var workers [2]<-chan error
		for index, upload := range []bool{true, false} {
			remaining := pendingHTTPAllowance(admission, upload)
			if err := admission.beforeWrite(ctx, upload, int(remaining)-prefixes[index]); err != nil {
				t.Fatal(err)
			}
			records[index] = new(pendingHTTPRecorder)
			connection := pendingHTTPBudget(ctx, admission, records[index], upload)
			workers[index] = ingressWorker(t, cancel, func() error {
				var err error
				written[index], err = connection.Write(payloads[index])
				return err
			})
		}
		synctest.Wait()
		for index, upload := range []bool{true, false} {
			if !bytes.Equal(records[index].data, payloads[index][:prefixes[index]]) ||
				pendingHTTPAllowance(admission, upload) != 0 {
				t.Fatal("copy crossed the directional pending ceiling", upload, len(records[index].data))
			}
			select {
			case err := <-workers[index]:
				t.Fatal("copy did not wait for acknowledgment", upload, err)
			default:
			}
		}
		if pending, active := publicServiceAdmissionCounts(server); pending != 1 || active != 0 {
			t.Fatal("blocked copies changed pending capacity", pending, active)
		}
		admission.meterOrdinaryBytes()
		select {
		case <-admission.copyReady:
			t.Fatal("metering without reserved capacity signaled permission")
		default:
		}
		if reason := admission.reserveForVisitor(); reason != "" {
			t.Fatal(reason)
		}
		if reason := admission.reserveForVisitor(); reason != "" {
			t.Fatal("cached reservation changed", reason)
		}
		synctest.Wait()
		select {
		case <-admission.copyReady:
			t.Fatal("reservation signaled an acknowledgment")
		default:
		}
		server.traffic.mu.Lock()
		run := server.traffic.runs[admission.key]
		connections, uploadTotal, downloadTotal := run.connections, run.upload, run.download
		server.traffic.mu.Unlock()
		if connections != 1 || uploadTotal != 0 || downloadTotal != 0 ||
			len(records[0].data) != prefixes[0] || len(records[1].data) != prefixes[1] {
			t.Fatal("unacknowledged reservation released or metered pending bytes")
		}
		admission.meterOrdinaryBytes()
		admission.meterOrdinaryBytes()
		for index := range records {
			if err := ingressAwait(t, workers[index]); err != nil {
				t.Fatal(err)
			}
			if written[index] != len(payloads[index]) || !bytes.Equal(records[index].data, payloads[index]) {
				t.Fatal("promotion lost or duplicated the buffered suffix", index, written[index])
			}
			if records[index].writes[0] != prefixes[index] {
				t.Fatal("first copy write did not fragment at the exact remainder")
			}
			for _, size := range records[index].writes {
				if size <= 0 || size > 32<<10 {
					t.Fatal("copy reservation escaped its bounded write", size)
				}
			}
		}
		server.traffic.mu.Lock()
		connections, uploadTotal, downloadTotal = run.connections, run.upload, run.download
		server.traffic.mu.Unlock()
		if connections != 1 || uploadTotal != int64(len(payloads[0])-prefixes[0]) ||
			downloadTotal != int64(len(payloads[1])-prefixes[1]) {
			t.Fatal("promotion changed the single debit or charged a suffix twice", connections, uploadTotal, downloadTotal)
		}
		admission.close()
		if !publicServiceCapacityReleased(server) {
			t.Fatal("joined copies retained capacity")
		}
	})
}

func TestPendingHTTPCopyKeepsOriginalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server, admission := pendingHTTPCopyFixture(t)
		deadline := admission.deadline
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		record := new(pendingHTTPRecorder)
		connection := pendingHTTPBudget(ctx, admission, record, true)
		var written int
		worker := ingressWorker(t, cancel, func() error {
			var err error
			written, err = connection.Write(make([]byte, int(server.config.Pending.UploadBytes)+1))
			return err
		})
		synctest.Wait()
		if len(record.data) != int(server.config.Pending.UploadBytes) {
			t.Fatal("copy did not stop at the pending ceiling")
		}
		// advance fake time, not a readiness delay; reservation must not renew it.
		time.Sleep(server.config.Pending.Timeout / 2)
		if reason := admission.reserveForVisitor(); reason != "" {
			t.Fatal(reason)
		}
		synctest.Wait()
		select {
		case err := <-worker:
			t.Fatal("reservation released pending copying", err)
		default:
		}
		time.Sleep(time.Until(deadline))
		if err := ingressAwait(t, worker); err != trafficError("pending_byte_or_time_budget") {
			t.Fatal("copy did not retain pending expiry", err)
		}
		if !time.Now().Equal(deadline) || !admission.deadline.Equal(deadline) ||
			written != int(server.config.Pending.UploadBytes) ||
			pendingHTTPAllowance(admission, false) != server.config.Pending.DownloadBytes {
			t.Fatal("fragmentation changed the original deadline, count or opposite allowance")
		}
		if pending, active := publicServiceAdmissionCounts(server); pending != 0 || active != 1 {
			t.Fatal("expiry released admission before its owner joined", pending, active)
		}
	})
}

func TestPendingHTTPCopyStopsOnCancellationOrAdmissionClose(t *testing.T) {
	for _, closeAdmission := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "close"}[closeAdmission], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server, admission := pendingHTTPCopyFixture(t)
				cause := errors.New("copy canceled")
				ctx, cancel := context.WithCancelCause(context.Background())
				defer cancel(cause)
				if err := admission.beforeWrite(ctx, true, int(server.config.Pending.UploadBytes)); err != nil {
					t.Fatal(err)
				}
				record := new(pendingHTTPRecorder)
				connection := pendingHTTPBudget(ctx, admission, record, true)
				worker := ingressWorker(t, func() { cancel(cause) }, func() error {
					_, err := connection.Write([]byte{1})
					return err
				})
				synctest.Wait()
				select {
				case err := <-worker:
					t.Fatal("exhausted copy did not block", err)
				default:
				}
				expected := cause
				if closeAdmission {
					admission.close()
					expected = net.ErrClosed
				} else {
					cancel(cause)
				}
				if err := ingressAwait(t, worker); !errors.Is(err, expected) || len(record.writes) != 0 {
					t.Fatal("closed copy forwarded bytes or lost its cause", err, record.writes)
				}
				if !closeAdmission {
					if pending, active := publicServiceAdmissionCounts(server); pending != 1 || active != 0 {
						t.Fatal("cancellation prematurely released admission", pending, active)
					}
				}
				admission.close()
				if !publicServiceCapacityReleased(server) {
					t.Fatal("closed admission retained capacity")
				}
			})
		})
	}
}

func TestPendingHTTPCopyFullCloseCancelsBeforeCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server, admission := pendingHTTPCopyFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := admission.beforeWrite(ctx, true, int(server.config.Pending.UploadBytes)); err != nil {
			t.Fatal(err)
		}
		release := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		cause := errors.New("physical close failed")
		physical := &blockedPhysicalClose{Conn: new(pendingHTTPRecorder), started: make(chan struct{}), release: release, err: cause}
		connection := httpCopyConn(physical, cancel)
		budget := pendingHTTPBudget(ctx, admission, connection, true)
		writer := ingressWorker(t, cancel, func() error {
			_, err := budget.Write([]byte{1})
			return err
		})
		synctest.Wait()
		closer := ingressWorker(t, unblock, budget.Close)
		ingressAwait(t, physical.started)
		if err := ingressAwait(t, writer); !errors.Is(err, context.Canceled) {
			t.Fatal("full close did not wake the pending reservation", err)
		}
		select {
		case err := <-closer:
			t.Fatal("physical cleanup was not joined", err)
		default:
		}
		if pending, active := publicServiceAdmissionCounts(server); pending != 1 || active != 0 {
			t.Fatal("full close released quota before cleanup joined", pending, active)
		}
		unblock()
		if err := ingressAwait(t, closer); !errors.Is(err, cause) {
			t.Fatal("physical cleanup lost its independent cause", err)
		}
		if err := budget.Close(); !errors.Is(err, cause) || physical.calls.Load() != 1 {
			t.Fatal("full close lost once-only cleanup or its retained failure", err, physical.calls.Load())
		}
		admission.close()
		if !publicServiceCapacityReleased(server) {
			t.Fatal("joined close retained pending quota")
		}
	})
}

func TestPendingHTTPCopyHalfCloseDoesNotCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server, admission := pendingHTTPCopyFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := admission.beforeWrite(ctx, true, int(server.config.Pending.UploadBytes)); err != nil {
			t.Fatal(err)
		}
		record := new(pendingHTTPRecorder)
		budget := pendingHTTPBudget(ctx, admission, httpCopyConn(record, cancel), true)
		worker := ingressWorker(t, cancel, func() error {
			_, err := budget.Write([]byte{1})
			return err
		})
		synctest.Wait()
		if err := budget.CloseWrite(); err != nil || ctx.Err() != nil || record.halfCloses != 1 {
			t.Fatal("half-close canceled the other copy direction", err, ctx.Err(), record.halfCloses)
		}
		synctest.Wait()
		select {
		case err := <-worker:
			t.Fatal("half-close released or canceled pending bytes", err)
		default:
		}
		if reason := admission.reserveForVisitor(); reason != "" {
			t.Fatal(reason)
		}
		admission.meterOrdinaryBytes()
		if err := ingressAwait(t, worker); err != nil || !bytes.Equal(record.data, []byte{1}) || ctx.Err() != nil {
			t.Fatal("half-close prevented acknowledged continuation", err, record.data, ctx.Err())
		}
	})
}

func TestPendingHTTPCopyFailedPromotionJoinsBlockedCopy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server, admission := pendingHTTPCopyFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := admission.beforeWrite(ctx, true, int(server.config.Pending.UploadBytes)); err != nil {
			t.Fatal(err)
		}
		failed := make(chan struct{})
		fail := sync.OnceFunc(func() { close(failed) })
		denied, leftClose, rightClose := errors.New("capacity denied"), errors.New("visitor close failed"), errors.New("backend close failed")
		left := &pendingHTTPRecorder{read: bytes.NewReader([]byte{1}).Read, closeErr: leftClose}
		capacityErr := denied
		right := &pendingHTTPRecorder{closeErr: rightClose, read: func([]byte) (int, error) {
			return 0, waitCopyCapacity(ctx, admission.deadline, failed, &capacityErr)
		}}
		public := pendingHTTPBudget(ctx, admission, httpCopyConn(left, cancel), false)
		upstream := pendingHTTPBudget(ctx, admission, httpCopyConn(right, cancel), true)
		var copied streamcopy.Result
		worker := ingressWorker(t, func() { fail(); cancel() }, func() error {
			var err error
			copied, err = streamcopy.Copy(public, upstream)
			return err
		})
		synctest.Wait()
		if reason := admission.reserveForVisitor(); reason != "" {
			t.Fatal(reason)
		}
		synctest.Wait()
		select {
		case <-admission.copyReady:
			t.Fatal("unacknowledged capacity released the blocked copy")
		default:
		}
		// deliver a failed capacity response from the backend without metering.
		fail()
		err := ingressAwait(t, worker)
		if !errors.Is(err, ErrServiceAdmission) || !errors.Is(err, denied) || !errors.Is(err, leftClose) || !errors.Is(err, rightClose) ||
			!errors.Is(err, context.Canceled) {
			t.Fatal("failed promotion lost a copy or cleanup cause", err)
		}
		if copied != (streamcopy.Result{}) || len(left.data) != 0 || len(right.data) != 0 ||
			left.closes != 1 || right.closes != 1 {
			t.Fatal("failed promotion forwarded bytes or repeated cleanup", copied, left.closes, right.closes)
		}
		select {
		case <-admission.copyReady:
			t.Fatal("failed capacity completion signaled ordinary metering")
		default:
		}
		if pending, active := publicServiceAdmissionCounts(server); pending != 0 || active != 1 {
			t.Fatal("copy cleanup prematurely released reserved capacity", pending, active)
		}
		admission.close()
		if !publicServiceCapacityReleased(server) {
			t.Fatal("failed promotion retained capacity after join")
		}
	})
}

func TestPendingHTTPCopyPartialWriteKeepsConservativeCharge(t *testing.T) {
	for _, ordinary := range []bool{false, true} {
		for _, upload := range []bool{false, true} {
			for _, short := range []bool{false, true} {
				name := map[bool]string{false: "pending", true: "ordinary"}[ordinary] + "/" +
					map[bool]string{false: "download", true: "upload"}[upload] + "/" +
					map[bool]string{false: "error", true: "short"}[short]
				t.Run(name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						server, admission := pendingHTTPCopyFixture(t)
						ctx, cancel := context.WithCancel(context.Background())
						defer cancel()
						if ordinary {
							if reason := admission.reserveForVisitor(); reason != "" {
								t.Fatal(reason)
							}
							admission.meterOrdinaryBytes()
						}
						payload := []byte("123456789")
						cause := errors.New("partial target write")
						source := &pendingHTTPRecorder{read: bytes.NewReader(payload).Read}
						target := &pendingHTTPRecorder{write: func([]byte) (int, error) {
							if short {
								return 3, nil
							}
							return 3, cause
						}}
						public, upstream := source, target
						if !upload {
							public, upstream = target, source
						}
						left := pendingHTTPBudget(ctx, admission, httpCopyConn(public, cancel), false)
						right := pendingHTTPBudget(ctx, admission, httpCopyConn(upstream, cancel), true)
						var copied streamcopy.Result
						var observed [2]int64
						worker := ingressWorker(t, cancel, func() error {
							var err error
							copied, err = streamcopy.CopyObserved(left, right,
								func(n int64) { observed[0] += n }, func(n int64) { observed[1] += n })
							return err
						})
						err := ingressAwait(t, worker)
						if (short && (err == nil || err.Error() != "ingress: short traffic write")) ||
							(!short && !errors.Is(err, cause)) {
							t.Fatal("partial write lost its original failure", err)
						}
						expected, expectedObserved := streamcopy.Result{RightToLeft: 3}, [2]int64{0, 3}
						if upload {
							expected, expectedObserved = streamcopy.Result{LeftToRight: 3}, [2]int64{3, 0}
						}
						if copied != expected || observed != expectedObserved || !bytes.Equal(target.data, payload[:3]) ||
							!slices.Equal(target.writes, []int{len(payload)}) {
							t.Fatal("partial write retried an uncertain suffix or reported reserved bytes", copied, observed, target.writes)
						}
						cap := server.config.Pending.DownloadBytes
						if upload {
							cap = server.config.Pending.UploadBytes
						}
						remaining := cap - int64(len(payload))
						if ordinary {
							remaining = cap
						}
						if pendingHTTPAllowance(admission, upload) != remaining {
							t.Fatal("partial write refunded a conservative pending reservation")
						}
						server.traffic.mu.Lock()
						process, rate := server.traffic.downloads, server.traffic.config.ProcessDownload
						if upload {
							process, rate = server.traffic.uploads, server.traffic.config.ProcessUpload
						}
						var total int64
						if run := server.traffic.runs[admission.key]; run != nil {
							total = run.download
							if upload {
								total = run.upload
							}
						}
						server.traffic.mu.Unlock()
						expectedTotal := int64(0)
						if ordinary {
							expectedTotal = int64(len(payload))
						}
						if process.tokens != float64(rate)-float64(len(payload)) || total != expectedTotal {
							t.Fatal("partial write refunded process/run accounting", process.tokens, total)
						}
					})
				})
			}
		}
	}
}

func TestBudgetConnRejectsInvalidCopyReservations(t *testing.T) {
	for _, allowed := range []int{-1, 0, 10, (32 << 10) + 1} {
		record := new(pendingHTTPRecorder)
		connection := &budgetConn{Conn: record, reserveWrite: func(requested int) (int, error) {
			if requested != 9 {
				t.Fatal("copy engine changed the bounded request", requested)
			}
			return allowed, nil
		}}
		if n, err := connection.Write(make([]byte, 9)); n != 0 || err == nil || len(record.writes) != 0 {
			t.Fatal("invalid allowance reached the socket", allowed, n, err)
		}
	}
	cause := errors.New("reservation failed")
	record := new(pendingHTTPRecorder)
	connection := &budgetConn{Conn: record, reserveWrite: func(requested int) (int, error) {
		return requested, cause
	}}
	if n, err := connection.Write([]byte{1}); n != 0 || !errors.Is(err, cause) || len(record.writes) != 0 {
		t.Fatal("failed allowance reached the socket", n, err)
	}
}

func TestPendingHTTPCopyNativeAdapterRemainsStrict(t *testing.T) {
	for _, upload := range []bool{false, true} {
		t.Run(map[bool]string{false: "download", true: "upload"}[upload], func(t *testing.T) {
			_, admission := pendingHTTPCopyFixture(t)
			remaining := pendingHTTPAllowance(admission, upload)
			if err := admission.beforeWrite(t.Context(), upload, int(remaining)-7); err != nil {
				t.Fatal(err)
			}
			record := new(pendingHTTPRecorder)
			connection := &budgetConn{Conn: record, reserveWrite: func(size int) (int, error) {
				return size, admission.beforeWrite(t.Context(), upload, size)
			}}
			if n, err := connection.Write(make([]byte, 8)); n != 0 || err != trafficError("pending_byte_or_time_budget") ||
				len(record.writes) != 0 || pendingHTTPAllowance(admission, upload) != 7 {
				t.Fatal("native adapter fragmented or waited instead of enforcing strict overflow", n, err, record.writes)
			}
		})
	}
}

func TestPendingHTTPCopyBandwidthWaitUsesCapacityGuard(t *testing.T) {
	for _, promoted := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending_expiry", true: "ordinary_continuation"}[promoted], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server, admission := pendingHTTPCopyFixture(t)
				admission.deadline = time.Now().Add(100 * time.Millisecond)
				deadline := admission.deadline
				server.traffic.config.ProcessUpload = 64 << 10
				server.traffic.uploads = tokenBucket{last: time.Now()}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				record := new(pendingHTTPRecorder)
				connection := httpCopyConn(record, cancel)
				budget := pendingHTTPBudget(ctx, admission, connection, true)
				capacityDone := make(chan struct{})
				var capacityErr error
				guard := ingressWorker(t, cancel, func() error {
					err := waitCopyCapacity(ctx, deadline, capacityDone, &capacityErr)
					if err != nil {
						return errors.Join(err, connection.Close())
					}
					return nil
				})
				payload := make([]byte, (32<<10)+1)
				var written int
				writer := ingressWorker(t, cancel, func() error {
					var err error
					written, err = budget.Write(payload)
					return err
				})
				synctest.Wait()
				if len(record.writes) != 0 || pendingHTTPAllowance(admission, true) != server.config.Pending.UploadBytes-(32<<10) {
					t.Fatal("bandwidth wait wrote before process accounting")
				}
				if reason := admission.reserveForVisitor(); reason != "" {
					t.Fatal(reason)
				}
				if promoted {
					admission.meterOrdinaryBytes()
					close(capacityDone)
					if err := ingressAwait(t, guard); err != nil {
						t.Fatal("successful capacity decision failed", err)
					}
					// the first reservation stays conservatively pending across
					// promotion; only the following suffix is ordinary.
					time.Sleep(600 * time.Millisecond)
					if err := ingressAwait(t, writer); err != nil || written != len(payload) ||
						!bytes.Equal(record.data, payload) || ctx.Err() != nil || !time.Now().After(deadline) {
						t.Fatal("obsolete setup deadline killed promoted bandwidth waiting", written, err, ctx.Err())
					}
					server.traffic.mu.Lock()
					run := server.traffic.runs[admission.key]
					connections, total := run.connections, run.upload
					server.traffic.mu.Unlock()
					if connections != 1 || total != 1 || !admission.deadline.Equal(deadline) {
						t.Fatal("promotion recharged the pending reservation or renewed the deadline", connections, total)
					}
				} else {
					time.Sleep(time.Until(deadline))
					if err := ingressAwait(t, guard); !errors.Is(err, ErrServiceAdmission) {
						t.Fatal("pending bandwidth wait escaped the setup guard", err)
					}
					if err := ingressAwait(t, writer); !errors.Is(err, context.Canceled) ||
						written != 0 || len(record.writes) != 0 || !time.Now().Equal(deadline) {
						t.Fatal("expired bandwidth wait forwarded reserved bytes", written, err, record.writes)
					}
				}
				if pending, active := publicServiceAdmissionCounts(server); pending != 0 || active != 1 {
					t.Fatal("bandwidth guard released admission before join", pending, active)
				}
				admission.close()
				if !publicServiceCapacityReleased(server) {
					t.Fatal("bandwidth copy retained capacity after join")
				}
			})
		})
	}
}

func TestPendingHTTPCopyCompletedCapacityOutlivesSetupTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		deadline := time.Now().Add(time.Second)
		var capacityErr error
		close(done)
		time.Sleep(time.Until(deadline))
		if err := waitCopyCapacity(context.Background(), deadline, done, &capacityErr); err != nil {
			t.Fatal("completed capacity decision lost to an obsolete timer", err)
		}
	})
}
