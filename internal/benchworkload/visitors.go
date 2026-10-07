package benchworkload

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

const RequestTimeout = 5 * time.Second

type Visitor struct {
	Roots         *x509.CertPool
	Address       string
	Resolver      *net.Resolver
	Network       string
	SourceAddress *net.TCPAddr
	PayloadBytes  int
}

func (v Visitor) client() (*http.Client, *http.Transport) {
	return v.httpClient(true)
}

func (v Visitor) bandwidthClient() (*http.Client, *http.Transport) {
	return v.httpClient(false)
}

func (v Visitor) httpClient(disableKeepAlives bool) (*http.Client, *http.Transport) {
	dialer := &net.Dialer{Resolver: v.Resolver, LocalAddr: v.SourceAddress}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if v.Network != "" {
			network = v.Network
		}
		if v.Address != "" {
			address = v.Address
		}
		return dialer.DialContext(ctx, network, address)
	}
	transport := &http.Transport{DialContext: dial,
		TLSClientConfig:   &tls.Config{RootCAs: v.Roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		DisableKeepAlives: disableKeepAlives, DisableCompression: true, ForceAttemptHTTP2: false,
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport
}

func (v Visitor) Request(parent context.Context, url string, scheduled time.Time) (result RequestResult) {
	result.URL = url
	result.Started = time.Now()
	scheduled = localSchedule(result.Started, scheduled)
	result.Scheduled = scheduled
	result.QueueDelay = result.Started.Sub(scheduled)
	if result.QueueDelay < 0 {
		result.Error = "invalid timing: request started before its scheduled slot"
		return
	}
	if result.QueueDelay >= RequestTimeout {
		result.QueueExpired, result.Error = true, "request expired in queue"
		return
	}
	ctx, cancel := context.WithDeadline(parent, scheduled.Add(RequestTimeout))
	defer cancel()
	client, transport := v.client()
	defer transport.CloseIdleConnections()
	var mu sync.Mutex
	var dnsStarted, tlsStarted time.Time
	connectStarted := make(map[string]time.Time)
	var dns, connect, handshake time.Duration
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { mu.Lock(); defer mu.Unlock(); dnsStarted = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			mu.Lock()
			defer mu.Unlock()
			if !dnsStarted.IsZero() {
				dns += time.Since(dnsStarted)
			}
		},
		ConnectStart: func(network, address string) {
			mu.Lock()
			defer mu.Unlock()
			connectStarted[network+address] = time.Now()
		},
		ConnectDone: func(network, address string, _ error) {
			mu.Lock()
			defer mu.Unlock()
			if started := connectStarted[network+address]; !started.IsZero() {
				connect += time.Since(started)
			}
		},
		TLSHandshakeStart: func() { mu.Lock(); defer mu.Unlock(); tlsStarted = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			mu.Lock()
			defer mu.Unlock()
			if !tlsStarted.IsZero() {
				handshake += time.Since(tlsStarted)
			}
		},
	}
	var failure error
	defer func() {
		mu.Lock()
		result.DNS, result.Connect, result.TLS = dns, connect, handshake
		mu.Unlock()
		result.Duration = time.Since(scheduled)
		if failure != nil {
			result.Error = safeMeasurementFailure(failure)
			result.Timeout = errors.Is(failure, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded)
		}
	}()
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url+"/bench", nil)
	if err != nil {
		failure = err
		return
	}
	response, err := client.Do(request)
	if err != nil {
		failure = err
		return
	}
	defer func() { failure = errors.Join(failure, response.Body.Close()) }()
	first := make([]byte, 1)
	if _, err := io.ReadFull(response.Body, first); err != nil {
		failure = err
		return
	}
	result.FirstByte = time.Now()
	rest, err := io.ReadAll(io.LimitReader(response.Body, int64(v.PayloadBytes)))
	body := append(first, rest...)
	result.Bytes = int64(len(body))
	if err != nil {
		failure = err
		return
	}
	if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		failure = &measurementResponseError{operation: "unverified visitor response", status: response.StatusCode}
		return
	}
	if response.Header.Get("X-TNL-Bench-Host") != request.URL.Host {
		failure = errors.New("origin observed wrong host")
		return
	}
	if !bytes.Equal(body, Payload(v.PayloadBytes)) {
		failure = errors.New("response payload mismatch")
	}
	return
}

type VisitorConfig struct {
	Rate, Workers, QueueSlots int
	Start                     time.Time
	Duration                  time.Duration
	// OnResult is serialized and is intended for scenario-specific observations.
	OnResult func(RequestResult)
}

func (v Visitor) Run(ctx context.Context, config VisitorConfig, urls []string) (VisitorResult, error) {
	return runVisitors(ctx, config, urls, v.Request)
}

func runVisitors(ctx context.Context, config VisitorConfig, urls []string, request func(context.Context, string, time.Time) RequestResult) (VisitorResult, error) {
	result := VisitorResult{Workers: config.Workers, QueueSlots: config.QueueSlots, Rate: config.Rate}
	if config.Workers <= 0 || config.QueueSlots < 0 || config.Rate < 0 || config.Rate > 10_000 || config.Duration <= 0 || len(urls) == 0 {
		return result, errors.New("invalid visitor configuration")
	}
	if config.Start.IsZero() {
		config.Start = time.Now()
	}
	// coordination serializes UTC timestamps without a monotonic component.
	// rebase once; subsequent wall-clock adjustments must not move the slots.
	config.Start = localSchedule(time.Now(), config.Start)
	result.StartedAt, result.OfferDuration = config.Start, config.Duration
	end := config.Start.Add(config.Duration)
	type job struct {
		at  time.Time
		url string
	}
	jobs := make(chan job, config.QueueSlots)
	var workers sync.WaitGroup
	var ready sync.WaitGroup
	var mu sync.Mutex
	ready.Add(config.Workers)
	for range config.Workers {
		workers.Go(func() {
			ready.Done()
			for job := range jobs {
				row := request(ctx, job.url, job.at)
				mu.Lock()
				result.Observe(row)
				if config.OnResult != nil {
					config.OnResult(row)
				}
				mu.Unlock()
			}
		})
	}
	ready.Wait()
	// compute each slot from the original epoch, never from a delayed timer.
	// a slow generator cannot silently lower its offered rate or extend its window.
	for index := 0; config.Rate > 0; index++ {
		at := config.Start.Add(time.Duration(index) * time.Second / time.Duration(config.Rate))
		if !at.Before(end) {
			break
		}
		if err := WaitUntil(ctx, at); err != nil {
			break
		}
		result.Scheduled++
		select {
		case jobs <- job{at, urls[index%len(urls)]}:
		default:
			result.Missed++
		}
	}
	_ = WaitUntil(ctx, end)
	offerEnded := time.Now()
	if offerEnded.After(end) {
		offerEnded = end
	}
	result.OfferDuration = max(0, offerEnded.Sub(config.Start))
	close(jobs)
	workers.Wait()
	result.DrainDuration = max(0, time.Since(offerEnded))
	return result, ctx.Err()
}

func localSchedule(now, scheduled time.Time) time.Time {
	return now.Add(scheduled.Sub(now))
}

func WaitUntil(ctx context.Context, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	delay := time.Until(at)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type HeldStream struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	bytes  atomic.Int64
}

type heldSink struct{ stream *HeldStream }

func (s heldSink) Write(p []byte) (int, error) { s.stream.bytes.Add(int64(len(p))); return len(p), nil }

// BytesReceived distinguishes ongoing delivery from a stalled, still-open socket.
func (s *HeldStream) BytesReceived() int64 { return s.bytes.Load() }

func (v Visitor) Hold(parent context.Context, url string) (*HeldStream, error) {
	ctx, cancel := context.WithCancel(parent)
	timer := time.AfterFunc(RequestTimeout, cancel)
	defer timer.Stop()
	client, transport := v.client()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/hold", nil)
	if err != nil {
		cancel()
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		cancel()
		transport.CloseIdleConnections()
		return nil, err
	}
	one := make([]byte, 1)
	_, err = io.ReadFull(response.Body, one)
	if !timer.Stop() {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	if err == nil && (one[0] != 't' || response.StatusCode != http.StatusOK || response.Header.Get("X-TNL-Bench-Host") != request.URL.Host || response.TLS == nil || len(response.TLS.VerifiedChains) == 0) {
		err = fmt.Errorf("invalid held-stream opening: status=%d first_byte=%q host_match=%t verified_tls=%t",
			response.StatusCode, one[0], response.Header.Get("X-TNL-Bench-Host") == request.URL.Host,
			response.TLS != nil && len(response.TLS.VerifiedChains) > 0)
	}
	if err != nil {
		cancel()
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		return nil, err
	}
	stream := &HeldStream{cancel: cancel, done: make(chan struct{})}
	go func() {
		_, stream.err = io.Copy(heldSink{stream}, response.Body)
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		close(stream.done)
	}()
	return stream, nil
}

func (s *HeldStream) Alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}
func (s *HeldStream) Close() error {
	s.cancel()
	timer := time.NewTimer(RequestTimeout)
	defer timer.Stop()
	select {
	case <-s.done:
		return nil
	case <-timer.C:
		return errors.New("held stream did not stop")
	}
}
