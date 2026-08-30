package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type driverBarrier struct {
	drivers int
	token   string
	mu      sync.Mutex
	phases  map[string]*driverBarrierPhase
}

type driverBarrierPhase struct {
	arrived map[int]struct{}
	release chan struct{}
}

func newDriverBarrier(drivers int, token string) *driverBarrier {
	return &driverBarrier{drivers: drivers, token: token, phases: make(map[string]*driverBarrierPhase)}
}

func (b *driverBarrier) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	wantAuthorization := "Bearer " + b.token
	if subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), []byte(wantAuthorization)) != 1 {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}
	phaseName := request.URL.Query().Get("phase")
	if phaseName != "activated" && phaseName != "ready" && phaseName != "loaded" {
		http.Error(response, "invalid phase", http.StatusBadRequest)
		return
	}
	driver, err := strconv.Atoi(request.URL.Query().Get("driver"))
	if err != nil || driver < 0 || driver >= b.drivers {
		http.Error(response, "invalid driver", http.StatusBadRequest)
		return
	}

	// Each driver counts once; closing release broadcasts to every waiter.
	b.mu.Lock()
	phase := b.phases[phaseName]
	if phase == nil {
		phase = &driverBarrierPhase{arrived: make(map[int]struct{}), release: make(chan struct{})}
		b.phases[phaseName] = phase
	}
	phase.arrived[driver] = struct{}{}
	if len(phase.arrived) == b.drivers {
		select {
		case <-phase.release:
		default:
			close(phase.release)
		}
	}
	release := phase.release
	b.mu.Unlock()

	select {
	case <-release:
		response.WriteHeader(http.StatusNoContent)
	case <-request.Context().Done():
	}
}

func startDriverBarrier(flags cli) (func(), error) {
	if flags.DriverCount == 1 || flags.BarrierListen == "" {
		return func() {}, nil
	}
	listener, err := net.Listen("tcp", flags.BarrierListen)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler:           newDriverBarrier(flags.DriverCount, flags.BarrierToken),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = server.Serve(listener)
	}()
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}, nil
}

func waitDriverBarrier(ctx context.Context, flags cli, phase string) error {
	if flags.DriverCount == 1 {
		return nil
	}
	endpoint, err := url.Parse(flags.BarrierURL)
	if err != nil {
		return err
	}
	query := endpoint.Query()
	query.Set("phase", phase)
	query.Set("driver", strconv.Itoa(flags.DriverIndex))
	endpoint.RawQuery = query.Encode()
	client := &http.Client{}
	// Drivers may beat the coordinator, so retry transport and server failures.
	for {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
		if requestErr != nil {
			return requestErr
		}
		request.Header.Set("Authorization", "Bearer "+flags.BarrierToken)
		response, requestErr := client.Do(request)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				return nil
			}
			if response.StatusCode >= 400 && response.StatusCode < 500 {
				return fmt.Errorf("driver barrier %s: HTTP %d", phase, response.StatusCode)
			}
		}
		select {
		case <-ctx.Done():
			return errors.Join(fmt.Errorf("driver barrier %s", phase), ctx.Err())
		case <-time.After(time.Second):
		}
	}
}
