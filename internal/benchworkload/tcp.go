package benchworkload

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TCPVisitor measures verified request/response bytes through an opaque connector.
// fresh requests include remote admission/TLS; Connect measures only the local dial.
type TCPVisitor struct {
	PayloadBytes int
	sequence     atomic.Uint64
	connections  map[string]chan net.Conn
	owned        []net.Conn
}

// Prepare opens and verifies reusable sockets before the paced measurement window.
// each address owns workers sockets so scheduling never hides a pool wait in setup.
func (v *TCPVisitor) Prepare(ctx context.Context, addresses []string, workers int) (Histogram, error) {
	var setup Histogram
	if workers < 1 || v.connections != nil || v.PayloadBytes < 8 || v.PayloadBytes > 1<<20 {
		return setup, errors.New("invalid TCP visitor preparation")
	}
	v.connections = make(map[string]chan net.Conn)
	for _, address := range addresses {
		if v.connections[address] != nil {
			continue
		}
		pool := make(chan net.Conn, workers)
		v.connections[address] = pool
		for range workers {
			started := time.Now()
			bounded, cancel := context.WithTimeout(ctx, RequestTimeout)
			conn, err := (&net.Dialer{}).DialContext(bounded, "tcp", address)
			if err == nil {
				v.owned = append(v.owned, conn)
				_, _, err = v.exchange(bounded, conn)
			}
			cancel()
			if err != nil {
				_ = v.Close()
				return setup, err
			}
			setup.Observe(time.Since(started))
			pool <- conn
		}
	}
	return setup, nil
}

// Close is called after Run joins all workers. failed reused sockets are never
// replaced: silently redialing would turn the reused phase into a fresh phase.
func (v *TCPVisitor) Close() error {
	var result error
	for _, connection := range v.owned {
		result = errors.Join(result, connection.Close())
	}
	v.owned = nil
	return result
}

func (v *TCPVisitor) Run(ctx context.Context, config VisitorConfig, addresses []string) (VisitorResult, error) {
	if v.PayloadBytes < 8 || v.PayloadBytes > 1<<20 {
		return VisitorResult{}, errors.New("TCP payload must be between 8 bytes and 1 MiB")
	}
	return runVisitors(ctx, config, addresses, v.request)
}

func (v *TCPVisitor) request(parent context.Context, address string, scheduled time.Time) (result RequestResult) {
	result.URL, result.Started = address, time.Now()
	scheduled = localSchedule(result.Started, scheduled)
	result.Scheduled, result.QueueDelay = scheduled, result.Started.Sub(scheduled)
	if result.QueueDelay >= RequestTimeout {
		result.QueueExpired, result.Error = true, "request expired in queue"
		return
	}
	ctx, cancel := context.WithDeadline(parent, scheduled.Add(RequestTimeout))
	defer cancel()
	var err error
	defer func() {
		result.Duration = time.Since(scheduled)
		if err != nil {
			result.Error = safeMeasurementFailure(err)
			var networkError net.Error
			result.Timeout = errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout()
		}
	}()
	var connection net.Conn
	if v.connections != nil {
		pool := v.connections[address]
		select {
		case connection = <-pool:
			defer func() { pool <- connection }()
		case <-ctx.Done():
			err = ctx.Err()
			return
		}
	} else {
		started := time.Now()
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
		result.Connect = time.Since(started)
		if err != nil {
			return
		}
		defer connection.Close()
	}
	result.FirstByte, result.Bytes, err = v.exchange(ctx, connection)
	return
}

func (v *TCPVisitor) exchange(ctx context.Context, connection net.Conn) (first time.Time, received int64, err error) {
	deadline, _ := ctx.Deadline()
	if err = connection.SetDeadline(deadline); err != nil {
		return
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		if err == nil {
			err = connection.SetDeadline(time.Time{})
		}
	}()
	payload := Payload(v.PayloadBytes)
	binary.BigEndian.PutUint64(payload, v.sequence.Add(1))
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	if _, err = io.Copy(connection, bytes.NewReader(frame)); err != nil {
		return
	}
	response := make([]byte, len(frame))
	if _, err = io.ReadFull(connection, response[:1]); err != nil {
		return
	}
	first = time.Now()
	n, readErr := io.ReadFull(connection, response[1:])
	received, err = int64(n+1), readErr
	if err == nil && !bytes.Equal(response, frame) {
		err = errors.New("TCP response payload mismatch")
	}
	return
}

// ServeTCPEcho preserves request boundaries and echoes a bounded frame unchanged.
// it joins accepted sockets on cancellation, including incomplete client writes.
func ServeTCPEcho(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		workers.Go(func() {
			defer connection.Close()
			stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
			defer stop()
			var header [4]byte
			for {
				if _, err := io.ReadFull(connection, header[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint32(header[:])
				if size < 8 || size > 1<<20 {
					return
				}
				frame := make([]byte, 4+int(size))
				copy(frame, header[:])
				if _, err := io.ReadFull(connection, frame[4:]); err != nil {
					return
				}
				if _, err := io.Copy(connection, bytes.NewReader(frame)); err != nil {
					return
				}
			}
		})
	}
}
