package publisher

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/streamcopy"
)

func nextRedisObservation(t *testing.T, observed <-chan RedisObservation) RedisObservation {
	t.Helper()
	select {
	case event := <-observed:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("redis result was not observed")
		return RedisObservation{}
	}
}

func TestRedisInspectorPipelinesFragmentsPushAndErrors(t *testing.T) {
	observed := make(chan RedisObservation, 3)
	monitor := newRedisInspector(func(event RedisObservation) { observed <- event })
	request := "*1\r\n$4\r\nping\r\n*2\r\n$3\r\nGET\r\n$6\r\nsecret\r\n"
	monitor.clientBytes([]byte(request[:9]))
	monitor.clientBytes([]byte(request[9:]))
	response := ">2\r\n+invalidate\r\n$6\r\nsecret\r\n|1\r\n+source\r\n+redis\r\n+PONG\r\n-ERR secret\r\n"
	for i := 0; i < len(response); i += 8 {
		monitor.serverBytes([]byte(response[i:min(i+8, len(response))]))
	}
	monitor.drain()
	first, second := nextRedisObservation(t, observed), nextRedisObservation(t, observed)
	if first.Command != "PING" || first.Result != inspection.ResultOK || second.Command != "GET" ||
		second.Result != inspection.ResultError || first.ReceivedAt.IsZero() || second.Duration < 0 ||
		strings.Contains(first.Command+second.Command, "secret") {
		t.Fatalf("redis summaries = %#v, %#v", first, second)
	}
}

func TestRedisInspectorOpaqueAndBoundedFrames(t *testing.T) {
	for _, request := range []string{
		"*2\r\n$9\r\nSUBSCRIBE\r\n$7\r\nchannel\r\n",
		"*2\r\n$4\r\nPING\r\n$1048577\r\n",
		"*1\r\n$65\r\n" + strings.Repeat("X", 65) + "\r\n",
		"*1\r\n*1\r\n$4\r\nPING\r\n",
		"PING\r\n",
	} {
		observed := make(chan RedisObservation, 1)
		monitor := newRedisInspector(func(event RedisObservation) { observed <- event })
		monitor.clientBytes([]byte(request))
		monitor.serverBytes([]byte("+OK\r\n"))
		monitor.drain()
		select {
		case event := <-observed:
			t.Fatalf("unattributable request %q was recorded: %#v", request, event)
		default:
		}
	}
}

func TestRedisInspectorDrainAfterClientStops(t *testing.T) {
	observed := make(chan RedisObservation, 1)
	monitor := newRedisInspector(func(event RedisObservation) { observed <- event })
	monitor.clientBytes([]byte("*2\r\n$4\r\nAUTH\r\n$8\r\ntestpass\r\n"))
	monitor.serverBytes([]byte("+OK\r\n"))
	monitor.drain()
	if event := nextRedisObservation(t, observed); event.Command != "AUTH" || event.Result != inspection.ResultOK {
		t.Fatalf("drained command = %#v", event)
	}
}

func TestRedisInspectorPairsNullAndBlobErrorReplies(t *testing.T) {
	observed := make(chan RedisObservation, 2)
	monitor := newRedisInspector(func(event RedisObservation) { observed <- event })
	monitor.clientBytes([]byte("*2\r\n$5\r\nBLPOP\r\n$3\r\nkey\r\n*1\r\n$4\r\nPING\r\n"))
	monitor.serverBytes([]byte("*-1\r\n!9\r\nERR hello\r\n"))
	monitor.drain()
	first, second := nextRedisObservation(t, observed), nextRedisObservation(t, observed)
	if first.Command != "BLPOP" || first.Result != inspection.ResultOK ||
		second.Command != "PING" || second.Result != inspection.ResultError {
		t.Fatalf("RESP2 null and RESP3 error = %#v, %#v", first, second)
	}
}

func TestRedisInspectorForwardsResponseAfterVisitorHalfClose(t *testing.T) {
	client, visitor := inspectionTCPPair(t)
	backend, target := inspectionTCPPair(t)
	observed := make(chan RedisObservation, 1)
	monitor := newRedisInspector(func(event RedisObservation) { observed <- event })
	wrapped := &databaseInspectionConn{Conn: backend, observer: monitor}
	done := make(chan error, 1)
	go func() {
		_, err := streamcopy.Copy(visitor, wrapped)
		monitor.drain()
		done <- err
	}()
	t.Cleanup(func() { _ = visitor.Close(); _ = backend.Close() })
	for _, connection := range []*net.TCPConn{client, target} {
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	request := "*1\r\n$4\r\nPING\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if body, err := io.ReadAll(target); err != nil || string(body) != request {
		t.Fatalf("forwarded command = %q, %v", body, err)
	}
	if _, err := io.WriteString(target, "+PONG\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := target.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if body, err := io.ReadAll(client); err != nil || string(body) != "+PONG\r\n" {
		t.Fatalf("forwarded reply = %q, %v", body, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("inspected half-close did not finish")
	}
	if event := nextRedisObservation(t, observed); event.Command != "PING" || event.Result != inspection.ResultOK {
		t.Fatalf("drained half-close result = %#v", event)
	}
}
