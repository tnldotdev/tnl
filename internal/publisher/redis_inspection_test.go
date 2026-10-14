package publisher

import (
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
)

func nextRedisObservation(t *testing.T, observed <-chan RedisObservation) RedisObservation {
	t.Helper()
	select {
	case event := <-observed:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("Redis command result was not observed")
		return RedisObservation{}
	}
}

func TestRedisInspectorAttributesPipelinedCommandsAndIgnoresRESP3Push(t *testing.T) {
	observed := make(chan RedisObservation, 4)
	monitor := newRedisInspector(func(event RedisObservation) { observed <- event })
	request := "*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"
	monitor.clientBytes([]byte(request[:9]))
	monitor.clientBytes([]byte(request[9:]))
	monitor.serverBytes([]byte(">2\r\n+invalidate\r\n$3\r\nkey\r\n|1\r\n+source\r\n+redis\r\n+PONG\r\n-ERR missing\r\n"))
	monitor.drain()
	first, second := nextRedisObservation(t, observed), nextRedisObservation(t, observed)
	if first.Command != "PING" || first.Result != inspection.ResultOK || second.Command != "GET" ||
		second.Result != inspection.ResultError || first.ReceivedAt.IsZero() || second.Duration < 0 {
		t.Fatalf("pipelined Redis observations = %#v, %#v", first, second)
	}
}

func TestRedisInspectorRetainsOnlyTheCommandName(t *testing.T) {
	observed := make(chan RedisObservation, 1)
	monitor := newRedisInspector(func(event RedisObservation) { observed <- event })
	monitor.clientBytes([]byte("*2\r\n$4\r\nAUTH\r\n$8\r\ntestpass\r\n"))
	monitor.serverBytes([]byte("+OK\r\n"))
	monitor.drain()
	event := nextRedisObservation(t, observed)
	if event.Command != "AUTH" || event.Result != inspection.ResultOK || strings.Contains(event.Command, "testpass") {
		t.Fatalf("Redis authentication summary = %#v", event)
	}
}

func TestRedisInspectorStopsOnSubscriptionsAndOversizedQueue(t *testing.T) {
	observed := make(chan RedisObservation, 1)
	monitor := newRedisInspector(func(event RedisObservation) { observed <- event })
	monitor.clientBytes([]byte("*2\r\n$9\r\nSUBSCRIBE\r\n$7\r\nchannel\r\n"))
	monitor.serverBytes([]byte("*3\r\n$9\r\nsubscribe\r\n$7\r\nchannel\r\n:1\r\n"))
	monitor.drain()
	select {
	case event := <-observed:
		t.Fatalf("unattributable subscription was recorded: %#v", event)
	case <-time.After(20 * time.Millisecond):
	}
	monitor = newRedisInspector(func(event RedisObservation) { observed <- event })
	monitor.clientBytes([]byte("*2\r\n$4\r\nPING\r\n$999999\r\n"))
	monitor.clientBytes([]byte(strings.Repeat("x", redisInspectionChunkSize*(redisInspectionQueueSize+2))))
	monitor.clientBytes([]byte("*1\r\n$4\r\nPING\r\n"))
	monitor.serverBytes([]byte("+PONG\r\n"))
	monitor.drain()
	select {
	case event := <-observed:
		t.Fatalf("oversized command was recorded: %#v", event)
	case <-time.After(20 * time.Millisecond):
	}
}
