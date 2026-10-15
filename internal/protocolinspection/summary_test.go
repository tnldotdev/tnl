package protocolinspection

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/inspection"
)

func pgWire(kind byte, body string) []byte {
	b := make([]byte, 5+len(body))
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:], uint32(4+len(body)))
	copy(b[5:], body)
	return b
}

func mysqlWire(seq byte, body []byte) []byte {
	return append([]byte{byte(len(body)), byte(len(body) >> 8), byte(len(body) >> 16), seq}, body...)
}

func summaryHarness(protocol string) (*Observer, *[]inspection.Summary) {
	var out []inspection.Summary
	return New(protocol, func(s inspection.Summary) { out = append(out, s) }), &out
}

func fragmented(m *Observer, client bool, b []byte) {
	for _, v := range b {
		m.bytes(client, []byte{v})
	}
}

func readyPG(m *Observer) {
	m.bytes(true, []byte{0, 0, 0, 8, 0, 3, 0, 0})
	m.bytes(false, pgWire('R', "\x00\x00\x00\x00"))
	m.bytes(false, pgWire('Z', "I"))
}

func assertSummaryPrivacy(t *testing.T, summaries []inspection.Summary) {
	t.Helper()
	data, err := json.Marshal(summaries)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-sql", "secret-argument", "secret-password", "secret-reply", "secret-error"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("summary retained private bytes: %s", data)
		}
	}
	for _, s := range summaries {
		if s.ReceivedAt.IsZero() || s.Duration < 0 || !s.Result.Valid() {
			t.Fatalf("invalid summary: %+v", s)
		}
	}
}

func TestPostgresSummariesRespectAuthGroupsAndPrivacy(t *testing.T) {
	m, out := summaryHarness("postgres")
	m.bytes(true, []byte{0, 0, 0, 8, 0, 3, 0, 0})
	m.bytes(true, pgWire('p', "secret-password\x00"))
	m.bytes(true, pgWire('Q', "secret-sql\x00"))
	if len(*out) != 0 {
		t.Fatal("observed before authentication")
	}
	m.bytes(false, pgWire('R', "\x00\x00\x00\x00"))
	m.bytes(false, pgWire('Z', "I"))
	fragmented(m, true, pgWire('Q', "secret-sql\x00"))
	fragmented(m, false, pgWire('D', "secret-reply"))
	m.bytes(false, pgWire('C', "SELECT 1\x00"))
	m.bytes(false, pgWire('Z', "I"))
	// an extended-query failure discards only the remaining executions before Sync.
	for range 2 {
		m.bytes(true, pgWire('E', "portal\x00\x00\x00\x00\x00"))
	}
	m.bytes(true, pgWire('S', ""))
	m.bytes(true, pgWire('E', "\x00\x00\x00\x00\x00"))
	m.bytes(true, pgWire('S', ""))
	fragmented(m, false, pgWire('E', "SERROR\x00C23505\x00Msecret-error\x00Dsecret-sql\x00\x00"))
	m.bytes(false, pgWire('Z', "E"))
	m.bytes(false, pgWire('C', "UPDATE 7\x00"))
	m.bytes(false, pgWire('Z', "I"))
	if len(*out) != 3 || (*out)[0].Rows != 1 || (*out)[1].SQLState != "23505" || (*out)[1].Result != inspection.ResultError || (*out)[2].Rows != 7 {
		t.Fatalf("summaries = %+v", *out)
	}
	assertSummaryPrivacy(t, *out)
}

func TestPostgresSummaryStopsOnCopyAndBoundedPipelining(t *testing.T) {
	for _, opaque := range []string{"copy", "pending", "oversize"} {
		t.Run(opaque, func(t *testing.T) {
			m, out := summaryHarness("postgres")
			readyPG(m)
			switch opaque {
			case "copy":
				m.bytes(true, pgWire('Q', "COPY secret-sql\x00"))
				m.bytes(false, pgWire('G', ""))
			case "pending":
				for range maxPendingOperations + 1 {
					m.bytes(true, pgWire('Q', "secret-sql\x00"))
				}
			case "oversize":
				m.bytes(true, []byte{'Q', 0x7f, 0xff, 0xff, 0xff})
			}
			if !m.stopped {
				t.Fatal("observer remained active after opaque boundary")
			}
			m.bytes(false, pgWire('Z', "I"))
			if len(*out) != 0 {
				t.Fatalf("fabricated summaries = %+v", *out)
			}
		})
	}
}

func TestPostgresEmptyExtendedGroupErrorDoesNotReachLaterQuery(t *testing.T) {
	m, out := summaryHarness("postgres")
	readyPG(m)
	m.bytes(true, pgWire('P', "\x00secret-sql\x00\x00\x00"))
	m.bytes(true, pgWire('S', ""))
	m.bytes(true, pgWire('Q', "SELECT 1\x00"))
	m.bytes(false, pgWire('E', "SERROR\x00C42601\x00Msecret-error\x00\x00"))
	m.bytes(false, pgWire('Z', "I"))
	if len(*out) != 0 {
		t.Fatalf("empty group's error reached another operation: %+v", *out)
	}
	m.bytes(false, pgWire('D', "secret-reply"))
	m.bytes(false, pgWire('C', "SELECT 1\x00"))
	m.bytes(false, pgWire('Z', "I"))
	if len(*out) != 1 || (*out)[0].Result != inspection.ResultOK || (*out)[0].SQLState != "" || (*out)[0].Rows != 1 {
		t.Fatalf("later query summary=%+v", *out)
	}
	assertSummaryPrivacy(t, *out)
}

func TestRedisTransactionsStopObservationBeforeQueuedReplies(t *testing.T) {
	m, out := summaryHarness("redis")
	m.bytes(true, respCommand("MULTI"))
	m.bytes(false, []byte("+OK\r\n"))
	m.bytes(true, respCommand("SET", "key", "secret-argument"))
	m.bytes(false, []byte("+QUEUED\r\n"))
	m.bytes(true, respCommand("EXEC"))
	m.bytes(false, []byte("*1\r\n-ERR secret-error\r\n"))
	if !m.stopped || len(*out) != 0 {
		t.Fatalf("transaction fabricated outcomes: %+v", *out)
	}
}

func TestRedisUnknownCommandsCannotPersistUserText(t *testing.T) {
	m, out := summaryHarness("redis")
	for _, command := range []string{"secret-password", "secret-sql", "MODULE.SECRET-ARGUMENT"} {
		m.bytes(true, respCommand(command))
		m.bytes(false, []byte("-ERR unknown command\r\n"))
	}
	if len(*out) != 3 {
		t.Fatalf("unknown summaries=%+v", *out)
	}
	for _, s := range *out {
		if s.Command != "UNKNOWN" || s.Result != inspection.ResultError {
			t.Fatalf("unsafe command=%+v", s)
		}
	}
	assertSummaryPrivacy(t, *out)
}

func TestMySQLSummaryResultsPreparedMetadataAndErrors(t *testing.T) {
	m, out := summaryHarness("mysql")
	m.MySQLFlags(0)
	fragmented(m, true, mysqlWire(0, append([]byte{3}, []byte("secret-sql")...)))
	m.bytes(false, mysqlWire(1, []byte{1}))
	m.bytes(false, mysqlWire(2, []byte("secret-reply")))
	m.bytes(false, mysqlWire(3, []byte{0xfe, 0, 0, 0, 0}))
	m.bytes(false, mysqlWire(4, []byte("secret-reply")))
	m.bytes(false, mysqlWire(5, []byte{0xfe, 0, 0, 0, 0}))
	// prepare has two parameter definitions and one result column, no summary.
	m.bytes(true, mysqlWire(0, append([]byte{0x16}, []byte("secret-sql")...)))
	m.bytes(false, mysqlWire(1, []byte{0, 9, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0}))
	for _, seq := range []byte{2, 3} {
		m.bytes(false, mysqlWire(seq, []byte("secret-reply")))
	}
	m.bytes(false, mysqlWire(4, []byte{0xfe, 0, 0, 0, 0}))
	m.bytes(false, mysqlWire(5, []byte("secret-reply")))
	m.bytes(false, mysqlWire(6, []byte{0xfe, 0, 0, 0, 0}))
	m.bytes(true, mysqlWire(0, append([]byte{0x17}, make([]byte, 9)...)))
	fragmented(m, false, mysqlWire(1, append([]byte{0xff, 0x28, 0x04, '#'}, []byte("42000secret-error secret-sql")...)))
	if m.stopped || len(*out) != 2 || (*out)[0].Rows != 1 || (*out)[0].ResultSets != 1 || (*out)[1].SQLState != "42000" || (*out)[1].MySQLErrorCode != 1064 {
		t.Fatalf("summaries = %+v, stopped=%t", *out, m.stopped)
	}
	assertSummaryPrivacy(t, *out)
}

func TestMySQLSummaryMultipleResultsAndOpaqueModes(t *testing.T) {
	m, out := summaryHarness("mysql")
	m.MySQLFlags(1 << 24)
	m.bytes(true, mysqlWire(0, []byte{3, 'x'}))
	m.bytes(false, mysqlWire(1, []byte{0, 2, 0, 8, 0, 0, 0}))
	m.bytes(false, mysqlWire(2, []byte{1}))
	m.bytes(false, mysqlWire(3, []byte("metadata")))
	m.bytes(false, mysqlWire(4, []byte{1, 'a'}))
	m.bytes(false, mysqlWire(5, []byte{0xfe, 0, 0, 0, 0, 0, 0}))
	if len(*out) != 1 || (*out)[0].Rows != 3 {
		t.Fatalf("multiple results = %+v", *out)
	}
	for _, flags := range []uint32{1 << 5, 1 << 26} {
		m, _ := summaryHarness("mysql")
		m.MySQLFlags(flags)
		if !m.stopped {
			t.Fatal("observed compressed packets")
		}
	}
	m.bytes(true, mysqlWire(0, []byte{3, 'x'}))
	m.bytes(false, mysqlWire(1, []byte{0xfb}))
	if !m.stopped {
		t.Fatal("observed LOCAL INFILE")
	}
}

func respCommand(parts ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(parts))
	for _, part := range parts {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(part), part)
	}
	return []byte(b.String())
}

func TestRedisSummaryPipelinePushAttributesAndPrivacy(t *testing.T) {
	m, out := summaryHarness("redis")
	fragmented(m, true, respCommand("AUTH", "secret-password"))
	m.bytes(false, []byte("+OK\r\n"))
	fragmented(m, true, respCommand("set", "key", "secret-argument"))
	m.bytes(true, respCommand("GET", "key"))
	fragmented(m, false, []byte(">2\r\n+invalidate\r\n*1\r\n$3\r\nkey\r\n|1\r\n+meta\r\n+secret-reply\r\n+OK\r\n$12\r\nsecret-reply\r\n"))
	m.bytes(true, respCommand("INCR", "secret-argument"))
	m.bytes(false, []byte("-ERR secret-error\r\n"))
	if m.stopped || len(*out) != 3 || (*out)[0].Command != "SET" || (*out)[1].Command != "GET" || (*out)[2].Result != inspection.ResultError {
		t.Fatalf("summaries=%+v stopped=%t", *out, m.stopped)
	}
	assertSummaryPrivacy(t, *out)
}

func TestRedisSummaryBoundsAndOpaqueCommands(t *testing.T) {
	for _, command := range []string{"SUBSCRIBE", "MONITOR", "PSYNC", "CLIENT"} {
		m, _ := summaryHarness("redis")
		m.bytes(true, respCommand(command, "secret-argument"))
		if !m.stopped {
			t.Fatalf("observed %s", command)
		}
	}
	m, out := summaryHarness("redis")
	for range maxPendingOperations + 1 {
		m.bytes(true, respCommand("PING"))
	}
	if !m.stopped || len(*out) != 0 {
		t.Fatal("unbounded pipeline")
	}
	m, _ = summaryHarness("redis")
	m.bytes(true, []byte("*1\r\n$999999999999999999999999999\r\n"))
	if !m.stopped {
		t.Fatal("unbounded numeric header")
	}
}

func FuzzSummaryFrames(f *testing.F) {
	f.Add([]byte("*1\r\n$4\r\nPING\r\n"), []byte("+PONG\r\n"))
	f.Fuzz(func(t *testing.T, client, server []byte) {
		if len(client)+len(server) > 1<<20 {
			t.Skip()
		}
		for _, protocol := range []string{"postgres", "mysql", "redis"} {
			m, out := summaryHarness(protocol)
			if protocol == "postgres" {
				readyPG(m)
			}
			m.bytes(true, client)
			m.bytes(false, server)
			for _, s := range *out {
				if s.Rows < 0 || s.Rows > inspection.MaxCount {
					t.Fatal("unbounded count")
				}
			}
		}
	})
}
