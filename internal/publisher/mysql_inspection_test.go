package publisher

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestMySQLInspectorGroupsPreparedAndMultiResultExecutions(t *testing.T) {
	var observed []DatabaseObservation
	monitor := newMySQLInspector(mysqlClientDeprecateEOF,
		func(value DatabaseObservation) { observed = append(observed, value) })
	prepare := encodeMySQLPacket(0, append([]byte{0x16}, []byte("SELECT ?")...))
	monitor.clientBytes(prepare[:3])
	monitor.clientBytes(prepare[3:])
	reply := make([]byte, 12)
	binary.LittleEndian.PutUint32(reply[1:5], 42)
	binary.LittleEndian.PutUint16(reply[5:7], 1)
	binary.LittleEndian.PutUint16(reply[7:9], 1)
	monitor.serverBytes(append(append(encodeMySQLPacket(1, reply), encodeMySQLPacket(2, []byte("field"))...), encodeMySQLPacket(3, []byte("field"))...))
	execute := make([]byte, 5)
	execute[0] = 0x17
	binary.LittleEndian.PutUint32(execute[1:], 42)
	monitor.clientBytes(encodeMySQLPacket(0, execute))
	response := append(encodeMySQLPacket(1, []byte{1}), encodeMySQLPacket(2, []byte("field"))...)
	response = append(response, encodeMySQLPacket(3, []byte{0, 0, 2})...)
	response = append(response, encodeMySQLPacket(4, mysqlInspectionTerminator(0))...)
	monitor.serverBytes(response)
	if len(observed) != 1 || observed[0].Operation != "execute" ||
		observed[0].Result != "ok" || observed[0].Rows != 1 || observed[0].ResultSets != 1 {
		t.Fatalf("prepared result = %#v", observed)
	}
	query := encodeMySQLPacket(0, append([]byte{0x03}, []byte("SELECT 1; SELECT 2")...))
	monitor.clientBytes(query)
	response = append(encodeMySQLPacket(1, []byte{1}), encodeMySQLPacket(2, []byte("field"))...)
	response = append(response, encodeMySQLPacket(3, []byte{1, '1'})...)
	response = append(response, encodeMySQLPacket(4, mysqlInspectionTerminator(mysqlServerMoreResults))...)
	response = append(response, encodeMySQLPacket(5, []byte{1})...)
	response = append(response, encodeMySQLPacket(6, []byte("field"))...)
	response = append(response, encodeMySQLPacket(7, []byte{1, '2'})...)
	response = append(response, encodeMySQLPacket(8, mysqlInspectionTerminator(0))...)
	monitor.serverBytes(response)
	if len(observed) != 2 || observed[1].Result != "ok" || observed[1].Rows != 2 ||
		observed[1].ResultSets != 2 {
		t.Fatalf("multiple results = %#v", observed)
	}
	monitor.clientBytes(encodeMySQLPacket(0, append([]byte{0x03}, []byte("SELECT missing_column")...)))
	monitor.serverBytes(encodeMySQLPacket(1, []byte{0xff, 0x1e, 0x04, '#', '4', '2', 'S', '2', '2'}))
	if len(observed) != 3 || observed[2].Result != "error" || observed[2].MySQLErrorCode != 1054 ||
		observed[2].SQLState != "42S22" || monitor.disabled {
		t.Fatalf("MySQL failure = %#v, disabled=%t", observed, monitor.disabled)
	}
}

func TestMySQLInspectorKeepsSummaryBoundedAndRejectsUncertainOutcomes(t *testing.T) {
	var observed []DatabaseObservation
	monitor := newMySQLInspector(mysqlClientDeprecateEOF,
		func(value DatabaseObservation) { observed = append(observed, value) })
	statement := strings.Repeat("x", 64<<10)
	monitor.clientBytes(encodeMySQLPacket(0, append([]byte{0x03}, []byte(statement)...)))
	monitor.serverBytes(encodeMySQLPacket(1, []byte{0, 0, 0, 0, 0, 0, 0}))
	if len(observed) != 1 || cap(monitor.client.prefix) > mysqlClientCapture || monitor.disabled {
		t.Fatalf("summary inspection = %#v, captured=%d, disabled=%t", observed, cap(monitor.client.prefix), monitor.disabled)
	}
	monitor.clientBytes(encodeMySQLPacket(0, []byte{0xfb})) // unsupported LOCAL INFILE command.
	if !monitor.disabled {
		t.Fatal("unknown client command left result attribution enabled")
	}
}

func TestMySQLInspectorLegacyEOFAfterColumnsAndRows(t *testing.T) {
	var observed []DatabaseObservation
	var monitor *mysqlInspector
	monitor = newMySQLInspector(0,
		func(value DatabaseObservation) {
			// observation callbacks may inspect connection state without deadlocking.
			monitor.mu.Lock()
			disabled := monitor.disabled
			monitor.mu.Unlock()
			if disabled {
				t.Fatal("inspector stopped before the result was delivered")
			}
			observed = append(observed, value)
		})
	monitor.clientBytes(encodeMySQLPacket(0, []byte{0x03, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'}))
	server := append(encodeMySQLPacket(1, []byte{1}), encodeMySQLPacket(2, []byte("field"))...)
	server = append(server, encodeMySQLPacket(3, []byte{0xfe, 0, 0, 0, 0})...)
	server = append(server, encodeMySQLPacket(4, []byte{1, '1'})...)
	server = append(server, encodeMySQLPacket(5, []byte{0xfe, 0, 0, 0, 0})...)
	monitor.serverBytes(server)
	if len(observed) != 1 || observed[0].Rows != 1 || observed[0].ResultSets != 1 || monitor.disabled {
		t.Fatalf("legacy result = %#v, disabled=%t", observed, monitor.disabled)
	}
}

func TestMySQLInspectorStreamsMaxSizePacketWithBoundedCapture(t *testing.T) {
	var observed []DatabaseObservation
	monitor := newMySQLInspector(mysqlClientDeprecateEOF,
		func(value DatabaseObservation) { observed = append(observed, value) })
	monitor.clientBytes([]byte{0xff, 0xff, 0xff, 0, 0x03})
	chunk := bytes.Repeat([]byte{'x'}, 32<<10)
	for remaining := mysqlMaxPayload - 1; remaining > 0; {
		n := min(remaining, len(chunk))
		monitor.clientBytes(chunk[:n])
		remaining -= n
	}
	// an exact 16 MiB - 1 physical packet has an empty continuation frame.
	monitor.clientBytes([]byte{0, 0, 0, 1})
	monitor.serverBytes(encodeMySQLPacket(2, []byte{0, 0, 0, 0, 0, 0, 0}))
	if len(observed) != 1 {
		t.Fatalf("large execution count=%d", len(observed))
	}
	if observed[0].Result != "ok" || cap(monitor.client.firstPrefix) > mysqlClientCapture {
		t.Fatalf("large execution count=%d, captured capacity=%d",
			len(observed), cap(monitor.client.firstPrefix))
	}
	monitor.clientBytes(encodeMySQLPacket(0, []byte{0x03, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1'}))
	monitor.serverBytes(encodeMySQLPacket(1, []byte{0, 0, 0, 0, 0, 0, 0}))
	if len(observed) != 2 || monitor.disabled {
		t.Fatalf("ordinary execution after large command count=%d, disabled=%t", len(observed), monitor.disabled)
	}
}

func TestMySQLInspectorDisablesCompressedAndUnrecognizedPackets(t *testing.T) {
	for _, flags := range []uint32{mysqlClientCompress, mysqlClientZstdCompression} {
		monitor := newMySQLInspector(flags,
			func(DatabaseObservation) { t.Fatal("compressed traffic cannot be inspected") })
		monitor.clientBytes(encodeMySQLPacket(0, []byte{0x03, 'x'}))
		monitor.serverBytes(encodeMySQLPacket(1, []byte{0, 0, 0, 0, 0, 0, 0}))
		if !monitor.disabled {
			t.Fatalf("inspector enabled for compression flags %d", flags)
		}
	}
	monitor := newMySQLInspector(0,
		func(DatabaseObservation) { t.Fatal("unknown response cannot be attributed") })
	monitor.clientBytes(encodeMySQLPacket(0, []byte{0x03, 'x'}))
	monitor.serverBytes(encodeMySQLPacket(2, []byte{0, 0, 0, 0, 0, 0, 0}))
	if !monitor.disabled {
		t.Fatal("inspector accepted wrong server sequence")
	}
}

func TestMySQLInspectorStopsAtBrokenContinuation(t *testing.T) {
	observed := 0
	monitor := newMySQLInspector(0,
		func(DatabaseObservation) { observed++ })
	physical := make([]byte, mysqlMaxPayload+4)
	physical[0], physical[1], physical[2] = 0xff, 0xff, 0xff
	physical[4] = 0x03 // query command, followed by a maximal payload.
	monitor.clientBytes(physical)
	monitor.clientBytes([]byte{0, 0, 0, 3}) // the next physical sequence must be 1.
	monitor.serverBytes(encodeMySQLPacket(2, []byte{0, 0, 0, 0, 0, 0, 0}))
	if !monitor.disabled || observed != 0 {
		t.Fatalf("broken MySQL continuation: disabled=%t, observations=%d", monitor.disabled, observed)
	}
}

func TestMySQLInspectorStartsOnlyAfterVerifiedTargetLogin(t *testing.T) {
	var observed []DatabaseObservation
	monitor := newMySQLInspectorDuringAuth(mysqlClientSSL,
		func(value DatabaseObservation) { observed = append(observed, value) })
	login := make([]byte, 4)
	binary.LittleEndian.PutUint32(login, mysqlClientSSL|mysqlClientDeprecateEOF)
	login = append(login, []byte("secret-auth-response")...)
	monitor.clientBytes(encodeMySQLPacket(2, login))
	monitor.serverBytes(encodeMySQLPacket(3, []byte{1, 3}))
	if !monitor.awaitingAuth || len(observed) != 0 || cap(monitor.client.prefix) > 16 {
		t.Fatalf("login was inspected as SQL: awaiting=%t, records=%d", monitor.awaitingAuth, len(observed))
	}
	monitor.serverBytes(encodeMySQLPacket(4, []byte{0, 0, 0, 0, 0, 0, 0}))
	if monitor.awaitingAuth || monitor.disabled || !monitor.deprecateEOF {
		t.Fatalf("authenticated observer = awaiting=%t disabled=%t EOF=%t", monitor.awaitingAuth, monitor.disabled, monitor.deprecateEOF)
	}
	for _, value := range monitor.client.firstPrefix {
		if value != 0 {
			t.Fatal("authentication prefix remained in the observer")
		}
	}
	monitor.clientBytes(encodeMySQLPacket(0, append([]byte{0x03}, []byte("SELECT 1")...)))
	monitor.serverBytes(encodeMySQLPacket(1, []byte{0, 0, 0, 0, 0, 0, 0}))
	if len(observed) != 1 || observed[0].Operation != "query" || observed[0].Result != "ok" {
		t.Fatalf("first authenticated query = %#v", observed)
	}
}

func mysqlInspectionTerminator(status uint16) []byte {
	payload := []byte{0xfe, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(payload[3:5], status)
	return payload
}
