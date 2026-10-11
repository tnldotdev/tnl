//go:build inspectororacle

package publisher

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	projectconfig "github.com/tnldotdev/tnl/internal/config"
	vitess "vitess.io/vitess/go/mysql"
	"vitess.io/vitess/go/mysql/sqlerror"
)

type oracleReaderConn struct{ *bytes.Reader }

func (*oracleReaderConn) Write(data []byte) (int, error)   { return len(data), nil }
func (*oracleReaderConn) Close() error                     { return nil }
func (*oracleReaderConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*oracleReaderConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*oracleReaderConn) SetDeadline(time.Time) error      { return nil }
func (*oracleReaderConn) SetReadDeadline(time.Time) error  { return nil }
func (*oracleReaderConn) SetWriteDeadline(time.Time) error { return nil }

// the column definition is a protocol-valid INT field for SELECT literals.
func oracleMySQLColumn() []byte {
	return []byte{3, 'd', 'e', 'f', 0, 0, 0, 1, 'n', 0, 12, 63, 0,
		11, 0, 0, 0, 3, 0, 0, 0, 0, 0}
}

func oracleMySQLResultSet(sequence byte, values []byte, more bool) ([]byte, byte) {
	packets := append(encodeMySQLPacket(sequence, []byte{1}), encodeMySQLPacket(sequence+1, oracleMySQLColumn())...)
	sequence += 2
	for _, value := range values {
		packets = append(packets, encodeMySQLPacket(sequence, []byte{1, value})...)
		sequence++
	}
	status := uint16(0)
	if more {
		status = mysqlServerMoreResults
	}
	packets = append(packets, encodeMySQLPacket(sequence, mysqlInspectionTerminator(status))...)
	return packets, sequence + 1
}

func oracleResult(t *testing.T, wire []byte, expectedSets int) (int64, int) {
	t.Helper()
	connection := vitess.NewConnForTest(&oracleReaderConn{Reader: bytes.NewReader(wire)})
	connection.Capabilities = vitess.CapabilityClientProtocol41 | vitess.CapabilityClientDeprecateEOF
	if err := connection.WriteComQuery("SELECT 1"); err != nil {
		t.Fatal(err)
	}
	var rows int64
	sets := 0
	for {
		result, more, _, err := connection.ReadQueryResult(vitess.FETCH_ALL_ROWS, false)
		if err != nil {
			t.Fatalf("Vitess could not decode server response: %v", err)
		}
		sets++
		rows += int64(len(result.Rows))
		if !more {
			break
		}
	}
	if sets != expectedSets {
		t.Fatalf("Vitess result sets = %d, want %d", sets, expectedSets)
	}
	return rows, sets
}

func TestOracleMySQLResultsMatchVitess(t *testing.T) {
	for _, test := range []struct {
		name string
		sets [][]byte
	}{
		{"one streamed set", [][]byte{bytes.Repeat([]byte{'1'}, 256)}},
		{"two result sets", [][]byte{{'1'}, {'2', '3'}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wire []byte
			sequence := byte(1)
			for index, values := range test.sets {
				packet, next := oracleMySQLResultSet(sequence, values, index+1 < len(test.sets))
				wire = append(wire, packet...)
				sequence = next
			}
			oracleRows, oracleSets := oracleResult(t, wire, len(test.sets))
			var observed []DatabaseObservation
			monitor := newMySQLInspector(mysqlClientDeprecateEOF, projectconfig.InspectionSummary,
				func(value DatabaseObservation) { observed = append(observed, value) })
			monitor.clientBytes(encodeMySQLPacket(0, []byte("\x03SELECT 1")))
			for len(wire) > 0 {
				n := min(len(wire), 7)
				monitor.serverBytes(wire[:n])
				wire = wire[n:]
			}
			if monitor.disabled || len(observed) != 1 || observed[0].Rows != oracleRows ||
				observed[0].ResultSets != oracleSets || observed[0].Result != "ok" {
				t.Fatalf("tnl observations = %#v, Vitess rows=%d sets=%d, disabled=%t", observed, oracleRows, oracleSets, monitor.disabled)
			}
		})
	}
}

func TestOracleMySQLErrorMatchesVitess(t *testing.T) {
	payload := []byte{0xff, 0x1e, 0x04, '#', '4', '2', 'S', '2', '2'}
	payload = append(payload, []byte("unknown column")...)
	wire := encodeMySQLPacket(1, payload)
	connection := vitess.NewConnForTest(&oracleReaderConn{Reader: bytes.NewReader(wire)})
	connection.Capabilities = vitess.CapabilityClientProtocol41 | vitess.CapabilityClientDeprecateEOF
	if err := connection.WriteComQuery("SELECT missing_column"); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := connection.ReadQueryResult(vitess.FETCH_NO_ROWS, false)
	var sqlError *sqlerror.SQLError
	if !errors.As(err, &sqlError) {
		t.Fatalf("Vitess error = %v, want SQL error", err)
	}
	var observed []DatabaseObservation
	monitor := newMySQLInspector(mysqlClientDeprecateEOF, projectconfig.InspectionSummary,
		func(value DatabaseObservation) { observed = append(observed, value) })
	monitor.clientBytes(encodeMySQLPacket(0, []byte("\x03SELECT missing_column")))
	monitor.serverBytes(wire)
	if len(observed) != 1 || observed[0].Result != "error" ||
		observed[0].MySQLErrorCode != uint16(sqlError.Number()) || observed[0].SQLState != sqlError.SQLState() {
		t.Fatalf("tnl error = %#v, Vitess error = %d %s", observed, sqlError.Number(), sqlError.SQLState())
	}
}
