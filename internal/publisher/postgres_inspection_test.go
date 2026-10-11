package publisher

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgproto3"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
)

func TestPostgresInspectorRecordsQueriesAndExecutionsAfterTLS(t *testing.T) {
	var observed []DatabaseObservation
	monitor := newPostgresInspector(func(value DatabaseObservation) { observed = append(observed, value) }, projectconfig.InspectionDetailed)
	startup := []byte{0, 0, 0, 8, 0, 3, 0, 0}
	monitor.clientBytes(startup[:3])
	monitor.clientBytes(startup[3:])
	ready, err := (&pgproto3.ReadyForQuery{TxStatus: 'I'}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	monitor.serverBytes(ready)
	query, err := (&pgproto3.Query{String: "SELECT 1"}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	monitor.clientBytes(query[:2])
	monitor.clientBytes(query[2:6])
	monitor.clientBytes(query[6:])
	row, err := (&pgproto3.DataRow{Values: [][]byte{[]byte("1")}}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	monitor.serverBytes(row)
	complete, err := (&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	monitor.serverBytes(append(complete, ready...))
	parse, err := (&pgproto3.Parse{Name: "s", Query: "SELECT $1::int"}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	bind, err := (&pgproto3.Bind{DestinationPortal: "p", PreparedStatement: "s", Parameters: [][]byte{[]byte("2")}}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	execute, err := (&pgproto3.Execute{Portal: "p"}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	monitor.clientBytes(append(append(parse, bind...), execute...))
	monitor.serverBytes(complete)
	monitor.serverBytes(ready)
	if len(observed) != 2 || observed[0].Operation != "query" || observed[0].Statement != "SELECT 1" ||
		observed[0].Rows != 1 || observed[1].Operation != "execute" || observed[1].Statement != "SELECT $1::int" ||
		observed[1].Result != "ok" {
		t.Fatalf("PostgreSQL executions = %#v", observed)
	}
	failed, err := (&pgproto3.Query{String: "SELECT missing_column"}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	monitor.clientBytes(failed)
	problem, err := (&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42703", Message: "column does not exist"}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	monitor.serverBytes(append(problem, ready...))
	if len(observed) != 3 || observed[2].Result != "error" || observed[2].SQLState != "42703" ||
		observed[2].Statement != "SELECT missing_column" {
		t.Fatalf("PostgreSQL failure = %#v", observed)
	}
}

func TestPostgresInspectorSkipsLargeFramesAndDoesNotStoreStatementsByDefault(t *testing.T) {
	if sql, truncated := boundedPostgresStatement(strings.Repeat("é", maxPostgresStatement)); !truncated || len(sql) > maxPostgresStatement || !utf8.ValidString(sql) {
		t.Fatal("bounded SQL cut through a UTF-8 character")
	}
	var observed []DatabaseObservation
	monitor := newPostgresInspector(func(value DatabaseObservation) { observed = append(observed, value) }, projectconfig.InspectionSummary)
	monitor.clientBytes([]byte{0, 0, 0, 8, 0, 3, 0, 0})
	ready, _ := (&pgproto3.ReadyForQuery{TxStatus: 'I'}).Encode(nil)
	monitor.serverBytes(ready)
	large := make([]byte, 5+(128<<10))
	large[0] = 'Q'
	binary.BigEndian.PutUint32(large[1:], uint32(len(large)-1))
	copy(large[5:], strings.Repeat("x", len(large)-6))
	monitor.clientBytes(large[:9])
	monitor.clientBytes(large[9:])
	complete, _ := (&pgproto3.CommandComplete{CommandTag: []byte("SELECT 0")}).Encode(nil)
	monitor.serverBytes(append(complete, ready...))
	if monitor.client.broken || len(observed) != 1 || observed[0].Result != "ok" || observed[0].Statement != "" ||
		cap(monitor.client.body) > maxPostgresCapturedFrame {
		t.Fatalf("large query inspection = %#v, monitor broken=%v", observed, monitor.client.broken)
	}
}

func TestPostgresInspectorKeepsPipelinedQueryOutcomesSeparate(t *testing.T) {
	var observed []DatabaseObservation
	monitor := newPostgresInspector(func(value DatabaseObservation) { observed = append(observed, value) }, projectconfig.InspectionDetailed)
	monitor.clientBytes([]byte{0, 0, 0, 8, 0, 3, 0, 0})
	ready, _ := (&pgproto3.ReadyForQuery{TxStatus: 'I'}).Encode(nil)
	monitor.serverBytes(ready)
	first, _ := (&pgproto3.Query{String: "SELECT missing_column"}).Encode(nil)
	second, _ := (&pgproto3.Query{String: "SELECT 2"}).Encode(nil)
	monitor.clientBytes(append(first, second...))
	problem, _ := (&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42703"}).Encode(nil)
	monitor.serverBytes(append(problem, ready...))
	if len(observed) != 1 || observed[0].Result != "error" || observed[0].Statement != "SELECT missing_column" {
		t.Fatalf("first query outcome = %#v", observed)
	}
	complete, _ := (&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}).Encode(nil)
	monitor.serverBytes(append(complete, ready...))
	if len(observed) != 2 || observed[1].Result != "ok" || observed[1].Statement != "SELECT 2" {
		t.Fatalf("second query outcome = %#v", observed)
	}
}

func TestPostgresInspectorSkipsLargeRowsWithoutLosingExecution(t *testing.T) {
	var observed []DatabaseObservation
	monitor := newPostgresInspector(func(value DatabaseObservation) { observed = append(observed, value) }, projectconfig.InspectionSummary)
	monitor.clientBytes([]byte{0, 0, 0, 8, 0, 3, 0, 0})
	ready, _ := (&pgproto3.ReadyForQuery{TxStatus: 'I'}).Encode(nil)
	monitor.serverBytes(ready)
	query, _ := (&pgproto3.Query{String: "SELECT large_value"}).Encode(nil)
	monitor.clientBytes(query)
	large, err := (&pgproto3.DataRow{Values: [][]byte{bytes.Repeat([]byte{'x'}, 128<<10)}}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	for len(large) > 0 {
		n := min(len(large), 32768)
		monitor.serverBytes(large[:n])
		large = large[n:]
	}
	complete, _ := (&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")}).Encode(nil)
	monitor.serverBytes(append(complete, ready...))
	if monitor.broken || len(observed) != 1 || observed[0].Rows != 1 ||
		observed[0].Result != "ok" || cap(monitor.server.body) > maxPostgresCapturedFrame {
		t.Fatalf("large PostgreSQL row inspection = %#v, broken=%t", observed, monitor.broken)
	}
}

func TestPostgresInspectorRejectsInvalidReadyFrame(t *testing.T) {
	observed := 0
	monitor := newPostgresInspector(func(DatabaseObservation) { observed++ }, projectconfig.InspectionSummary)
	monitor.clientBytes([]byte{0, 0, 0, 8, 0, 3, 0, 0})
	monitor.serverBytes([]byte{'Z', 0, 0, 0, 5, 'X'})
	if !monitor.broken || observed != 0 {
		t.Fatalf("malformed ready frame: broken=%t, observed=%d", monitor.broken, observed)
	}
}
