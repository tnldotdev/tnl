package benchworkload

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
)

// the routine fixture checks pgx session ownership without external infrastructure.
// the separated load test supplies real PostgreSQL, SCRAM, and verified TLS.
func TestPostgresVisitorWarmSessions(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Uint32
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			pid := accepted.Add(1)
			workers.Go(func() {
				defer conn.Close()
				backend := pgproto3.NewBackend(conn, conn)
				if _, err := backend.ReceiveStartupMessage(); err != nil {
					return
				}
				backend.Send(&pgproto3.AuthenticationCleartextPassword{})
				if err := backend.Flush(); err != nil {
					return
				}
				password, err := backend.Receive()
				if err != nil || password.(*pgproto3.PasswordMessage).Password != "testpass" {
					return
				}
				backend.Send(&pgproto3.AuthenticationOk{})
				backend.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
				backend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
				backend.Send(&pgproto3.BackendKeyData{ProcessID: pid, SecretKey: []byte{0, 0, 0, 123}})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if err := backend.Flush(); err != nil {
					return
				}
				for {
					message, err := backend.Receive()
					if err != nil {
						return
					}
					if _, ok := message.(*pgproto3.Terminate); ok {
						return
					}
					query, ok := message.(*pgproto3.Query)
					if !ok || !slices.Contains([]string{"SELECT 1", "SELECT pg_backend_pid()"}, query.String) {
						t.Errorf("unexpected warm query: %T %+v", message, message)
						return
					}
					value := "1"
					if query.String == "SELECT pg_backend_pid()" {
						value = strconv.Itoa(int(pid))
					}
					backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("value"), DataTypeOID: 23, DataTypeSize: 4}}})
					backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte(value)}})
					backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
					backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
					if err := backend.Flush(); err != nil {
						return
					}
				}
			})
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; workers.Wait() })
	config, err := pgx.ParseConfig(fmt.Sprintf("postgres://test:testpass@%s/test?sslmode=disable", listener.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	visitor := &PostgresVisitor{}
	t.Cleanup(func() { _ = visitor.Close() })
	setup, err := visitor.Prepare(t.Context(), config, 4)
	if err != nil || setup.Count != 4 {
		t.Fatalf("prepare: %+v %v", setup, err)
	}
	before, err := visitor.Verify(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	result, err := visitor.Run(t.Context(), VisitorConfig{Rate: 100, Workers: 4, QueueSlots: 4, Duration: 100 * time.Millisecond})
	if err != nil || result.Err() != nil || result.Successes != 10 || result.FirstByte.Count != 0 || result.Connect.Count != 0 || result.TLS.Count != 0 {
		t.Fatalf("warm result: %+v %v", result, err)
	}
	after, err := visitor.Verify(t.Context())
	if err != nil || !slices.Equal(before.BackendPIDs, after.BackendPIDs) || after.DialCalls != 4 || accepted.Load() != 4 {
		t.Fatalf("session identity changed: before=%+v after=%+v accepted=%d error=%v", before, after, accepted.Load(), err)
	}
	// a failed connection is reported, never silently replaced by a fresh session.
	if err := visitor.owned[0].Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err = visitor.Run(t.Context(), VisitorConfig{Rate: 100, Workers: 4, QueueSlots: 4, Duration: 100 * time.Millisecond})
	if err != nil || result.Failures == 0 || result.Err() == nil || accepted.Load() != 4 {
		t.Fatalf("broken session reconnected or hidden: %+v accepted=%d error=%v", result, accepted.Load(), err)
	}
	if _, err := visitor.Verify(t.Context()); err == nil {
		t.Fatal("broken session passed verification")
	}
}

func TestPostgresVisitorRequiresPreparedSessions(t *testing.T) {
	v := &PostgresVisitor{}
	if _, err := v.Prepare(t.Context(), nil, 1); err == nil {
		t.Fatal("missing configuration accepted")
	}
	if _, err := v.Run(t.Context(), VisitorConfig{Workers: 1}); err == nil {
		t.Fatal("unprepared workload accepted")
	}
	if _, err := v.Verify(context.Background()); err == nil {
		t.Fatal("unprepared sessions verified")
	}
}
