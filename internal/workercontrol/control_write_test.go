package workercontrol

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/workerv1"
)

func TestControlWritersSetAndClearDeadline(t *testing.T) {
	for _, test := range controlWriters() {
		t.Run(test.name, func(t *testing.T) {
			connection := new(controlWriteTestConn)
			before := time.Now()
			err := test.write(connection, workerv1.Message{Type: workerv1.WorkerDraining})
			after := time.Now()
			if err != nil {
				t.Fatal(err)
			}
			if len(connection.writeDeadlines) != 2 {
				t.Fatalf("write deadlines = %v", connection.writeDeadlines)
			}
			deadline := connection.writeDeadlines[0]
			if deadline.Before(before.Add(controlWriteTimeout)) || deadline.After(after.Add(controlWriteTimeout)) {
				t.Fatalf("write deadline = %v, want now + %v", deadline, controlWriteTimeout)
			}
			if !connection.writeDeadlines[1].IsZero() {
				t.Fatalf("cleared write deadline = %v", connection.writeDeadlines[1])
			}
			if connection.closed {
				t.Fatal("control stream closed after successful write")
			}
			message, err := workerv1.ReadControl(bytes.NewReader(connection.Bytes()))
			if err != nil || message.Type != workerv1.WorkerDraining {
				t.Fatalf("control message = %#v, %v", message, err)
			}
		})
	}
}

func TestControlWritersCloseOnFailure(t *testing.T) {
	failure := errors.New("failure")
	failures := []struct {
		name              string
		deadlineErrorCall int
		writeError        error
	}{
		{name: "set deadline", deadlineErrorCall: 1},
		{name: "write", writeError: failure},
		{name: "clear deadline", deadlineErrorCall: 2},
	}
	for _, writer := range controlWriters() {
		for _, test := range failures {
			t.Run(writer.name+"/"+test.name, func(t *testing.T) {
				connection := &controlWriteTestConn{
					deadlineErrorCall: test.deadlineErrorCall,
					writeError:        test.writeError,
					failure:           failure,
				}
				err := writer.write(connection, workerv1.Message{Type: workerv1.WorkerDraining})
				if !errors.Is(err, failure) {
					t.Fatalf("write error = %v, want %v", err, failure)
				}
				if !connection.closed {
					t.Fatal("control stream was not closed")
				}
			})
		}
	}
}

type controlWriter struct {
	name  string
	write func(net.Conn, workerv1.Message) error
}

func controlWriters() []controlWriter {
	return []controlWriter{
		{name: "remote worker", write: func(connection net.Conn, message workerv1.Message) error {
			return (&remoteWorker{control: connection}).write(message)
		}},
		{name: "worker session", write: func(connection net.Conn, message workerv1.Message) error {
			return (&workerSession{control: connection}).write(message)
		}},
	}
}

type controlWriteTestConn struct {
	bytes.Buffer
	writeDeadlines    []time.Time
	deadlineErrorCall int
	deadlineCalls     int
	writeError        error
	failure           error
	closed            bool
}

func (c *controlWriteTestConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *controlWriteTestConn) Write(payload []byte) (int, error) {
	if c.writeError != nil {
		return 0, c.writeError
	}
	return c.Buffer.Write(payload)
}

func (c *controlWriteTestConn) Close() error {
	c.closed = true
	return nil
}

func (c *controlWriteTestConn) LocalAddr() net.Addr  { return nil }
func (c *controlWriteTestConn) RemoteAddr() net.Addr { return nil }

func (c *controlWriteTestConn) SetDeadline(time.Time) error     { return nil }
func (c *controlWriteTestConn) SetReadDeadline(time.Time) error { return nil }

func (c *controlWriteTestConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineCalls++
	c.writeDeadlines = append(c.writeDeadlines, deadline)
	if c.deadlineCalls == c.deadlineErrorCall {
		return c.failure
	}
	return nil
}
