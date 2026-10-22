package connectionruntime

import (
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestListenerReplacementKeepsAddressAndNeverReplaysAcceptedBytes(t *testing.T) {
	base, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	owner := NewListenerSwitch(base)
	defer owner.Close()
	first := owner.Next()
	client, err := net.Dial("tcp4", owner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted, err := first.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = accepted.SetDeadline(time.Now().Add(time.Second))
	second := owner.Next()
	if second.Addr().String() != first.Addr().String() {
		t.Fatal("replacement changed listener")
	}
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("old generation still accepted", err)
	}
	go func() { _, _ = client.Write([]byte("original")) }()
	data := make([]byte, 8)
	if _, err := io.ReadFull(accepted, data); err != nil || string(data) != "original" {
		t.Fatal("accepted stream changed owner", err)
	}
	next, err := net.Dial("tcp4", owner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	future, err := second.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer future.Close()
	_ = future.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if n, err := future.Read(data); n != 0 || err == nil {
		t.Fatal("replacement replayed old bytes")
	}
}

func TestOwnerRecoveryRequiresReleasedLifetimeLock(t *testing.T) {
	directory, err := NewDirectory(fixtureScope(t).Directory)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := ownerLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "handle.json")
	if err := OwnerStopped(file); !errors.Is(err, ErrUnavailable) {
		t.Fatal("live owner could be replaced after an IPC read failure", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := OwnerStopped(file); err != nil {
		t.Fatal("dead owner could not be recovered", err)
	}
}

func TestListenerCloseJoinsAnUndeliveredAccept(t *testing.T) {
	base, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	owner := NewListenerSwitch(base)
	_ = owner.Next()
	client, err := net.Dial("tcp4", owner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- owner.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner close leaked an undelivered accept")
	}
}

func TestListenerNextAfterTerminalCloseIsImmediatelyClosed(t *testing.T) {
	for _, acceptFailure := range []bool{false, true} {
		name := "close"
		if acceptFailure {
			name = "accept-failure"
		}
		t.Run(name, func(t *testing.T) {
			base, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			owner := NewListenerSwitch(base)
			defer owner.Close()
			first := owner.Next()
			if acceptFailure {
				_ = base.Close()
				select {
				case <-owner.done:
				case <-time.After(time.Second):
					t.Fatal("accept worker did not exit")
				}
			} else if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			for _, generation := range []net.Listener{first, owner.Next(), owner.Next()} {
				result := make(chan error, 1)
				go func() { _, err := generation.Accept(); result <- err }()
				select {
				case err := <-result:
					if !errors.Is(err, net.ErrClosed) {
						t.Fatalf("terminal accept=%v", err)
					}
				case <-time.After(time.Second):
					_ = generation.Close()
					t.Fatal("Next after terminal close blocked")
				}
				if generation.Addr().String() != base.Addr().String() {
					t.Fatal("terminal address changed")
				}
			}
		})
	}
}

func TestListenerConcurrentNextAndCloseCannotReviveAccepts(t *testing.T) {
	base, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	owner := NewListenerSwitch(base)
	defer owner.Close()
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			for range 16 {
				_ = owner.Next().Close()
			}
		})
		group.Go(func() { _ = owner.Close() })
	}
	group.Wait()
	if _, err := owner.Next().Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("revived accept=%v", err)
	}
}
