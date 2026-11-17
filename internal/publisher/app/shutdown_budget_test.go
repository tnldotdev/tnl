package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestManagerShutdownFencesAllRegistrationsBeforeJoining(t *testing.T) {
	started, canceled := make(chan string, 2), make(chan string, 2)
	release := make(chan struct{})
	var manager *Manager
	var err error
	manager, err = newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "api"}, {Name: "web"}}, func(ctx context.Context, service Service, _ func(PublicationUpdate) error) error {
		started <- service.Name
		<-ctx.Done()
		canceled <- service.Name
		<-release
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	manager.ShutdownDeadline = func() time.Time { return until }
	ids := make([]string, 0, 2)
	for _, name := range []string{"api", "web"} {
		id, err := manager.Reserve(name, "owner", 1, "https://"+name+".example")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		if err := manager.Register(id, "owner", "http://127.0.0.1:3000", "node"); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		<-started
	}
	done := make(chan struct{})
	go func() { manager.Close(); close(done) }()
	var once sync.Once
	defer func() { once.Do(func() { close(release) }); <-done }()
	for range 2 {
		select {
		case <-canceled:
		case <-time.After(time.Second):
			t.Fatal("one registration's join prevented another registration from stopping")
		}
	}
	for _, id := range ids {
		if got := manager.PublicationShutdownDeadline(id); !got.Equal(until) {
			t.Fatal("registrations did not share the process shutdown deadline", got, until)
		}
	}
	once.Do(func() { close(release) })
	<-done
}

func TestManagerUnregisterDeadlineOnlyNarrowsExactRegistration(t *testing.T) {
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("web", "owner", 1, "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	if err := manager.LimitShutdown(id, "wrong-owner", "", until); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("another owner narrowed the registration", err)
	}
	if err := manager.LimitShutdown(id, "owner", "", until); err != nil {
		t.Fatal(err)
	}
	if err := manager.LimitShutdown(id, "owner", "", until.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := manager.PublicationShutdownDeadline(id); !got.Equal(until) {
		t.Fatal("retry extended the original shutdown deadline", got, until)
	}
}
