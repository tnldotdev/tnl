package main

import (
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

func TestPublisherGroupEnrollmentHasBoundedIndependentTaskBudget(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publisher", "enroll", "--group", "cluster", "--members", "20", "--expires-in", "1h"}); err != nil {
		t.Fatal(err)
	}
	members, expires, err := publisherGroupEnrollmentBounds(flags.Publisher.Enroll)
	if err != nil || members != 20 || expires != 3600 {
		t.Fatalf("bootstrap bounds: members=%d seconds=%d err=%v", members, expires, err)
	}
	for _, entry := range []publisherEnrollCommand{{Members: 0, ExpiresIn: time.Minute}, {Members: 257, ExpiresIn: time.Minute}, {Members: 1, ExpiresIn: 0}, {Members: 1, ExpiresIn: 59 * time.Second}, {Members: 1, ExpiresIn: 25 * time.Hour}, {Members: 1, ExpiresIn: time.Minute + time.Millisecond}} {
		if _, _, err := publisherGroupEnrollmentBounds(entry); err == nil {
			t.Fatalf("unbounded bootstrap accepted: members=%d lifetime=%s", entry.Members, entry.ExpiresIn)
		}
	}
	for _, entry := range []publisherEnrollCommand{{Members: 1, ExpiresIn: time.Minute}, {Members: 256, ExpiresIn: 24 * time.Hour}} {
		if _, _, err := publisherGroupEnrollmentBounds(entry); err != nil {
			t.Fatal(err)
		}
	}
}
