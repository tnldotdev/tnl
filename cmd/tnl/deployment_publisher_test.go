package main

import (
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

func TestDeploymentPublisherEnrollmentHasBoundedIndependentTaskBudget(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publisher", "setup", "--deployment", "cluster", "--service", "db", "--members", "20", "--expires-in", "1h"}); err != nil {
		t.Fatal(err)
	}
	body, err := deploymentPublisherSetupBody(flags.Publisher.Setup)
	if err != nil || *body.MaxMembers != 20 || *body.ExpiresIn != 3600 {
		t.Fatalf("bootstrap bounds: %#v err=%v", body, err)
	}
	for _, entry := range []publisherSetupCommand{{Members: 0, ExpiresIn: time.Minute}, {Members: 257, ExpiresIn: time.Minute}, {Members: 1, ExpiresIn: 0}, {Members: 1, ExpiresIn: 59 * time.Second}, {Members: 1, ExpiresIn: 25 * time.Hour}, {Members: 1, ExpiresIn: time.Minute + time.Millisecond}} {
		entry.Deployment, entry.Services = "cluster", []string{"db"}
		if _, err := deploymentPublisherSetupBody(entry); err == nil {
			t.Fatalf("unbounded bootstrap accepted: members=%d lifetime=%s", entry.Members, entry.ExpiresIn)
		}
	}
	for _, entry := range []publisherSetupCommand{{Members: 1, ExpiresIn: time.Minute}, {Members: 256, ExpiresIn: 24 * time.Hour}} {
		entry.Deployment, entry.Services = "cluster", []string{"db"}
		if _, err := deploymentPublisherSetupBody(entry); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRetiredPublisherGroupCommandsAreNotParsed(t *testing.T) {
	for _, args := range [][]string{
		{"publisher", "enroll", "--deployment", "production"},
		{"publisher", "enroll", "--group", "production"},
		{"publisher", "provision", "--group", "production", "--output-file", "unused.json"},
		{"publisher", "serve", "--group", "production"},
		{"publisher", "rename", "production", "live"},
		{"publisher", "namespace", "rename", "production", "live"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err == nil {
			t.Fatalf("retired command remained accepted: %v", args)
		}
	}
}
