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

func TestPublisherProvisionKeepsSavedServiceIDSeparateFromDeploymentNames(t *testing.T) {
	for _, test := range []struct {
		name, serviceID, deployment string
		args                        []string
	}{
		{"saved service", "svc_aaaaaaaaaaaaaaaaaaaaaa", "", []string{"--service-id", "svc_aaaaaaaaaaaaaaaaaaaaaa"}},
		{"deployment binding", "", "production", []string{"--deployment", "production", "--service", "shell"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			args := append([]string{"publisher", "provision", "--output-file", "unused.json"}, test.args...)
			if _, err := parser.Parse(args); err != nil {
				t.Fatal(err)
			}
			selection := flags.Publisher.Provision
			if selection.ServiceID != test.serviceID || selection.Deployment != test.deployment {
				t.Fatal("provision confused an exact saved service ID with a deployment binding")
			}
			if test.deployment == "" && len(selection.Services) != 0 ||
				test.deployment != "" && (len(selection.Services) != 1 || selection.Services[0] != "shell") {
				t.Fatal("provision lost its exact binding approval")
			}
		})
	}
}
