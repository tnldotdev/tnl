package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/0xcadams/tnl/internal/credentials"
)

func TestTokenCommands(t *testing.T) {
	for _, test := range []struct {
		name  string
		args  []string
		parse func(string) error
	}{
		{name: "bootstrap", args: []string{"token", "bootstrap"}, parse: func(value string) error {
			_, err := credentials.ParseBootstrapToken(credentials.BootstrapToken(value))
			return err
		}},
		{name: "worker", args: []string{"token", "worker"}, parse: func(value string) error {
			_, err := credentials.ParseWorkerToken(credentials.WorkerToken(value))
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(context.Background(), test.args, &output); err != nil {
				t.Fatal(err)
			}
			if err := test.parse(strings.TrimSpace(output.String())); err != nil {
				t.Fatal(err)
			}
		})
	}
}
