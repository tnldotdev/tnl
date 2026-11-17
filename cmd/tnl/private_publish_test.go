package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisher/invocation"
)

func TestServicePublishPresentationSeparatesExposureAndIdentity(t *testing.T) {
	for _, test := range []struct {
		name, protocol string
		port           int
		public         bool
		want, absent   string
	}{
		{"private without reservation", "http", 0, false, "TLS hostname", "example.test:0"},
		{"retained private reservation", "postgres", 25443, false, "connector access only", "example.test:25443"},
		{"public HTTP", "http", 25443, true, "https://api.example.test:25443", "https://api.example.test:443"},
		{"public postgres", "postgres", 25443, true, "api.example.test:25443", "https://"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			event := invocation.ServiceEvent{State: "ready", ServiceID: "svc_test", Name: "api", Target: "localhost:3000", Hostname: "api.example.test", Port: test.port, Protocol: test.protocol, Public: test.public}
			err := privatePresentation(t.Context(), publishCommand{}, &output, &diagnostics).Event(event)
			if err != nil || output.Len() != 0 || !strings.Contains(diagnostics.String(), test.want) || strings.Contains(diagnostics.String(), test.absent) {
				t.Fatal("service publish presentation lost exposure or port", diagnostics.String(), err)
			}
		})
	}
}

func TestServicePublishNDJSONContractDoesNotChangeWithExposure(t *testing.T) {
	var output, diagnostics bytes.Buffer
	flags := publishCommand{Output: publishOutputNDJSON}
	err := privatePresentation(context.Background(), flags, &output, &diagnostics).Event(invocation.ServiceEvent{
		State: "ready", ServiceID: "svc_test", Name: "api", Target: "localhost:3000", Hostname: "api.example.test", Port: 25443, Protocol: "http", Public: true,
	})
	const expected = "{\"schema_version\":1,\"type\":\"ready\",\"service_id\":\"svc_test\",\"name\":\"api\",\"target\":\"localhost:3000\"}\n"
	if err != nil || diagnostics.Len() != 0 || output.String() != expected {
		t.Fatal("service publish NDJSON changed", output.String(), diagnostics.String(), err)
	}
}
