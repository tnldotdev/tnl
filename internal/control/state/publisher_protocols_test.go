package state

import (
	"errors"
	"reflect"
	"testing"
)

func TestPublisherProtocolIssuanceCapturesExplicitCapability(t *testing.T) {
	member, err := authorizePublisherProtocols(nil, false, "http")
	if err != nil || !reflect.DeepEqual(member.values(), []string{"http"}) {
		t.Fatal("member default was not exactly HTTP", member, err)
	}
	admin, err := authorizePublisherProtocols(nil, true, "http")
	if err != nil || !admin.includes("postgres") || !admin.includes("tcp") || len(admin) != 5 {
		t.Fatal("administrator default lost existing explicit native capability", admin, err)
	}
	request := []string{"postgres", "http"}
	narrow, err := authorizePublisherProtocols(request, true, "http")
	if err != nil || !reflect.DeepEqual(narrow.values(), []string{"http", "postgres"}) {
		t.Fatal("administrator could not issue a canonical narrower set", narrow, err)
	}
	request[0] = "tcp"
	if !narrow.includes("postgres") || narrow.includes("tcp") {
		t.Fatal("approved capability retained the request's mutable slice")
	}
	values := narrow.values()
	values[0] = "tcp"
	if narrow.includes("tcp") {
		t.Fatal("capability projection mutated its approved set")
	}
}

func TestPublisherProtocolIssuanceRejectsMemberNativeAndMalformedSets(t *testing.T) {
	for _, test := range []struct {
		name, protocol string
		request        []string
		administrator  bool
	}{
		{"native member default", "postgres", nil, false},
		{"native member request", "http", []string{"postgres"}, false},
		{"mixed member request", "http", []string{"http", "tcp"}, false},
		{"empty", "http", []string{}, true},
		{"duplicate", "http", []string{"http", "http"}, true},
		{"unknown", "http", []string{"ssh"}, true},
		{"wildcard", "http", []string{"*"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := authorizePublisherProtocols(test.request, test.administrator, test.protocol); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("invalid or unauthorized protocol capability was accepted", err)
			}
		})
	}
	if _, err := normalizePublisherProtocols(nil); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("missing persisted capability acquired a default", err)
	}
}
