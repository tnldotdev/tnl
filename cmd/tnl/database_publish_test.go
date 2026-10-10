package main

import (
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestDatabasePublishAndCredentialFlags(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"publish", "db.internal:5432", "--protocol", "postgres", "--name", "orders", "--target-tls-name", "db.internal", "--database-tls-passthrough"}, "postgres"},
		{[]string{"url", "credential", "create", "--protocol", "mysql", "--name", "orders"}, "mysql"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(test.args); err != nil {
			t.Fatal(err)
		}
		if test.want == "postgres" {
			if flags.Publish.Target != "db.internal:5432" || flags.Publish.Protocol != test.want ||
				flags.Publish.Name != "orders" || flags.Publish.TargetTLSName != "db.internal" || !flags.Publish.DatabasePassthrough {
				t.Fatalf("database publish flags = %+v", flags.Publish)
			}
		} else if flags.URL.Credential.Create.Protocol != test.want || flags.URL.Credential.Create.Name != "orders" {
			t.Fatalf("database credential flags = %+v", flags.URL.Credential.Create)
		}
	}
}

func TestDatabasePublishTargetAndScopedProtocol(t *testing.T) {
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Postgres, controlv1.Mysql} {
		if got, err := normalizePublishTarget("db.internal:5432", protocol); err != nil || got != "db.internal:5432" {
			t.Fatalf("%s target = %q, %v", protocol, got, err)
		}
		if got, err := selectScopedPublishTargetForProtocol("", "db.internal:5432", protocol); err != nil || got != "db.internal:5432" {
			t.Fatalf("%s credential target = %q, %v", protocol, got, err)
		}
		if _, err := selectScopedPublishTargetForProtocol("", "", protocol); err == nil {
			t.Fatal("database credential accepted a missing local target")
		} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.MissingTarget {
			t.Fatalf("missing target reason = %q, %v", reason, err)
		}
		if _, err := selectScopedPublishTargetForProtocol("http://db.internal:5432", "db.internal:5432", protocol); err == nil {
			t.Fatal("database credential accepted a control-stored private target")
		}
	}
	for _, target := range []string{"http://db.internal:5432", "db.internal", "db.internal:0", "db.internal:65536"} {
		if _, err := normalizePublishTarget(target, controlv1.Postgres); err == nil {
			t.Fatalf("invalid database target %q was accepted", target)
		} else if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.TargetInvalid {
			t.Fatalf("invalid target %q diagnostic = %q, %v", target, code, err)
		}
	}
	if _, err := publishProtocol("other"); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
	if _, err := normalizePublishTarget("127.0.0.1:5432", controlv1.Http); err == nil {
		t.Fatal("HTTP accepted a database target syntax")
	}
}

func TestDatabasePublicAddressAndFlags(t *testing.T) {
	port := 15432
	address, err := savedPublicAddress(controlv1.PublicURL{
		CanonicalHostname: "orders.example", ServiceProtocol: controlv1.Postgres, PublicPort: &port,
	})
	if err != nil || address != "orders.example:15432" {
		t.Fatalf("database address = %q, %v", address, err)
	}
	if _, err := savedPublicAddress(controlv1.PublicURL{ServiceProtocol: controlv1.Mysql}); err == nil {
		t.Fatal("database URL without a public port was accepted")
	}
	if got, err := savedPublicAddress(controlv1.PublicURL{CanonicalHostname: "api.example", ServiceProtocol: controlv1.Http}); err != nil || got != "https://api.example" {
		t.Fatalf("HTTP address = %q, %v", got, err)
	}
	if err := validateDatabasePublishOptions(publishCommand{TargetTLSName: "db.internal"}, controlv1.Http); err == nil {
		t.Fatal("HTTP accepted database TLS settings")
	}
	if err := validateDatabasePublishOptions(publishCommand{DatabasePassthrough: true, TargetTLSName: "db.internal"}, controlv1.Postgres); err == nil {
		t.Fatal("passthrough accepted a misleading target TLS name")
	}
	if err := validateDatabasePublishOptions(publishCommand{openOptions: openOptions{Open: true}}, controlv1.Mysql); err == nil {
		t.Fatal("database --open was silently ignored")
	}
}
