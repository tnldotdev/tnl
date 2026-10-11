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
		{[]string{"publish", "db.internal:5432", "--protocol", "postgres", "--name", "orders", "--target-tls", "--target-tls-name", "db.internal"}, "postgres"},
		{[]string{"url", "credential", "create", "--protocol", "mysql", "--name", "orders"}, "mysql"},
		{[]string{"url", "credential", "create", "--protocol", "redis", "--name", "orders"}, "redis"},
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
				flags.Publish.Name != "orders" || !flags.Publish.TargetTLS || flags.Publish.TargetTLSName != "db.internal" {
				t.Fatalf("database publish flags = %+v", flags.Publish)
			}
		} else if flags.URL.Credential.Create.Protocol != test.want || flags.URL.Credential.Create.Name != "orders" {
			t.Fatalf("database credential flags = %+v", flags.URL.Credential.Create)
		}
	}
}

func TestVisitorTLSPassthroughFlagUsesClientVerification(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publish", "db.internal:5432", "--protocol", "postgres", "--visitor-tls-passthrough"}); err != nil {
		t.Fatal(err)
	}
	if !flags.Publish.VisitorTLSPassthrough || flags.Publish.TargetTLS ||
		validateTCPPublishOptions(flags.Publish, controlv1.Postgres) != nil {
		t.Fatalf("passthrough unexpectedly required target TLS: %+v", flags.Publish)
	}
	if _, err := parser.Parse([]string{"publish", "db.internal:5432", "--protocol", "postgres", "--database-tls-passthrough"}); err == nil {
		t.Fatal("retired flag was accepted")
	}
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Http, controlv1.Redis, controlv1.Ssh} {
		if err := validateTCPPublishOptions(publishCommand{VisitorTLSPassthrough: true}, protocol); err == nil {
			t.Fatalf("%s accepted database TLS passthrough", protocol)
		}
	}
	for _, invalid := range []publishCommand{
		{VisitorTLSPassthrough: true, TargetTLS: true},
		{VisitorTLSPassthrough: true, TargetTLSName: "db.internal"},
		{VisitorTLSPassthrough: true, tunnelFlags: tunnelFlags{TargetCAFile: "private.pem"}},
	} {
		if err := validateTCPPublishOptions(invalid, controlv1.Postgres); err == nil {
			t.Fatalf("passthrough accepted conflicting target TLS options: %+v", invalid)
		}
	}
}

func TestRedisPublishTargetAndAddress(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publish", "redis:6379", "--protocol", "redis", "--name", "cache"}); err != nil {
		t.Fatal(err)
	}
	if flags.Publish.Target != "redis:6379" || flags.Publish.Protocol != "redis" || flags.Publish.Name != "cache" {
		t.Fatalf("Redis publish flags = %+v", flags.Publish)
	}
	protocol, err := publishProtocol(flags.Publish.Protocol)
	if err != nil || protocol != controlv1.Redis {
		t.Fatalf("Redis protocol = %q, %v", protocol, err)
	}
	if target, err := normalizePublishTarget(flags.Publish.Target, protocol); err != nil || target != "redis:6379" {
		t.Fatalf("Redis private target = %q, %v", target, err)
	}
	if err := validateTCPPublishOptions(flags.Publish, protocol); err != nil {
		t.Fatal(err)
	}
	port := 6379
	if address, err := savedPublicAddress(controlv1.PublicURL{CanonicalHostname: "cache.example", ServiceProtocol: protocol, PublicPort: &port}); err != nil || address != "cache.example:6379" {
		t.Fatalf("Redis public address = %q, %v", address, err)
	}
	if err := validateTCPPublishOptions(publishCommand{TargetTLSName: "redis.internal"}, protocol); err == nil {
		t.Fatal("Redis accepted a target TLS name without target TLS")
	}
}

func TestSSHPublishTargetAndAddress(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"publish", "sshd:22", "--protocol", "ssh", "--name", "shell"}); err != nil {
		t.Fatal(err)
	}
	protocol, err := publishProtocol(flags.Publish.Protocol)
	if err != nil || protocol != controlv1.Ssh {
		t.Fatalf("SSH protocol = %q, %v", protocol, err)
	}
	if target, err := normalizePublishTarget(flags.Publish.Target, protocol); err != nil || target != "sshd:22" {
		t.Fatalf("SSH private target = %q, %v", target, err)
	}
	if err := validateTCPPublishOptions(flags.Publish, protocol); err != nil {
		t.Fatal(err)
	}
	port := 2222
	if address, err := savedPublicAddress(controlv1.PublicURL{CanonicalHostname: "shell.example", ServiceProtocol: protocol, PublicPort: &port}); err != nil || address != "shell.example:2222" {
		t.Fatalf("SSH public address = %q, %v", address, err)
	}
	if err := validateTCPPublishOptions(publishCommand{openOptions: openOptions{Open: true}}, protocol); err == nil {
		t.Fatal("SSH --open was silently ignored")
	}
}

func TestDatabasePublishTargetAndScopedProtocol(t *testing.T) {
	for _, protocol := range []controlv1.PublicURLServiceProtocol{controlv1.Postgres, controlv1.Mysql} {
		if got, err := normalizePublishTarget("db.internal:5432", protocol); err != nil || got != "db.internal:5432" {
			t.Fatalf("%s target = %q, %v", protocol, got, err)
		}
		if got, err := normalizePublishTarget("5432", protocol); err != nil || got != "127.0.0.1:5432" {
			t.Fatalf("%s bare port target = %q, %v", protocol, got, err)
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
	for _, invalid := range []int{1023, 65536} {
		if _, err := savedPublicAddress(controlv1.PublicURL{ServiceProtocol: controlv1.Postgres, PublicPort: &invalid}); err == nil {
			t.Fatalf("out-of-range public port %d was accepted", invalid)
		}
	}
	if _, err := savedPublicAddress(controlv1.PublicURL{ServiceProtocol: "unknown"}); err == nil {
		t.Fatal("unknown public URL protocol was accepted")
	}
	if _, err := savedPublicAddress(controlv1.PublicURL{ServiceProtocol: controlv1.Http, PublicPort: &port}); err == nil {
		t.Fatal("HTTP public URL advertised a database port")
	}
	if got, err := savedPublicAddress(controlv1.PublicURL{CanonicalHostname: "api.example", ServiceProtocol: controlv1.Http}); err != nil || got != "https://api.example" {
		t.Fatalf("HTTP address = %q, %v", got, err)
	}
	if err := validateTCPPublishOptions(publishCommand{TargetTLSName: "db.internal"}, controlv1.Http); err == nil {
		t.Fatal("HTTP accepted database TLS settings")
	}
	if err := validateTCPPublishOptions(publishCommand{TargetTLSName: "db.internal"}, controlv1.Postgres); err == nil {
		t.Fatal("database accepted target TLS name without target TLS")
	}
	if err := validateTCPPublishOptions(publishCommand{openOptions: openOptions{Open: true}}, controlv1.Mysql); err == nil {
		t.Fatal("database --open was silently ignored")
	}
}
