package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDeploymentCommandsCaptureExplicitProjectAndTeam(t *testing.T) {
	for _, args := range [][]string{
		{"deployment", "create", "customer", "--target", "db=orders.us-east-1.rds.amazonaws.com:5432", "--target-tls", "db=aws-rds", "--idempotency-key", "customer-setup"},
		{"deployment", "list", "--after", "dpl_aaaaaaaaaaaaaaaaaaaaaa", "--limit", "1"},
		{"deployment", "show", "production"},
		{"deployment", "update", "production", "--target", "db=replacement.internal:5432"},
		{"deployment", "delete", "production"},
	} {
		var flags cli
		parser, err := kong.New(&flags, kong.Writers(io.Discard, io.Discard))
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, "--project-key", "shop", "--team", "acme", "--output", "json")
		parsed, err := parser.Parse(args)
		if err != nil {
			t.Fatal(err)
		}
		selected := selectedDeploymentFlags(parsed.Command(), &flags)
		if selected == nil || selected.ProjectKey != "shop" || selected.Team != "acme" || selected.Output != statusOutputJSON {
			t.Fatal("deployment selection was lost")
		}
		configured := "project-team"
		project := projectConfiguration{}
		project.Config.Team = &configured
		if err = applyProjectCommandContext(parsed.Command(), project, &flags); err != nil {
			t.Fatal(err)
		}
		if selection := selected.selection(); selection.SelectedTeam != "acme" || selection.ProjectTeam != configured {
			t.Fatal("explicit team did not override the configured team")
		}
	}
}

func TestDeploymentTargetFlagsUseCanonicalVerifiedTLS(t *testing.T) {
	targets, err := deploymentTargets(deploymentTargetFlags{Target: []string{"db=orders.us-east-1.rds.amazonaws.com:5432", "web=http://app.internal:3000"}, TargetTLS: []string{"db=aws-rds"}, TargetTLSHostname: []string{"db=orders.us-east-1.rds.amazonaws.com"}})
	if err != nil || len(targets) != 2 || targets["db"].Tls == nil || targets["db"].Tls.Ca == nil || *targets["db"].Tls.Ca != "aws-rds" || targets["web"].Tls != nil {
		t.Fatal("canonical target TLS selection was changed", err)
	}
	for _, flags := range []deploymentTargetFlags{
		{}, {Target: []string{"db=one:5432", "db=two:5432"}}, {Target: []string{"db="}},
		{Target: []string{"db=db:5432"}, TargetTLS: []string{"web=system"}},
		{Target: []string{"db=db:5432"}, TargetTLS: []string{"db=insecure"}},
		{Target: []string{"db=db:5432"}, TargetTLS: []string{"db=system", "db=aws-rds"}},
		{Target: []string{"db=db:5432"}, TargetTLSHostname: []string{"web=other.internal"}},
		{Target: []string{"db=private\nsecret:5432"}},
	} {
		_, err := deploymentTargets(flags)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags || strings.Contains(err.Error(), "private\nsecret") {
			t.Fatal("invalid target lost classification or exposed raw input", err)
		}
	}
}

func TestDeploymentReadRejectsCrossScopeAndRendersDeterministically(t *testing.T) {
	deployment := controlv1.Deployment{Id: "dpl_aaaaaaaaaaaaaaaaaaaaaa", TeamId: "team-selected", ProjectKey: "shop", Name: "production", Revision: 7,
		Services: map[string]controlv1.DeploymentService{
			"web": {Id: "url_bbbbbbbbbbbbbbbbbbbbbb", Protocol: "http", TrustRevision: 1, PublicUrl: new("https://web.example.test")},
			"db":  {Id: "svc_cccccccccccccccccccccc", Protocol: "postgres", TrustRevision: 1, Endpoint: &controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: 5432}},
		}}
	if err := validateDeploymentResult(deployment, deployment.TeamId, deployment.ProjectKey); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*controlv1.Deployment){
		func(d *controlv1.Deployment) { d.TeamId = "another-team" }, func(d *controlv1.Deployment) { d.ProjectKey = "other" },
		func(d *controlv1.Deployment) { d.Id = "invalid" }, func(d *controlv1.Deployment) { d.Revision = 0 },
	} {
		changed := deployment
		mutate(&changed)
		if reason, ok := failure.ReasonOf(validateDeploymentResult(changed, deployment.TeamId, deployment.ProjectKey)); !ok || reason != failure.ServerResponseInvalid {
			t.Fatal("invalid deployment response escaped its boundary")
		}
	}
	var output bytes.Buffer
	if err := writeHumanFrame(&output, "tnl deployment show", "saved", "", deploymentBlock(deployment)); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "db") || !strings.Contains(text, "web") || strings.Index(text, "db") > strings.Index(text, "web") {
		t.Fatal("service presentation depends on map order")
	}
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 72 {
			t.Fatal("deployment output exceeded the shared renderer's width")
		}
	}
}

func TestDeploymentReadValidatesPublicURLAndServiceBindingShapes(t *testing.T) {
	saved := controlv1.DeploymentService{Id: "url_bbbbbbbbbbbbbbbbbbbbbb", Protocol: "http", TrustRevision: 1, PublicUrl: new("https://web.example.test")}
	private := controlv1.DeploymentService{Id: "svc_cccccccccccccccccccccc", Protocol: "postgres", TrustRevision: 1}
	for _, service := range []controlv1.DeploymentService{
		saved, private,
		{Id: private.Id, Protocol: "http", TrustRevision: 2},
		{Id: private.Id, Protocol: "tcp", TrustRevision: 2, Endpoint: &controlv1.ServiceEndpoint{Hostname: "tcp.example.test", Port: 1024}},
		{Id: private.Id, Protocol: "mysql", TrustRevision: 2, Endpoint: &controlv1.ServiceEndpoint{Hostname: "mysql.example.test", Port: 65535, Public: true}},
	} {
		deployment := controlv1.Deployment{Id: "dpl_aaaaaaaaaaaaaaaaaaaaaa", TeamId: "team-selected", ProjectKey: "shop", Name: "production", Revision: 1, Services: map[string]controlv1.DeploymentService{"selected": service}}
		if err := validateDeploymentResult(deployment, deployment.TeamId, deployment.ProjectKey); err != nil {
			t.Fatal("canonical binding was rejected", err)
		}
	}
	for name, mutate := range map[string]func(*controlv1.DeploymentService){
		"url service ID": func(s *controlv1.DeploymentService) { s.Id = private.Id },
		"url invalid ID": func(s *controlv1.DeploymentService) { s.Id = "url_invalid" },
		"url not HTTP":   func(s *controlv1.DeploymentService) { s.Protocol = "postgres" },
		"url endpoint": func(s *controlv1.DeploymentService) {
			s.Endpoint = &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443}
		},
		"url absent":       func(s *controlv1.DeploymentService) { s.PublicUrl = nil },
		"url revision":     func(s *controlv1.DeploymentService) { s.TrustRevision = 0 },
		"service URL ID":   func(s *controlv1.DeploymentService) { *s = private; s.Id = saved.Id },
		"service protocol": func(s *controlv1.DeploymentService) { *s = private; s.Protocol = "invalid" },
		"service URL":      func(s *controlv1.DeploymentService) { *s = private; s.PublicUrl = saved.PublicUrl },
		"endpoint empty": func(s *controlv1.DeploymentService) {
			*s = private
			s.Endpoint = &controlv1.ServiceEndpoint{Port: 5432}
		},
		"endpoint case": func(s *controlv1.DeploymentService) {
			*s = private
			s.Endpoint = &controlv1.ServiceEndpoint{Hostname: "DB.example.test", Port: 5432}
		},
		"endpoint IP": func(s *controlv1.DeploymentService) {
			*s = private
			s.Endpoint = &controlv1.ServiceEndpoint{Hostname: "127.0.0.1", Port: 5432}
		},
		"endpoint port": func(s *controlv1.DeploymentService) {
			*s = private
			s.Endpoint = &controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: 1023}
		},
		"endpoint bounds": func(s *controlv1.DeploymentService) {
			*s = private
			s.Endpoint = &controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: 65536}
		},
	} {
		t.Run(name, func(t *testing.T) {
			service := saved
			mutate(&service)
			deployment := controlv1.Deployment{Id: "dpl_aaaaaaaaaaaaaaaaaaaaaa", TeamId: "team-selected", ProjectKey: "shop", Name: "production", Revision: 1, Services: map[string]controlv1.DeploymentService{"selected": service}}
			if reason, ok := failure.ReasonOf(validateDeploymentResult(deployment, deployment.TeamId, deployment.ProjectKey)); !ok || reason != failure.ServerResponseInvalid {
				t.Fatal("invalid binding escaped its response boundary")
			}
		})
	}
	for _, value := range []string{"", "web.example.test", "http://web.example.test", "https://WEB.example.test", "https://web.example.test.", "https://web.example.test:443", "https://web.example.test/", "https://web.example.test/path", "https://web.example.test?query", "https://web.example.test#fragment", "https://user@web.example.test", "https://127.0.0.1", "https://*.example.test", "https://web.example.test\nsecret"} {
		t.Run(value, func(t *testing.T) {
			service := saved
			service.PublicUrl = &value
			if validDeploymentService(service) {
				t.Fatal("noncanonical public URL was accepted")
			}
		})
	}
}
