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
		Services: map[string]controlv1.DeploymentService{"web": {Id: "svc_bbbbbbbbbbbbbbbbbbbbbb", Protocol: "http", TrustRevision: 1}, "db": {Id: "svc_cccccccccccccccccccccc", Protocol: "postgres", TrustRevision: 1}}}
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
