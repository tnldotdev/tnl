package main

import (
	"context"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// startDeployedPublisher belongs to the foreground publication, after preflight.
// installed jobs and named groups own this boundary in their runtime loops.
func startDeployedPublisher(ctx context.Context, n *nativeauth.Native, server string) (func(), error) {
	runtime, err := n.RemoteRuntime(server)
	if err != nil {
		return nil, err
	}
	if _, err = runtime.Renew(ctx); err != nil {
		return nil, err
	}
	n.WithRuntime(runtime)
	return func() {
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Stop(finish)
	}, nil
}

func publisherRuntimeFields(r *controlv1.PublisherRuntimeStatus) []clioutput.Field {
	if r == nil {
		return []clioutput.Field{{Label: "runtime", Value: "not observed"}}
	}
	state, address := "offline", "unknown (no public address observed)"
	if r.Active {
		state = "active"
	}
	if r.Address != nil {
		address = *r.Address + " (" + string(r.AddressFamily) + ")"
	}
	fields := []clioutput.Field{
		{Label: "runtime", Value: state}, {Label: "process run", Value: r.ProcessRunId},
		{Label: "runtime epoch", Value: strconv.FormatInt(r.Epoch, 10)},
		{Label: "control observed egress", Value: address},
		{Label: "observed at", Value: r.ObservedAt.UTC().Format(time.RFC3339)},
		{Label: "last seen", Value: r.LastSeenAt.UTC().Format(time.RFC3339)},
		{Label: "lease expires", Value: r.LeaseExpiresAt.UTC().Format(time.RFC3339)},
	}
	if d := r.Deployment; d != nil {
		fields = append(fields,
			clioutput.Field{Label: "deployment evidence", Value: string(d.Evidence)},
			clioutput.Field{Label: "deployment", Value: d.Report.DeploymentId},
			clioutput.Field{Label: "group ID", Value: d.GroupId},
			clioutput.Field{Label: "replica", Value: d.Report.ReplicaKey},
			clioutput.Field{Label: "instance", Value: d.Report.Instance},
			clioutput.Field{Label: "provider", Value: string(d.Report.Provider)},
			clioutput.Field{Label: "reported image", Value: d.Report.Image},
			clioutput.Field{Label: "software version", Value: d.Report.SoftwareVersion},
			clioutput.Field{Label: "template version", Value: d.Report.TemplateVersion},
			clioutput.Field{Label: "template sha256", Value: d.Report.TemplateSha256},
			clioutput.Field{Label: "first reported", Value: d.FirstObservedAt.UTC().Format(time.RFC3339)},
			clioutput.Field{Label: "last reported", Value: d.ObservedAt.UTC().Format(time.RFC3339)},
		)
	}
	return fields
}
