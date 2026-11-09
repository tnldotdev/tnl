package main

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
	"time"

	clientidentity "github.com/tnldotdev/tnl/internal/client/identity"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type authRegisterCommand struct {
	scopedTeamFlags `embed:""`
	Name            string           `arg:"" name:"name" help:"Application identity name."`
	Visit           []string         `name:"visit" help:"Exact public URL or service ID to visit; repeat for each grant."`
	Publish         []string         `name:"publish" help:"Exact public URL or service ID to publish; repeat for each grant."`
	Allocate        []string         `name:"allocate" help:"Ready domain ID whose authorized HTTP namespace can allocate public URLs; repeat for each grant."`
	Ownership       string           `name:"ownership" enum:"member,team" default:"member" help:"Member-owned or administrator-created team-owned application."`
	ExpiresIn       time.Duration    `name:"expires-in" help:"Optional lifetime for all grants, such as 24h; defaults to no expiry."`
	OutputFile      string           `name:"output-file" type:"path" required:"" help:"Private credential document; identical retries resume setup without replacing a different file."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func applicationRegistrationSpec(flags authRegisterCommand, team string) (clientidentity.RegistrationSpec, error) {
	spec := clientidentity.RegistrationSpec{TeamID: team, Name: flags.Name, Ownership: controlv1.RegisterApplicationRequestOwnership(flags.Ownership), ExpiresIn: flags.ExpiresIn}
	for _, selection := range []struct {
		operation controlv1.ApplicationOperation
		resources []string
	}{{controlv1.ApplicationVisit, flags.Visit}, {controlv1.ApplicationPublish, flags.Publish}, {controlv1.ApplicationAllocate, flags.Allocate}} {
		for _, resource := range selection.resources {
			grant := controlv1.ApplicationGrantInput{Operation: selection.operation}
			switch {
			case selection.operation == controlv1.ApplicationAllocate && opaqueid.Valid(resource, opaqueid.DomainPrefix):
				grant.DomainId = &resource
			case selection.operation != controlv1.ApplicationAllocate && opaqueid.Valid(resource, opaqueid.PublicURLPrefix):
				grant.PublicUrlId = &resource
			case selection.operation != controlv1.ApplicationAllocate && opaqueid.Valid(resource, opaqueid.ServicePrefix):
				grant.ServiceId = &resource
			default:
				return spec, clientidentity.ErrRegistration
			}
			spec.Grants = append(spec.Grants, grant)
		}
	}
	if !spec.Valid() {
		return spec, clientidentity.ErrRegistration
	}
	return spec, nil
}

func runAuthRegister(ctx context.Context, flags authRegisterCommand, output, diagnostics io.Writer) error {
	if _, err := applicationRegistrationSpec(flags, "selected-team"); err != nil {
		return err
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl auth register", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	spec, err := applicationRegistrationSpec(flags, current.Team().Id)
	if err != nil {
		return err
	}
	registered, err := clientidentity.RegisterApplication(ctx, session.Store(), session.Authenticated().Control, flags.OutputFile, spec)
	if err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			File        string                          `json:"file"`
			Application controlv1.RegisteredApplication `json:"application"`
		}{flags.OutputFile, registered})
	}
	return writeHumanFrame(output, "tnl auth register", "ready", "keep this file in server-side secret storage", clioutput.Fields(
		clioutput.Field{Label: "file", Value: flags.OutputFile}, clioutput.Field{Label: "application", Value: registered.ClientId}, clioutput.Field{Label: "grants", Value: strconv.Itoa(len(registered.Grants))},
	))
}
