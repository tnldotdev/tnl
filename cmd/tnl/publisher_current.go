package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type publisherCurrentCommand struct {
	StateDir  string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Local client state directory."`
	ServerURL string           `name:"server" env:"TNL_SERVER" help:"Control URL for the selected publisher."`
	Output    statusOutputMode `name:"output" enum:"human,json" default:"human"`
	Check     bool             `name:"check" help:"Check the publisher's current grant with control."`
}

type publisherCurrentResult struct {
	Source      string `json:"source"`
	ControlURL  string `json:"control_url"`
	PublisherID string `json:"publisher_id"`
	GrantID     string `json:"grant_id"`
	Scope       string `json:"scope"`
	Checked     bool   `json:"checked"`
}

func runPublisherCurrent(ctx context.Context, flags publisherCurrentCommand, output io.Writer) error {
	result := publisherCurrentResult{}
	if path, present := os.LookupEnv("TNL_PUBLISHER_FILE"); present {
		if path == "" {
			return credentialfile.ErrInvalid
		}
		file, err := credentialfile.Read(path)
		if err != nil {
			return err
		}
		if flags.ServerURL != "" && flags.ServerURL != file.ControlURL {
			return credentialfile.ErrInvalid
		}
		result = publisherCurrentResult{Source: "publisher file", ControlURL: file.ControlURL, PublisherID: file.PublisherID, GrantID: file.GrantID, Scope: file.Kind}
		if file.Namespace != nil {
			result.Scope = *file.Namespace
		} else if file.PublicURLID != nil {
			result.Scope = *file.PublicURLID
		} else if file.PrivateServiceID != nil {
			result.Scope = *file.PrivateServiceID
		}
		if flags.Check {
			control, err := controlclient.New(file.ControlURL, nil, "")
			if err != nil {
				return err
			}
			authority, err := authorityclient.New(file.ControlURL, nil, "")
			if err != nil {
				return err
			}
			selected, err := nativeauth.LoadFile(path, file.ControlURL, control, authority)
			if err != nil {
				return err
			}
			if _, err := selected.Access(ctx); err != nil {
				return err
			}
			result.Checked = true
		}
	} else {
		root, err := clientStateRoot(flags.StateDir)
		if err != nil {
			return err
		}
		state, err := clientstate.Open(ctx, root)
		if err != nil {
			return err
		}
		defer state.Close()
		server, err := clientserver.Select(ctx, state, flags.ServerURL)
		if err != nil {
			return err
		}
		profile, err := state.Server(ctx, server)
		if err != nil {
			return err
		}
		saved, found, err := profile.SelectedPublisherIdentity(ctx, "default_namespace", "")
		if err != nil {
			return err
		}
		if !found {
			return nativeauth.ErrSetupRequired
		}
		var identity authorityv1.PublisherEnrollmentResult
		if json.Unmarshal(saved.PublicDocument, &identity) != nil || identity.ClientId == "" || saved.ID != identity.ClientId || identity.Namespace == nil || identity.Kind != "namespace" {
			return nativeauth.ErrScope
		}
		result = publisherCurrentResult{Source: "local profile", ControlURL: server, PublisherID: identity.ClientId, GrantID: identity.GrantId, Scope: *identity.Namespace}
		if flags.Check {
			control, err := controlclient.New(server, nil, "")
			if err != nil {
				return err
			}
			authority, err := authorityclient.New(server, nil, "")
			if err != nil {
				return err
			}
			if _, err := nativeauth.LoadDefaultNamespace(ctx, profile, control, authority); err != nil {
				return err
			}
			result.Checked = true
		}
	}
	if result.PublisherID == "" || result.GrantID == "" || result.Scope == "" {
		return errors.New("selected publisher has no grant scope")
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	state := "configured"
	if result.Checked {
		state = "authorized"
	}
	return writeHumanFrame(output, "tnl publisher current", state, "", clioutput.Fields(
		clioutput.Field{Label: "source", Value: result.Source},
		clioutput.Field{Label: "control URL", Value: result.ControlURL},
		clioutput.Field{Label: "publisher", Value: result.PublisherID},
		clioutput.Field{Label: "grant", Value: result.GrantID},
		clioutput.Field{Label: "scope", Value: result.Scope},
	))
}
