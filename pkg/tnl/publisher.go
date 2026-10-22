package tnl

import (
	"context"
	"errors"
	"net/http"
	"os"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
)

// PublisherIdentity holds one signing identity and selected namespace grant.
// prepare it once to reuse it across independent ad-hoc invocations.
type PublisherIdentity struct {
	value *publisheridentity.Native
}

type StateProtection string

const (
	ProtectionFile     StateProtection = "file"
	ProtectionKeychain StateProtection = "keychain"
)

var ErrPublisherScope = publisheridentity.ErrScope
var ErrPublisherSelection = publisheridentity.ErrSelection

// PreparePublisherIdentity loads a selected namespace identity
// using protected local state. it closes the database before returning; Open
// opens its own certificate state for the duration of each publication.
func PreparePublisherIdentity(ctx context.Context, options Options) (*PublisherIdentity, error) {
	state, _, _, publisher, err := preparePublisher(ctx, options)
	if err != nil {
		return nil, err
	}
	if err := state.Close(); err != nil {
		return nil, err
	}
	return &PublisherIdentity{value: publisher}, nil
}

func preparePublisher(ctx context.Context, options Options) (*clientstate.Database, *clientstate.Store, string, *publisheridentity.Native, error) {
	selected := 0
	if options.EnrollmentKey != "" {
		selected++
	}
	if options.PublisherIdentityID != "" {
		selected++
	}
	if options.PublisherIdentity != nil {
		selected++
	}
	if options.PublisherCredentialFile != "" {
		selected++
	}
	if selected > 1 {
		return nil, nil, "", nil, ErrPublisherSelection
	}
	server := options.ServerURL
	if options.PublisherIdentity != nil {
		if options.PublisherIdentity.value == nil {
			return nil, nil, "", nil, ErrPublisherScope
		}
		origin := options.PublisherIdentity.value.ControlURL()
		if origin == "" {
			return nil, nil, "", nil, ErrPublisherScope
		}
		if server != "" {
			canonical, err := clientstate.CanonicalServer(server)
			if err != nil || canonical != origin {
				return nil, nil, "", nil, ErrPublisherScope
			}
		}
		server = origin
	} else if server == "" {
		server = os.Getenv("TNL_SERVER")
	}
	root := options.StateDir
	if root == "" {
		root = os.Getenv("TNL_STATE_DIR")
	}
	if root == "" {
		var err error
		root, err = clientstate.DefaultDir()
		if err != nil {
			return nil, nil, "", nil, err
		}
	}
	database, err := clientstate.OpenWithOptions(ctx, root, clientstate.OpenOptions{Protection: clientstate.ProtectionMode(options.StateProtection)})
	if err != nil {
		return nil, nil, "", nil, err
	}
	fail := func(err error) (*clientstate.Database, *clientstate.Store, string, *publisheridentity.Native, error) {
		return nil, nil, "", nil, errors.Join(err, database.Close())
	}
	server, err = clientserver.Select(ctx, database, server)
	if err != nil {
		return fail(err)
	}
	profile, err := database.Server(ctx, server)
	if err != nil {
		return fail(err)
	}
	control, authority, err := publisherClients(server, options.HTTPClient)
	if err != nil {
		return fail(err)
	}
	var selectedIdentity *publisheridentity.Native
	if options.PublisherIdentity != nil {
		selectedIdentity = options.PublisherIdentity.value
	}
	native, err := publisheridentity.ResolveAdHoc(ctx, profile, control, authority, server, "", "", "", options.PublisherCredentialFile, options.EnrollmentKey, options.PublisherIdentityID, selectedIdentity)
	if err != nil {
		return fail(err)
	}
	if err := native.NamespaceScope(); err != nil {
		return fail(err)
	}
	return database, profile, server, native, nil
}

func publisherClients(server string, httpClient *http.Client) (*clientcontrol.Client, *clientauthority.Client, error) {
	control, err := clientcontrol.New(server, httpClient, "")
	if err != nil {
		return nil, nil, err
	}
	authority, err := clientauthority.New(server, httpClient, "")
	return control, authority, err
}
