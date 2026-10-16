package tnl

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
)

// Publisher is a locally held signing identity and one selected grant. prepare
// one once to reuse it across independent Go ad-hoc invocations.
type Publisher = nativeauth.Native

type StateProtection string

const (
	ProtectionFile     StateProtection = "file"
	ProtectionKeychain StateProtection = "keychain"
)

var ErrPublisherScope = nativeauth.ErrScope
var ErrPublisherSelection = nativeauth.ErrSelection

// PreparePublisher loads a selected namespace identity
// using protected local state. it closes the database before returning; Open
// opens its own certificate state for the duration of each publication.
func PreparePublisher(ctx context.Context, options Options) (*Publisher, error) {
	state, _, _, publisher, err := preparePublisher(ctx, options)
	if err != nil {
		return nil, err
	}
	if err := state.Close(); err != nil {
		return nil, err
	}
	return publisher, nil
}

func preparePublisher(ctx context.Context, options Options) (*clientstate.Database, *clientstate.Store, string, *nativeauth.Native, error) {
	selected := 0
	if options.EnrollmentKey != "" {
		selected++
	}
	if options.PublisherID != "" {
		selected++
	}
	if options.Publisher != nil {
		selected++
	}
	if options.PublisherFile != "" {
		selected++
	}
	if selected > 1 {
		return nil, nil, "", nil, ErrPublisherSelection
	}
	server := options.ServerURL
	if options.Publisher != nil {
		origin := options.Publisher.ControlURL()
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
	fail := func(err error) (*clientstate.Database, *clientstate.Store, string, *nativeauth.Native, error) {
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
	native, err := nativeauth.ResolveAdHoc(ctx, profile, control, authority, server, "", "", "", options.PublisherFile, options.EnrollmentKey, options.PublisherID, options.Publisher)
	if err != nil {
		return fail(err)
	}
	if err := native.NamespaceScope(); err != nil {
		return fail(err)
	}
	return database, profile, server, native, nil
}

func publisherClients(server string, httpClient *http.Client) (*controlclient.Client, *authorityclient.Client, error) {
	control, err := controlclient.New(server, httpClient, "")
	if err != nil {
		return nil, nil, err
	}
	authority, err := authorityclient.New(server, httpClient, "")
	return control, authority, err
}
