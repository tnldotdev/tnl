package local

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type sdkPublisher struct {
	instance string
	server   string
	control  *clientcontrol.Client
	identity *publisheridentity.Deployment
	ready    func(publisherprotocol.Endpoint) error
}

type sdkPublisherReady struct {
	Type       string                     `json:"type"`
	Publisher  string                     `json:"publisher_identity_id"`
	Deployment string                     `json:"deployment_id"`
	ControlURL string                     `json:"control_url"`
	Endpoint   publisherprotocol.Endpoint `json:"endpoint"`
}

// ServeSDKPublisher holds the protected slot until the existing app runtime has
// joined all its registered publications. stdin carries bootstrap only on
// request; its EOF is the parent's shutdown signal.
func ServeSDKPublisher(ctx context.Context, options Options, instance, controlURL string, input io.ReadCloser, output io.Writer) (result error) {
	if instance == "" {
		instance = "default"
	}
	if !naming.ValidServiceName(instance) || input == nil || output == nil {
		return publisheridentity.ErrScope
	}
	defer input.Close()
	root := options.StateDir
	if root == "" {
		var err error
		root, err = clientstate.DefaultDir()
		if err != nil {
			return err
		}
	}
	lifetime, stop := context.WithCancel(ctx)
	defer stop()
	open, stopOpen := context.WithTimeout(lifetime, 30*time.Second)
	defer stopOpen()
	state, err := clientstate.Open(open, root)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, state.Close()) }()
	files, err := state.PublisherEnrollmentFiles(instance)
	if err != nil {
		return err
	}
	var control *clientcontrol.Client
	reader := bufio.NewReaderSize(input, 2048)
	writer := json.NewEncoder(output)
	watchInput := sync.OnceFunc(func() {
		go func() {
			// no further commands or secrets are accepted after enrollment.
			_, _ = reader.ReadByte()
			stop()
		}()
	})
	identity, err := publisheridentity.OpenPublisherIdentity(open, files, func(server string) (publisheridentity.EnrollmentControl, error) {
		client, clientErr := clientcontrol.New(server, nil, "")
		if clientErr != nil {
			return nil, clientErr
		}
		control = client
		return control, nil
	}, publisheridentity.EnrollmentSelection{ControlURL: controlURL, Instance: instance}, func(context.Context) (string, error) {
		if err := writer.Encode(struct {
			Type string `json:"type"`
		}{"enrollment"}); err != nil {
			return "", err
		}
		read := make(chan string, 1)
		go func() {
			line, err := reader.ReadSlice('\n')
			var key string
			if err != nil || json.Unmarshal(line, &key) != nil {
				key = ""
			}
			clear(line)
			read <- key
		}()
		select {
		case key := <-read:
			if key == "" {
				return "", publisheridentity.ErrScope
			}
			watchInput()
			return key, nil
		case <-open.Done():
			return "", context.Cause(open)
		}
	})
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, identity.Close()) }()
	authority, err := clientauthority.New(identity.Server, nil, "")
	if err != nil {
		return err
	}
	deployment, err := publisheridentity.NewDeployment(publisheridentity.NativeControl{Services: control}, control, authority, identity.Server, identity.Member, identity.Private)
	if err != nil {
		return err
	}
	stopOpen()
	watchInput()
	if err := context.Cause(lifetime); err != nil {
		return err
	}
	options.Publications, options.StateDir = true, state.Root()
	options.sdkPublisher = &sdkPublisher{instance: instance, server: identity.Server, control: control, identity: deployment, ready: func(endpoint publisherprotocol.Endpoint) error {
		return writer.Encode(sdkPublisherReady{"ready", identity.Member.PublisherIdentityId, identity.Member.DeploymentId, identity.Server, endpoint})
	}}
	return Serve(lifetime, options)
}

func (a *appRuntime) prepareEnrolledInvocation(ctx context.Context, r publisherprotocol.Invocation) (result deploymentInvocation, err error) {
	owner := a.sdkPublisher
	if owner == nil || r.Deployment != nil || r.ServerUrl != nil || r.PublisherCredentialFile != "" || r.Public != nil ||
		r.PublisherIdentityId != "" || r.AccessMode != nil || r.Ip != nil || r.Limits != nil || r.RequirePostQuantum != nil {
		return result, publisheridentity.ErrScope
	}
	native, service, err := owner.identity.HTTPApp(ctx, owner.control, r.EnrolledService)
	if err != nil {
		return result, err
	}
	if service.Protocol != controlv1.ServiceProtocolHTTP || service.Endpoint == nil ||
		!serviceendpoint.Valid("http", service.Endpoint.Hostname, service.Endpoint.Port, service.Endpoint.Public) {
		return result, publisheridentity.ErrScope
	}
	target, err := targetsyntax.ParseCanonicalTarget(r.Target)
	if err != nil {
		return result, err
	}
	trust, err := publisheridentity.ServiceTrust(service)
	if err != nil {
		return result, err
	}
	if (target.Scheme == "https") != (trust != nil) {
		return result, publisheridentity.ErrScope
	}
	profile, err := a.state.Server(ctx, owner.server)
	if err != nil {
		return result, err
	}
	discovery, err := owner.control.Discovery(ctx)
	if err != nil {
		return result, err
	}
	browserLogin := discovery.BrowserLoginAvailable != nil && *discovery.BrowserLoginAvailable
	result.native, result.service = native, service
	result.config = publisherservice.RunConfig{Control: native, Access: native.Access, State: profile,
		PublisherIdentityID: native.PublisherIdentityID(), PublisherGrantID: native.PublisherGrantID(), PublisherKeyID: native.PublisherKeyID(),
		ServiceID: service.Id, Target: target.Host, Metadata: publisheridentity.ServiceMetadata(service), BrowserLoginAvailable: &browserLogin}
	return result, nil
}
