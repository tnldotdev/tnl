//go:build js && wasm && !tnlconnector

package main

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"net/http"
	"sync"
	"syscall/js"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
)

type publisherEnrollmentOptions struct {
	publisheridentity.EnrollmentSelection
}

type enrolledPublisher struct {
	ctx        context.Context
	cancel     context.CancelFunc
	unwatch    func()
	server     string
	identity   *publisheridentity.EnrolledIdentity
	deployment *publisheridentity.Deployment
	apps       publisheridentity.DeploymentAppControl
	methods    methodSet
	mu         sync.Mutex
	stopped    bool
	work       sync.WaitGroup
	once       sync.Once
	err        error
}

func (p *enrolledPublisher) begin() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped || p.ctx.Err() != nil {
		return false
	}
	p.work.Add(1)
	return true
}

func (p *enrolledPublisher) close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.stopped = true
		p.cancel()
		p.mu.Unlock()
		p.work.Wait()
		p.unwatch()
		p.err = p.identity.Close()
		p.methods.retire()
		runtimeMu.Lock()
		delete(runtimeResources, p)
		runtimeMu.Unlock()
	})
	return p.err
}

func openEnrolledPublisher(encoded string, host js.Value) (_ js.Value, result error) {
	var options publisherEnrollmentOptions
	if len(encoded) > 4096 || json.Unmarshal([]byte(encoded), &options, json.RejectUnknownMembers(true)) != nil {
		return js.Undefined(), errArguments
	}
	ctx, cancel := context.WithCancel(runtimeContext)
	unwatch, err := publisherSignal(publisherGet(host, "signal"), cancel)
	if err != nil {
		cancel()
		return js.Undefined(), err
	}
	var identity *publisheridentity.EnrolledIdentity
	retained := false
	defer func() {
		if !retained {
			cancel()
			unwatch()
			if identity != nil {
				result = errors.Join(result, identity.Close())
			}
			result = operationError(ctx, result)
		}
	}()
	storage := publisherGet(host, "storage")
	if storage.Type() != js.TypeObject || storage.IsNull() {
		return js.Undefined(), errArguments
	}
	scope, err := json.Marshal(struct {
		PublisherSlot string `json:"publisher_slot"`
	}{options.Instance})
	if err != nil {
		return js.Undefined(), err
	}
	files := &publisherHostFiles{host: storage, scope: string(scope)}
	fetch := publisherGet(host, "controlFetch")
	if fetch.Type() != js.TypeFunction {
		return js.Undefined(), errArguments
	}
	httpClient := &http.Client{Transport: &fetchTransport{fetch: fetch}}
	var control *clientcontrol.Client
	identity, err = publisheridentity.OpenPublisherIdentity(ctx, files, func(server string) (publisheridentity.EnrollmentControl, error) {
		var err error
		control, err = clientcontrol.New(server, httpClient, "")
		return control, err
	}, options.EnrollmentSelection, func(ctx context.Context) (string, error) {
		source, err := publisherJS(func() js.Value { return publisherGet(host, "enrollment") })
		if err != nil || source.Type() != js.TypeFunction {
			return "", errArguments
		}
		pending, err := publisherJS(func() js.Value { return source.Invoke() })
		if err != nil {
			return "", err
		}
		value, err := publisherAwait(ctx, pending, nil)
		if err != nil {
			return "", err
		}
		if value.Type() != js.TypeString {
			return "", errArguments
		}
		secret := value.String()
		if len(secret) == 0 || len(secret) > 256 {
			return "", errArguments
		}
		return secret, nil
	})
	if err != nil {
		return js.Undefined(), err
	}
	authority, err := clientauthority.New(identity.Server, httpClient, "")
	if err != nil {
		return js.Undefined(), err
	}
	if err := context.Cause(ctx); err != nil {
		return js.Undefined(), err
	}
	deployment, err := publisheridentity.NewDeployment(publisheridentity.NativeControl{Services: control}, control, authority, identity.Server, identity.Member, identity.Private)
	if err != nil {
		return js.Undefined(), err
	}
	owner := &enrolledPublisher{ctx: ctx, cancel: cancel, unwatch: unwatch, server: identity.Server, identity: identity, deployment: deployment, apps: control}
	runtimeMu.Lock()
	if runtimeClosed || len(runtimeResources) >= 32 {
		runtimeMu.Unlock()
		return js.Undefined(), errCapacity
	}
	runtimeResources[owner] = struct{}{}
	runtimeMu.Unlock()
	handle := js.Global().Get("Object").New()
	handle.Set("publisherIdentityID", identity.Member.PublisherIdentityId)
	handle.Set("deploymentID", identity.Member.DeploymentId)
	handle.Set("controlUrl", identity.Server)
	bind(handle, "publish", &owner.methods, func(args []js.Value) (any, error) {
		if len(args) != 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeObject || args[1].IsNull() {
			return nil, errArguments
		}
		return startPublisherUsing(args[0].String(), args[1], owner)
	})
	bind(handle, "close", &owner.methods, func(args []js.Value) (any, error) {
		if len(args) != 0 {
			return nil, errArguments
		}
		return nil, owner.close()
	})
	retained = true
	return handle, nil
}
