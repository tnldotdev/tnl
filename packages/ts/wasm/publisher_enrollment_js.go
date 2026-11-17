//go:build js && wasm

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	EnrollmentKey string `json:"enrollment_key"`
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
	storage, err := newPublisherHostStore(publisherGet(host, "storage"), options.ControlURL)
	if err != nil {
		return js.Undefined(), err
	}
	selectionJSON, err := json.Marshal(options.EnrollmentSelection)
	if err != nil {
		return js.Undefined(), err
	}
	selectionDigest := sha256.Sum256(selectionJSON)
	scope, err := json.Marshal(struct {
		ControlURL          string `json:"control_url"`
		EnrollmentSelection string `json:"enrollment_selection"`
	}{options.ControlURL, hex.EncodeToString(selectionDigest[:])})
	if err != nil {
		return js.Undefined(), err
	}
	files := &publisherHostFiles{host: storage.host, scope: string(scope)}
	fetch := publisherGet(host, "controlFetch")
	if fetch.Type() != js.TypeFunction {
		return js.Undefined(), errArguments
	}
	httpClient := &http.Client{Transport: &fetchTransport{fetch: fetch}}
	control, err := clientcontrol.New(options.ControlURL, httpClient, "")
	if err != nil {
		return js.Undefined(), err
	}
	authority, err := clientauthority.New(options.ControlURL, httpClient, "")
	if err != nil {
		return js.Undefined(), err
	}
	identity, err = publisheridentity.OpenEnrolledIdentity(ctx, files, control, options.EnrollmentSelection, options.EnrollmentKey)
	if err != nil {
		return js.Undefined(), err
	}
	if err := context.Cause(ctx); err != nil {
		return js.Undefined(), err
	}
	deployment, err := publisheridentity.NewDeployment(publisheridentity.NativeControl{Services: control}, control, authority, options.ControlURL, identity.Member, identity.Private)
	if err != nil {
		return js.Undefined(), err
	}
	owner := &enrolledPublisher{ctx: ctx, cancel: cancel, unwatch: unwatch, server: options.ControlURL, identity: identity, deployment: deployment, apps: control}
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
