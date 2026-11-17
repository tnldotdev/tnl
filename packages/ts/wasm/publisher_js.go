//go:build js && wasm && !tnlconnector

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"syscall/js"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherOptions struct {
	Credential string `json:"credential"`
	Project    string `json:"project"`
	Deployment string `json:"deployment"`
	Service    string `json:"service,omitempty"`
	Temporary  *struct {
		RequirePostQuantum bool                                    `json:"require_post_quantum,omitempty"`
		AccessMode         controlv1.VisitorAccessMode             `json:"access_mode,omitempty"`
		IP                 []string                                `json:"ip,omitempty"`
		Limits             *controlv1.ProjectHTTPApplicationLimits `json:"limits,omitempty"`
	} `json:"temporary,omitempty"`
}

func (publisherOptions) String() string   { return "private publisher options" }
func (publisherOptions) GoString() string { return "private publisher options" }

func registerPublisher(api js.Value) {
	var functions methodSet
	bind(api, "publish", &functions, func(args []js.Value) (any, error) {
		if len(args) != 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeObject || args[1].IsNull() {
			return nil, errArguments
		}
		return startPublisher(args[0].String(), args[1])
	})
	bind(api, "enrollPublisher", &functions, func(args []js.Value) (any, error) {
		if len(args) != 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeObject || args[1].IsNull() {
			return nil, errArguments
		}
		return openEnrolledPublisher(args[0].String(), args[1])
	})
}

type publisherDeferred struct {
	value, resolve, reject js.Value
	once                   sync.Once
}

func newPublisherDeferred() *publisherDeferred {
	deferred := &publisherDeferred{}
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		deferred.resolve, deferred.reject = args[0], args[1]
		return nil
	})
	deferred.value = js.Global().Get("Promise").New(executor)
	executor.Release()
	// a run can fail immediately after returning its handle. observing this
	// original promise later still rejects, without an unhandled host rejection.
	deferred.value.Call("catch", js.Global().Get("String"))
	return deferred
}

func (d *publisherDeferred) finish(err error) {
	d.once.Do(func() {
		if err == nil {
			d.resolve.Invoke(js.Undefined())
		} else {
			// lifecycle diagnostics can include request-specific facts. do not
			// export them across the host boundary with a signing credential.
			d.reject.Invoke(safeError(err))
		}
	})
}

type publisherOwner struct {
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
	methods methodSet
}

func (p *publisherOwner) close() error {
	p.cancel()
	<-p.done
	return p.err
}

func startPublisher(encoded string, host js.Value) (js.Value, error) {
	return startPublisherUsing(encoded, host, nil)
}

func startPublisherUsing(encoded string, host js.Value, enrolled *enrolledPublisher) (_ js.Value, result error) {
	transferred := false
	if enrolled != nil {
		if !enrolled.begin() {
			return js.Undefined(), errArguments
		}
		defer func() {
			if !transferred {
				enrolled.work.Done()
			}
		}()
	}
	var options publisherOptions
	if len(encoded) > 64<<10 || json.Unmarshal([]byte(encoded), &options, json.RejectUnknownMembers(true)) != nil {
		return js.Undefined(), errArguments
	}
	if enrolled == nil && options.Deployment == "" || options.Service != "" && options.Temporary != nil ||
		enrolled != nil && (options.Service == "" || options.Temporary != nil || options.Credential != "" || options.Project != "" || options.Deployment != "") {
		return js.Undefined(), errArguments
	}
	certificateSource, err := publisherCertificateSource(host)
	if err != nil {
		return js.Undefined(), err
	}
	var credential auth.DeploymentCredential
	server := ""
	if enrolled == nil {
		credential, err = auth.ParseDeploymentCredential(options.Credential)
		if err != nil {
			return js.Undefined(), err
		}
		if err := credential.SelectProject(options.Project); err != nil {
			return js.Undefined(), err
		}
		server = credential.ControlURL
	} else {
		server = enrolled.server
	}
	handler, err := newPublisherFetchHandler(publisherGet(host, "fetch"))
	if err != nil {
		return js.Undefined(), err
	}
	var ctx context.Context
	var cancel context.CancelFunc
	if enrolled == nil {
		ctx, cancel = context.WithDeadline(runtimeContext, credential.Approval.ExpiresAt)
	} else {
		ctx, cancel = context.WithCancel(enrolled.ctx)
	}
	stopHandler := context.AfterFunc(ctx, handler.stop)
	unwatch := func() {}
	defer func() {
		if !transferred {
			cancel()
			unwatch()
			stopHandler()
			result = errors.Join(result, handler.Close())
			result = operationError(ctx, result)
		}
	}()
	storage, err := newPublisherHostStore(publisherGet(host, "storage"), server)
	if err != nil {
		return js.Undefined(), err
	}
	watch, err := publisherSignal(publisherGet(host, "signal"), cancel)
	if err != nil {
		return js.Undefined(), err
	}
	unwatch = watch
	var prepared *publisherdeployment.PreparedHandler
	if enrolled == nil {
		controlFetch := publisherGet(host, "controlFetch")
		if controlFetch.IsUndefined() {
			controlFetch = js.Global().Get("fetch")
		}
		if controlFetch.Type() != js.TypeFunction {
			return js.Undefined(), errArguments
		}
		httpClient := &http.Client{Transport: &fetchTransport{fetch: controlFetch}}
		control, err := clientcontrol.New(server, httpClient, "")
		if err != nil {
			return js.Undefined(), err
		}
		authority, err := clientauthority.New(server, httpClient, "")
		if err != nil {
			return js.Undefined(), err
		}
		private, decodeErr := base64.RawURLEncoding.DecodeString(credential.PrivateKey)
		if decodeErr != nil {
			return js.Undefined(), auth.ErrDeploymentCredential
		}
		defer clear(private)
		preparation := publisherdeployment.HandlerOptions{
			Control: control, Authority: authority, Approval: credential.Approval, Private: ed25519.PrivateKey(private),
			Deployment: options.Deployment, Service: options.Service, Handler: handler,
		}
		if temporary := options.Temporary; temporary != nil {
			preparation.Temporary = &publisherdeployment.TemporaryHandlerOptions{
				RequirePostQuantum: temporary.RequirePostQuantum, AccessMode: temporary.AccessMode, IP: temporary.IP, Limits: temporary.Limits,
			}
		}
		prepared, err = publisherdeployment.PrepareHandler(ctx, preparation)
	} else {
		prepared, err = publisherdeployment.PrepareEnrolledHandler(ctx, enrolled.deployment, enrolled.apps, options.Service, handler)
	}
	if err != nil {
		if prepared != nil {
			err = errors.Join(err, publisherCleanup(ctx, prepared))
		}
		return js.Undefined(), err
	}
	if err := context.Cause(ctx); err != nil {
		return js.Undefined(), errors.Join(err, publisherCleanup(ctx, prepared))
	}
	owner := &publisherOwner{cancel: cancel, done: make(chan struct{})}
	runtimeMu.Lock()
	if runtimeClosed || len(runtimeResources) >= 32 {
		runtimeMu.Unlock()
		return js.Undefined(), errors.Join(errCapacity, publisherCleanup(ctx, prepared))
	}
	runtimeResources[owner] = struct{}{}
	runtimeWork.Add(1)
	runtimeMu.Unlock()
	ready, closed := newPublisherDeferred(), newPublisherDeferred()
	prepared.Config.CertificateStore = storage
	prepared.Config.SuppliedCertificate = certificateSource
	prepared.Config.WebSocketOnly = true
	// the host owns relay TLS; native TLS options cannot cross this boundary.
	prepared.Config.RelayWebSocket = muxsession.WebSocketConnector{}
	prepared.Config.Ready = func() error { ready.finish(nil); return nil }
	handle := js.Global().Get("Object").New()
	handle.Set("url", "https://"+prepared.Service.Endpoint.Hostname)
	prepared.Config.Prepared = func(run controlv1.ServiceRunPreparation) error {
		reference := js.Global().Get("Object").New()
		reference.Set("serviceID", run.ServiceId)
		reference.Set("serviceRunID", run.ServiceRunId)
		reference.Set("runNumber", strconv.FormatInt(run.RunNumber, 10))
		handle.Set("run", js.Global().Get("Object").Call("freeze", reference))
		if run.RunHostname != nil {
			handle.Set("runURL", "https://"+*run.RunHostname)
		}
		return nil
	}
	handle.Set("ready", ready.value)
	handle.Set("closed", closed.value)
	bind(handle, "close", &owner.methods, func(args []js.Value) (any, error) {
		if len(args) != 0 {
			return nil, errArguments
		}
		return nil, owner.close()
	})
	transferred = true
	go func() {
		defer runtimeWork.Done()
		if enrolled != nil {
			defer enrolled.work.Done()
		}
		_, err := publisherWork(func() (js.Value, error) {
			return js.Undefined(), publisherservice.Publish(ctx, prepared.Config)
		})
		if ctx.Err() == context.Canceled && failure.Only(err, context.Canceled) {
			err = nil
		}
		// service.Publish owns and joins its run, including visitor handlers.
		// the host adapter independently fences any late handler invocation.
		err = errors.Join(err, handler.Close(), publisherCleanup(ctx, prepared))
		unwatch()
		stopHandler()
		cancel()
		owner.err = err
		owner.methods.retire()
		runtimeMu.Lock()
		delete(runtimeResources, owner)
		runtimeMu.Unlock()
		ready.finish(errors.Join(err, errors.New("publisher stopped before readiness")))
		closed.finish(err)
		close(owner.done)
	}()
	return handle, nil
}

func publisherCleanup(ctx context.Context, prepared *publisherdeployment.PreparedHandler) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return prepared.Cleanup(cleanup)
}

func publisherSignal(signal js.Value, cancel context.CancelFunc) (func(), error) {
	if signal.IsNull() || signal.IsUndefined() {
		return func() {}, nil
	}
	if !signal.InstanceOf(js.Global().Get("AbortSignal")) {
		return nil, errPublisherHost
	}
	// use the standard signal's operations, not replaceable own getters or
	// methods that can throw after installing a live go callback.
	prototype := js.Global().Get("AbortSignal").Get("prototype")
	aborted := js.Global().Get("Object").Call("getOwnPropertyDescriptor", prototype, "aborted").Get("get")
	target := js.Global().Get("EventTarget").Get("prototype")
	add, remove := publisherGet(target, "addEventListener"), publisherGet(target, "removeEventListener")
	if _, err := publisherJS(func() js.Value { return aborted.Call("call", signal) }); err != nil {
		return nil, err
	}
	listener := js.FuncOf(func(js.Value, []js.Value) any { cancel(); return nil })
	_, err := publisherJS(func() js.Value {
		add.Call("call", signal, "abort", listener)
		if aborted.Call("call", signal).Bool() {
			cancel()
		}
		return js.Undefined()
	})
	if err != nil {
		_, _ = publisherJS(func() js.Value { return remove.Call("call", signal, "abort", listener) })
		listener.Release()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			remove.Call("call", signal, "abort", listener)
			listener.Release()
		})
	}, nil
}
