package connector

import (
	"context"
	"path/filepath"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
)

// prepare from the already-owned source, not a new federation exchange. only the
// private caller gets this document; metadata and registry records never retain it.
func (b *connectorConnectionBackend) PrepareApplication(ctx context.Context, assertion string) (connectorruntime.PreparedApplication, error) {
	ctx, finish, err := b.begin(ctx)
	if err != nil {
		return connectorruntime.PreparedApplication{}, err
	}
	defer finish()
	if assertion != "" {
		if err := b.UseAssertion(ctx, assertion); err != nil {
			return connectorruntime.PreparedApplication{}, err
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.workload == nil {
		return connectorruntime.PreparedApplication{}, connectorruntime.ErrUnauthorized
	}
	session, err := b.workload.Session()
	if err != nil {
		return connectorruntime.PreparedApplication{}, err
	}
	proof := b.verification
	if assertion != "" {
		verified, ok := b.assertions[sdkDigest(assertion)]
		if !ok {
			return connectorruntime.PreparedApplication{}, connectorruntime.ErrUnauthorized
		}
		proof = &verified.proof
	}
	if proof == nil || b.verifiedSession != session.Id || !proof.ExpiresAt.After(time.Now()) {
		return connectorruntime.PreparedApplication{}, connectorruntime.ErrUnauthorized
	}
	document, err := b.workload.PrepareApplication()
	if err != nil {
		return connectorruntime.PreparedApplication{}, err
	}
	verification := *proof
	return connectorruntime.PreparedApplication{Schema: 1, Credential: document, SourceSessionID: session.Id, LeaseExpiresAt: session.LeaseExpiresAt, Verification: &verification}, nil
}

func applicationSnapshot(ctx context.Context, owner connectorruntime.Status, assertion string) (connectorruntime.PreparedApplication, error) {
	handle, err := connectorruntime.ReadHandle(owner.ConnectionHandle)
	if err != nil {
		return connectorruntime.PreparedApplication{}, err
	}
	var result connectorruntime.PreparedApplication
	err = connectorruntime.Call(ctx, owner.ConnectionHandle, "application", connectorruntime.Request{Schema: 1, Directory: handle.Directory, ConfigDigest: handle.ConfigDigest, Assertion: assertion}, &result)
	return result, err
}

// refresh only this owner. request credentials must prove the existing binding;
// they cannot switch a live publication to another source session.
func (b *connectorConnectionBackend) Application(ctx context.Context, request connectorruntime.Request) (connectorruntime.PreparedApplication, error) {
	ctx, finish, err := b.begin(ctx)
	if err != nil {
		return connectorruntime.PreparedApplication{}, err
	}
	defer finish()
	if request.SDKWorkload == nil {
		return b.PrepareApplication(ctx, request.Assertion)
	}
	selected, source, err := selectSDKWorkload(b.scope.Directory, "", *request.SDKWorkload)
	if err != nil {
		return connectorruntime.PreparedApplication{}, err
	}
	if selected.Policy != b.scope.ConfigDigest || selected.Policy != request.SDKWorkloadPolicy || selected.Name != b.scope.Workload {
		return connectorruntime.PreparedApplication{}, connectorruntime.ErrUnauthorized
	}
	environment := connectorruntime.SDKEnvironment{}
	if request.SDKEnvironment != nil {
		environment = *request.SDKEnvironment
	}
	assertion, err := acquireSDKWorkload(ctx, selected, source, *request.SDKWorkload, environment, request.Assertion)
	if err != nil {
		return connectorruntime.PreparedApplication{}, err
	}
	return b.PrepareApplication(ctx, assertion)
}

func (b *connectorConnectionBackend) SDKApplication(ctx context.Context, request connectorruntime.Request) (connectorruntime.SDKApplication, error) {
	if b.sdk == nil {
		return connectorruntime.SDKApplication{}, connectorruntime.ErrInvalid
	}
	ctx, finish, err := b.begin(ctx)
	if err != nil {
		return connectorruntime.SDKApplication{}, err
	}
	defer finish()
	options := *b.sdk
	options.Workload, options.Manifest = request.Workload, request.Manifest
	options.WorkloadSelection, options.WorkloadPolicy, options.Environment = request.SDKWorkload, request.SDKWorkloadPolicy, request.SDKEnvironment
	options.Service = ""
	options.RequestedAt, options.RequestHandle = request.RequestedAt, request.SDKRequestHandle
	options.ContextOptions.Service = nil
	operations := nativeSDKOperations()
	remote := operations.application
	operations.application = func(ctx context.Context, owner connectorruntime.Status, assertion string) (connectorruntime.PreparedApplication, error) {
		if owner.ConnectionHandle != filepath.Join(b.directory, "handle.json") {
			return remote(ctx, owner, assertion)
		}
		return b.PrepareApplication(ctx, assertion)
	}
	return operations.selectSDKApplication(ctx, options, request.Assertion)
}
