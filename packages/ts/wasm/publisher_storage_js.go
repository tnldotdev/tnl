//go:build js && wasm && !tnlconnector

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"syscall/js"

	"github.com/tnldotdev/tnl/internal/client/state/certificatestore"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const publisherStorageMaxBytes = 16 << 20

type publisherHostStore struct {
	host       js.Value
	controlURL string
}

func newPublisherHostStore(host js.Value, controlURL string) (*publisherHostStore, error) {
	if host.Type() != js.TypeObject || host.IsNull() {
		return nil, publisherStorageError(errPublisherHost)
	}
	// property access can execute a host getter. validate both its result and
	// exceptions without exposing provider values or messages.
	validated, err := publisherJS(func() js.Value {
		for _, method := range []string{"read", "write", "sync", "lock"} {
			if publisherGet(host, method).Type() != js.TypeFunction {
				return js.Undefined()
			}
		}
		return host
	})
	if err != nil || validated.IsUndefined() {
		return nil, publisherStorageError(errPublisherHost)
	}
	return &publisherHostStore{host: validated, controlURL: controlURL}, nil
}

func (s *publisherHostStore) CertificatesForPublisher(team, publisher string, plan controlv1.CertificatePlan) (*certificatestore.CertificateCache, error) {
	scope := certificatestore.Scope{ControlURL: s.controlURL, TeamID: team, PublisherIdentityID: publisher}
	encoded, err := json.Marshal(scope)
	if err != nil {
		return nil, publisherStorageError(err)
	}
	files := &publisherHostFiles{host: s.host, scope: string(encoded)}
	return certificatestore.New(files, scope, plan)
}

type publisherHostFiles struct {
	host  js.Value
	scope string
}

func publisherStorageError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return failure.Wrap("use publisher host storage", failure.PublisherIdentityStateUnavailable, errPublisherHost)
}

func publisherStorageInput(ctx context.Context, key string) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if key == "" || len(key) > 1024 || strings.ContainsRune(key, '\x00') {
		return publisherStorageError(errPublisherHost)
	}
	return nil
}

func (s *publisherHostFiles) call(ctx context.Context, method string, values ...any) (js.Value, error) {
	if err := context.Cause(ctx); err != nil {
		return js.Undefined(), err
	}
	abort, err := publisherJS(func() js.Value { return js.Global().Get("AbortController").New() })
	if err != nil {
		return js.Undefined(), publisherStorageError(err)
	}
	pending, err := publisherJS(func() js.Value {
		args := append([]any{s.scope}, values...)
		args = append(args, abort.Get("signal"))
		return s.host.Call(method, args...)
	})
	if err != nil {
		return js.Undefined(), publisherStorageError(err)
	}
	value, err := publisherAwait(ctx, pending, func() {
		_, _ = publisherJS(func() js.Value { return abort.Call("abort") })
	})
	return value, publisherStorageError(errors.Join(err, context.Cause(ctx)))
}

func (s *publisherHostFiles) Read(ctx context.Context, key string, limit int64) ([]byte, bool, error) {
	if err := publisherStorageInput(ctx, key); err != nil {
		return nil, false, err
	}
	if limit < 0 || limit > publisherStorageMaxBytes {
		return nil, false, publisherStorageError(errPublisherHost)
	}
	value, err := s.call(ctx, "read", key, float64(limit))
	if err != nil {
		return nil, false, err
	}
	if value.IsNull() {
		return nil, false, nil
	}
	var bytes []byte
	copied, err := publisherJS(func() js.Value {
		if !value.InstanceOf(js.Global().Get("Uint8Array")) {
			return js.Undefined()
		}
		size := publisherGet(value, "byteLength")
		if size.Type() != js.TypeNumber || size.Float() < 0 || size.Float() > float64(limit) {
			return js.Undefined()
		}
		length := size.Int()
		if float64(length) != size.Float() {
			return js.Undefined()
		}
		bytes = make([]byte, length)
		if js.CopyBytesToGo(bytes, value) != len(bytes) {
			return js.Undefined()
		}
		return js.ValueOf(true)
	})
	if err != nil || copied.IsUndefined() {
		clear(bytes)
		return nil, false, publisherStorageError(errPublisherHost)
	}
	if err := context.Cause(ctx); err != nil {
		clear(bytes)
		return nil, false, err
	}
	return bytes, true, nil
}

func (s *publisherHostFiles) Write(ctx context.Context, key string, data []byte) error {
	if err := publisherStorageInput(ctx, key); err != nil {
		return err
	}
	if len(data) > publisherStorageMaxBytes {
		return publisherStorageError(errPublisherHost)
	}
	value, err := publisherJS(func() js.Value {
		value := js.Global().Get("Uint8Array").New(len(data))
		if js.CopyBytesToJS(value, data) != len(data) {
			return js.Undefined()
		}
		return value
	})
	if err != nil || value.IsUndefined() {
		return publisherStorageError(errPublisherHost)
	}
	_, err = s.call(ctx, "write", key, value)
	return err
}

func (s *publisherHostFiles) Sync(ctx context.Context, key string) error {
	if err := publisherStorageInput(ctx, key); err != nil {
		return err
	}
	_, err := s.call(ctx, "sync", key)
	return err
}

func (s *publisherHostFiles) Lock(ctx context.Context, key string) (io.Closer, error) {
	if err := publisherStorageInput(ctx, key); err != nil {
		return nil, err
	}
	release, err := s.call(ctx, "lock", key)
	if release.Type() != js.TypeFunction {
		if err == nil {
			err = publisherStorageError(errPublisherHost)
		}
		return nil, err
	}
	lock := &publisherHostLock{release: release}
	if err != nil {
		// the acquisition can win while cancellation is being delivered to
		// javascript. release that exact lock and join it before returning.
		return nil, errors.Join(err, lock.Close())
	}
	return lock, nil
}

type publisherHostLock struct {
	release js.Value
	once    sync.Once
	err     error
}

func (l *publisherHostLock) Close() error {
	l.once.Do(func() {
		pending, err := publisherJS(func() js.Value { return l.release.Invoke() })
		if err == nil {
			_, err = publisherAwait(context.Background(), pending, nil)
		}
		l.err = publisherStorageError(err)
	})
	return l.err
}
