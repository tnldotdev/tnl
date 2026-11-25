//go:build js && wasm

package main

import (
	"context"
	"syscall/js"

	"github.com/tnldotdev/tnl/internal/connector/workload"
)

func assertionCallback(callback js.Value) (func(context.Context) (string, error), error) {
	if callback.Type() != js.TypeFunction {
		return nil, errArguments
	}
	return func(ctx context.Context) (string, error) {
		controller := js.Global().Get("AbortController").New()
		reason := js.Global().Get("Object").New()
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(done)
			controller.Call("abort", reason)
		})
		defer func() {
			if !stop() {
				<-done
			}
		}()
		value, err := invoke(callback, controller.Get("signal"))
		if err != nil {
			return "", workload.ErrAssertionUnavailable
		}
		resolved, ownedAbort, err := awaitWithAbort(value, reason.Equal)
		if ownedAbort && ctx.Err() != nil {
			return "", context.Cause(ctx)
		}
		if err != nil || resolved.Type() != js.TypeString {
			return "", workload.ErrAssertionUnavailable
		}
		return resolved.String(), nil
	}, nil
}
