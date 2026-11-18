//go:build js && wasm && !tnlconnector

package main

import (
	"context"
	"errors"
	"syscall/js"

	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
)

func publisherCertificateSource(host js.Value) (func(context.Context) (publisherservice.CertificateMaterial, error), error) {
	source, err := publisherJS(func() js.Value { return publisherGet(host, "certificate") })
	if err != nil {
		return nil, errPublisherHost
	}
	if source.IsUndefined() {
		return nil, nil
	}
	if source.Type() != js.TypeFunction {
		return nil, errArguments
	}
	return func(ctx context.Context) (material publisherservice.CertificateMaterial, result error) {
		abort, err := publisherJS(func() js.Value { return js.Global().Get("AbortController").New() })
		if err != nil {
			return material, errPublisherHost
		}
		pending, err := publisherJS(func() js.Value { return source.Invoke(abort.Get("signal")) })
		if err != nil {
			return material, errPublisherHost
		}
		value, err := publisherAwait(ctx, pending, func() {
			_, _ = publisherJS(func() js.Value { return abort.Call("abort") })
		})
		if err != nil {
			return material, errors.Join(err, context.Cause(ctx))
		}
		_, err = publisherJS(func() js.Value {
			if value.Type() != js.TypeObject || value.IsNull() {
				return js.Undefined()
			}
			chain, key := publisherGet(value, "certificatePEM"), publisherGet(value, "privateKeyPEM")
			if chain.Type() != js.TypeString || key.Type() != js.TypeString {
				return js.Undefined()
			}
			certificatePEM, privateKeyPEM := chain.String(), key.String()
			if len(certificatePEM) == 0 || len(certificatePEM) > 128<<10 || len(privateKeyPEM) == 0 || len(privateKeyPEM) > 16<<10 {
				return js.Undefined()
			}
			material.CertificatePEM, material.PrivateKeyPEM = []byte(certificatePEM), []byte(privateKeyPEM)
			return js.Undefined()
		})
		if err != nil || len(material.PrivateKeyPEM) == 0 {
			clear(material.PrivateKeyPEM)
			clear(material.CertificatePEM)
			return publisherservice.CertificateMaterial{}, errPublisherHost
		}
		return material, context.Cause(ctx)
	}, nil
}
