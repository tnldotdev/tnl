//go:build js && wasm

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPublisherCertificateSourceBoundsAndRedaction(t *testing.T) {
	valid, err := publisherCertificateSource(publisherFunction(t, `({certificate() {return {certificatePEM:"public-chain",privateKeyPEM:"private-key"}}})`))
	if err != nil || valid == nil {
		t.Fatal("valid supplied source was rejected", err)
	}
	material, err := valid(t.Context())
	if err != nil || string(material.CertificatePEM) != "public-chain" || string(material.PrivateKeyPEM) != "private-key" {
		t.Fatal("host source lost exact private material", err)
	}
	clear(material.PrivateKeyPEM)
	for _, encoded := range []string{
		`({get certificate(){throw Error("PRIVATE KEY")}})`,
		`({certificate:"PRIVATE KEY"})`,
		`({certificate(){throw Error("PRIVATE KEY")}})`,
		`({certificate(){return {get privateKeyPEM(){throw Error("PRIVATE KEY")},certificatePEM:"chain"}}})`,
		`({certificate(){return {certificatePEM:"chain",privateKeyPEM:"x".repeat(16385)}}})`,
	} {
		source, err := publisherCertificateSource(publisherFunction(t, encoded))
		if err == nil {
			_, err = source(t.Context())
		}
		if err == nil || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Fatal("invalid source was accepted or exposed key details", err)
		}
	}
}

func TestPublisherCertificateSourceCancellationJoinsHostSettlement(t *testing.T) {
	state := publisherFunction(t, `(() => {
		let enteredResolve, abortedResolve, finish;
		return {
			entered: new Promise(r=>enteredResolve=r),
			aborted: new Promise(r=>abortedResolve=r),
			finish(){finish()},
			host:{certificate(signal){
				enteredResolve();
				signal.addEventListener("abort",()=>abortedResolve(),{once:true});
				return new Promise(resolve=>finish=()=>resolve({certificatePEM:"chain",privateKeyPEM:"key"}));
			}}
		};
	})()`)
	source, err := publisherCertificateSource(state.Get("host"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { material, err := source(ctx); clear(material.PrivateKeyPEM); done <- err }()
	if _, err := publisherAwait(t.Context(), state.Get("entered"), nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := publisherAwait(t.Context(), state.Get("aborted"), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("cancellation did not join the certificate provider")
	default:
	}
	state.Call("finish")
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("joined certificate source lost cancellation", err)
	}
}
