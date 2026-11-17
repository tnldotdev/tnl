//go:build js && wasm

package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherStoragePersistsPendingKeysAcrossAdapters(t *testing.T) {
	host := publisherFunction(t, `(() => {
		const records = new Map(), locks = new Set();
		return {
			read(scope,key,limit,signal) {const value=records.get(scope+key); return value?.slice() ?? null},
			write(scope,key,value,signal) {records.set(scope+key,value.slice())},
			sync(scope,key,signal) {if (!records.has(scope+key)) throw Error("missing checkpoint")},
			lock(scope,key,signal) {
				if (locks.has(scope+key)) throw Error("lock already held");
				locks.add(scope+key);
				return async () => {locks.delete(scope+key)};
			}
		};
	})()`)
	plan := controlv1.CertificatePlan{CacheKey: "web.example.test", Scope: "web.example.test", Identifiers: []string{"web.example.test"}, ChallengeMethod: controlv1.Dns01}
	store, err := newPublisherHostStore(host, "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	cache, err := store.CertificatesForPublisher("team", "pub_0123456789abcdefghijkl", plan)
	if err != nil {
		t.Fatal(err)
	}
	first, err := cache.Pending(t.Context(), "web.example.test")
	if err != nil {
		t.Fatal(err)
	}
	store, err = newPublisherHostStore(host, "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	cache, err = store.CertificatesForPublisher("team", "pub_0123456789abcdefghijkl", plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.Pending(t.Context(), "web.example.test")
	if err != nil || !bytes.Equal(first.CSRDER, second.CSRDER) || first.Key.D.Cmp(second.Key.D) != 0 {
		t.Fatal("host adapter replaced an existing pending CSR or signing key", err)
	}
	other, err := store.CertificatesForPublisher("other-team", "pub_0123456789abcdefghijkl", plan)
	if err != nil {
		t.Fatal(err)
	}
	third, err := other.Pending(t.Context(), "web.example.test")
	if err != nil || bytes.Equal(first.CSRDER, third.CSRDER) {
		t.Fatal("host adapter shared private material across ownership scopes", err)
	}
}

func TestPublisherStorageCanceledAcquisitionJoinsRelease(t *testing.T) {
	state := publisherFunction(t, `(() => {
		let acquiringResolve, abortedResolve, releaseResolve, acquire, finish;
		const acquiring = new Promise(r => acquiringResolve = r);
		const aborted = new Promise(r => abortedResolve = r);
		const releasing = new Promise(r => releaseResolve = r);
		return {
			acquiring, aborted, releasing, acquire() {acquire()}, finish() {finish()},
			storage: {lock(scope,key,signal) {
				acquiringResolve();
				signal.addEventListener("abort", () => abortedResolve(), {once:true});
				return new Promise(resolve => acquire = () => resolve(() => {
					releaseResolve();
					return new Promise(r => finish=r);
				}));
			}}
		};
	})()`)
	storage := &publisherHostFiles{host: state.Get("storage"), scope: "exact-scope"}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		lock, err := storage.Lock(ctx, "issuance")
		if lock != nil {
			err = errors.Join(err, lock.Close())
		}
		done <- err
	}()
	if _, err := publisherAwait(t.Context(), state.Get("acquiring"), nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := publisherAwait(t.Context(), state.Get("aborted"), nil); err != nil {
		t.Fatal(err)
	}
	state.Call("acquire")
	if _, err := publisherAwait(t.Context(), state.Get("releasing"), nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatal("canceled acquisition returned while its release was pending", err)
	default:
	}
	state.Call("finish")
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("canceled acquisition lost cancellation", err)
	}
}

func TestPublisherStorageBoundsReadAndRedactsHostErrors(t *testing.T) {
	for _, source := range []string{
		`({read() {return new Uint8Array(9)}})`,
		`({read() {return "not bytes"}})`,
		`({read() {throw Error("private certificate content")}})`,
	} {
		storage := &publisherHostFiles{host: publisherFunction(t, source), scope: "exact-scope"}
		data, found, err := storage.Read(t.Context(), "record", 8)
		if err == nil || found || data != nil || err.Error() == "private certificate content" {
			t.Fatal("host storage accepted an invalid snapshot or exposed private content", err)
		}
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.PublisherIdentityStateUnavailable {
			t.Fatal("host storage did not report its owned boundary failure", err)
		}
	}
}

func TestPublisherStorageReleaseIsJoinedOnce(t *testing.T) {
	state := publisherFunction(t, `(() => {
		let calls=0;
		return {get calls() {return calls}, release() {calls++; return Promise.reject(Error("private failure"))}};
	})()`)
	lock := &publisherHostLock{release: state.Get("release")}
	first, second := lock.Close(), lock.Close()
	if first == nil || second != first || state.Get("calls").Int() != 1 {
		t.Fatal("host release was not joined exactly once", first, second)
	}
}

func TestPublisherStorageConstructorGuardsGettersOnce(t *testing.T) {
	state := publisherFunction(t, `(() => {
		let reads=0;
		return {get reads() {return reads}, storage:{
			get read() {reads++; return () => null},
			write() {}, sync() {}, lock() {return () => {}}
		}};
	})()`)
	if _, err := newPublisherHostStore(state.Get("storage"), "https://control.example.test"); err != nil || state.Get("reads").Int() != 1 {
		t.Fatal("host constructor evaluated a method getter more than once", err)
	}
	host := publisherFunction(t, `({get read() {throw Error("private provider settings")}})`)
	if _, err := newPublisherHostStore(host, "https://control.example.test"); err == nil {
		t.Fatal("host constructor accepted a throwing method getter")
	}
}
