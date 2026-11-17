package proxy

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type ownedProxyTransport struct {
	roundTrip func(*http.Request) (*http.Response, error)
	idle      func()
	close     func() error
}

func (t *ownedProxyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.roundTrip != nil {
		return t.roundTrip(r)
	}
	return proxyTransportResponse(r), nil
}

func (t *ownedProxyTransport) CloseIdleConnections() {
	if t.idle != nil {
		t.idle()
	}
}

func (t *ownedProxyTransport) Close() error {
	if t.close != nil {
		return t.close()
	}
	return nil
}

func TestTransportFactoryReceivesCapturedNormalizedTargetAndTrust(t *testing.T) {
	roots := x509.NewCertPool()
	options := TargetOptions{RootCAs: roots, ServerName: "verified.internal"}
	var captured []string
	var closed atomic.Int32
	handler, err := New(Config{Target: "HTTPS://APP.EXAMPLE:8443", Hostname: "preview.example", TargetOptions: options,
		Mounts: []Mount{{Prefix: "/api", Target: "http://LOCALHOST:4000"}},
		Transport: func(target *url.URL, actual TargetOptions, base bool) (Transport, error) {
			address := target.String()
			captured = append(captured, address)
			if len(captured) == 1 {
				if !base || address != "https://app.example:8443" || actual.ServerName != options.ServerName ||
					actual.RootCAs == roots || !actual.RootCAs.Equal(roots) {
					t.Error("factory did not receive the captured target and independent trust", address, actual)
				}
			} else if base || address != "http://127.0.0.1:4000" || actual.ServerName != "" || actual.RootCAs != nil {
				t.Error("mounted target inherited base trust", address, actual)
			}
			// a factory cannot change the URL later used by routing or hooks.
			target.Host = "changed.example:9999"
			return &ownedProxyTransport{roundTrip: func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme+"://"+r.URL.Host != address {
					t.Error("factory input mutation changed captured routing", r.URL)
				}
				return proxyTransportResponse(r), nil
			}, close: func() error { closed.Add(1); return nil }}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/one", "/two", "/api/one", "/api/two"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, ownedProxyRequest(path))
		if response.Code != http.StatusOK {
			t.Fatal(response.Code)
		}
	}
	if len(captured) != 2 {
		t.Fatal("factory was rebuilt per request rather than per captured target", captured)
	}
	if err := handler.Close(); err != nil || closed.Load() != 2 {
		t.Fatal("custom owners were not closed", err, closed.Load())
	}
}

func TestTransportFactoryDistinguishesBaseAndMountAtSameAddress(t *testing.T) {
	for _, mode := range []string{"static", "resolved"} {
		t.Run(mode, func(t *testing.T) {
			const address = "https://app.example:8443"
			var bases, mounts int
			config := Config{Target: address, Hostname: "preview.example", TargetOptions: TargetOptions{ServerName: "base.internal"},
				Mounts: []Mount{{Prefix: "/api", Target: address, Options: TargetOptions{ServerName: "mount.internal"}}},
				Transport: func(target *url.URL, options TargetOptions, base bool) (Transport, error) {
					if target.String() != address {
						t.Error("factory changed the shared target address", target)
					}
					if base {
						bases++
						if options.ServerName != "base.internal" {
							t.Error("base slot received mounted trust", options)
						}
					} else {
						mounts++
						if options.ServerName != "mount.internal" {
							t.Error("mounted slot received base trust", options)
						}
					}
					return &ownedProxyTransport{}, nil
				}}
			if mode == "resolved" {
				config.ResolveTarget = func(*http.Request) (string, string, error) { return address, "base", nil }
				config.Mounts[0].ResolveTarget = func(context.Context) (string, string, error) { return address, "mount", nil }
			}
			handler, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Close()
			for _, path := range []string{"/", "/api/", "/", "/api/"} {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, ownedProxyRequest(path))
				if response.Code != http.StatusOK {
					t.Fatal("captured slot did not forward its request", response.Code)
				}
			}
			if bases != 1 || mounts != 1 {
				t.Fatal("factory guessed base identity from the shared address or rebuilt a captured slot", bases, mounts)
			}
		})
	}
}

type gatedProxyBody struct {
	entered chan struct{}
	release <-chan struct{}
	body    io.ReadCloser
	first   sync.Once
}

func (b *gatedProxyBody) Read(data []byte) (int, error) {
	b.first.Do(func() { close(b.entered); <-b.release })
	return b.body.Read(data)
}

func (b *gatedProxyBody) Close() error { return b.body.Close() }

func TestRetiredTransportLivesThroughCapturedSetupAndStreaming(t *testing.T) {
	for _, phase := range []string{"setup", "stream"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				closeStarted, finishClose := make(chan struct{}), make(chan struct{})
				unblockClose := sync.OnceFunc(func() { close(finishClose) })
				defer unblockClose()
				oldProblem, currentProblem := errors.New("retired close failed"), errors.New("current close failed")
				var idle, oldClosed atomic.Int32
				var creations int
				old := &ownedProxyTransport{
					roundTrip: func(r *http.Request) (*http.Response, error) {
						if phase == "setup" {
							close(entered)
							<-release
						}
						response := proxyTransportResponse(r)
						if phase == "stream" {
							response.Body = &gatedProxyBody{entered: entered, release: release, body: response.Body}
						}
						return response, nil
					},
					idle: func() { idle.Add(1) },
					close: func() error {
						oldClosed.Add(1)
						close(closeStarted)
						<-finishClose
						return oldProblem
					},
				}
				handler, err := New(Config{Target: "3000", Hostname: "preview.example",
					ResolveTarget: func(r *http.Request) (string, string, error) { return "3000", r.URL.Path, nil },
					Transport: func(*url.URL, TargetOptions, bool) (Transport, error) {
						creations++
						if creations == 1 {
							return old, nil
						}
						return &ownedProxyTransport{close: func() error { return currentProblem }}, nil
					}})
				if err != nil {
					t.Fatal(err)
				}
				first := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, ownedProxyRequest("/old"))
					first <- response
				}()
				awaitProxyTest(t, entered)
				second := httptest.NewRecorder()
				handler.ServeHTTP(second, ownedProxyRequest("/new"))
				if second.Code != http.StatusOK || idle.Load() != 1 {
					t.Fatal("replacement did not retire idle connections", second.Code, idle.Load())
				}
				synctest.Wait()
				if oldClosed.Load() != 0 {
					t.Fatal("retirement interrupted a captured handler")
				}
				unblock()
				if response := awaitProxyTest(t, first); response.Code != http.StatusOK || response.Body.String() != "captured target" {
					t.Fatal("retired request lost its target", response.Code, response.Body.String())
				}
				awaitProxyTest(t, closeStarted)
				synctest.Wait()
				handler.mu.Lock()
				pending := len(handler.transports)
				handler.mu.Unlock()
				if pending != 2 {
					t.Fatal("retired owner disappeared before close joined", pending)
				}
				unblockClose()
				synctest.Wait()
				handler.mu.Lock()
				remaining := len(handler.transports)
				handler.mu.Unlock()
				if remaining != 1 {
					t.Fatal("completed retirement retained a stale target", remaining)
				}
				if err := handler.Close(); !errors.Is(err, oldProblem) || !errors.Is(err, currentProblem) || oldClosed.Load() != 1 {
					t.Fatal("close lost a retired owner's independent error", err, oldClosed.Load())
				}
			})
		})
	}
}

func TestProxyCloseJoinsAllOwnersAndConcurrentClosers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
		release := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
		unblock := [2]func(){sync.OnceFunc(func() { close(release[0]) }), sync.OnceFunc(func() { close(release[1]) })}
		defer unblock[0]()
		defer unblock[1]()
		problems := [2]error{errors.New("base close failed"), errors.New("mount close failed")}
		var calls [2]atomic.Int32
		var creations int
		handler, err := New(Config{Target: "3000", Hostname: "preview.example", Mounts: []Mount{{Prefix: "/api", Target: "4000"}},
			Transport: func(*url.URL, TargetOptions, bool) (Transport, error) {
				index := creations
				creations++
				return &ownedProxyTransport{close: func() error {
					calls[index].Add(1)
					close(started[index])
					<-release[index]
					return errors.Join(context.Canceled, problems[index])
				}}, nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		finished := [2]chan error{make(chan error, 1), make(chan error, 1)}
		for _, done := range finished {
			go func() { done <- handler.Close() }()
		}
		awaitProxyTest(t, started[0])
		awaitProxyTest(t, started[1])
		late := httptest.NewRecorder()
		handler.ServeAdmittedHTTP(late, ownedProxyRequest("/api/late"))
		if late.Code != http.StatusBadGateway || creations != 2 {
			t.Fatal("closed proxy admitted new work", late.Code, creations)
		}
		unblock[0]()
		synctest.Wait()
		for _, done := range finished {
			select {
			case <-done:
				t.Fatal("close returned before every owner joined")
			default:
			}
		}
		unblock[1]()
		first, second := awaitProxyTest(t, finished[0]), awaitProxyTest(t, finished[1])
		if first != second || !errors.Is(first, context.Canceled) || !errors.Is(first, problems[0]) || !errors.Is(first, problems[1]) ||
			calls[0].Load() != 1 || calls[1].Load() != 1 {
			t.Fatal("concurrent close lost independent errors or closed an owner twice", first, second)
		}
	})
}

func TestProxyCloseJoinsRetiredHandlersBeforeAndAfterOwnerClose(t *testing.T) {
	for _, mounted := range []bool{false, true} {
		name := "base"
		if mounted {
			name = "mount"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started, releaseRequest := make(chan struct{}), make(chan struct{})
				closing, releaseClose := make(chan struct{}), make(chan struct{})
				unblockRequest := sync.OnceFunc(func() { close(releaseRequest) })
				unblockClose := sync.OnceFunc(func() { close(releaseClose) })
				defer unblockRequest()
				defer unblockClose()
				problem := errors.New("retired close failed")
				var replaced atomic.Bool
				var idle, closes atomic.Int32
				resolve := func() (string, string, error) {
					if replaced.Load() {
						return "5000", "replacement", nil
					}
					return "4000", "captured", nil
				}
				config := Config{Target: "4000", Hostname: "preview.example",
					ResolveTarget: func(*http.Request) (string, string, error) { return resolve() },
					Transport: func(target *url.URL, _ TargetOptions, _ bool) (Transport, error) {
						if target.Host != "127.0.0.1:4000" {
							return &ownedProxyTransport{}, nil
						}
						return &ownedProxyTransport{
							roundTrip: func(r *http.Request) (*http.Response, error) {
								close(started)
								<-releaseRequest
								return proxyTransportResponse(r), nil
							},
							idle: func() { idle.Add(1) },
							close: func() error {
								closes.Add(1)
								close(closing)
								<-releaseClose
								return problem
							},
						}, nil
					}}
				path := "/"
				if mounted {
					path = "/api/"
					config.Target, config.ResolveTarget = "3000", nil
					config.Mounts = []Mount{{Prefix: "/api", ResolveTarget: func(context.Context) (string, string, error) { return resolve() }}}
				}
				handler, err := New(config)
				if err != nil {
					t.Fatal(err)
				}
				requestDone := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, ownedProxyRequest(path))
					requestDone <- response
				}()
				awaitProxyTest(t, started)
				replaced.Store(true)
				replacement := httptest.NewRecorder()
				handler.ServeHTTP(replacement, ownedProxyRequest(path))
				synctest.Wait()
				if replacement.Code != http.StatusOK || idle.Load() != 1 || closes.Load() != 0 {
					t.Fatal("replacement interrupted its captured handler", replacement.Code, idle.Load(), closes.Load())
				}
				done := make(chan error, 1)
				go func() { done <- handler.Close() }()
				awaitProxyTest(t, closing)
				unblockClose()
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("proxy close joined the owner but missed its captured handler")
				default:
				}
				unblockRequest()
				if response := awaitProxyTest(t, requestDone); response.Code != http.StatusOK {
					t.Fatal("captured request changed its target", response.Code)
				}
				if err := awaitProxyTest(t, done); !errors.Is(err, problem) || closes.Load() != 1 {
					t.Fatal("close lost or repeated the retired owner's failure", err, closes.Load())
				}
			})
		})
	}
}

func TestProxyCloseFencesAndJoinsLateTransportCreation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		creating, finishCreate := make(chan struct{}), make(chan struct{})
		closeStarted, finishClose := make(chan struct{}), make(chan struct{})
		unblockCreate := sync.OnceFunc(func() { close(finishCreate) })
		unblockClose := sync.OnceFunc(func() { close(finishClose) })
		defer unblockCreate()
		defer unblockClose()
		problem := errors.New("late owner close failed")
		var resolutions, creations, requests atomic.Int32
		handler, err := New(Config{Target: "3000", Hostname: "preview.example",
			ResolveTarget: func(*http.Request) (string, string, error) {
				resolutions.Add(1)
				return "4000", "captured", nil
			},
			Transport: func(target *url.URL, _ TargetOptions, _ bool) (Transport, error) {
				creations.Add(1)
				if target.String() != "http://127.0.0.1:4000" {
					t.Error("factory did not receive the captured target", target)
				}
				close(creating)
				<-finishCreate
				return &ownedProxyTransport{roundTrip: func(r *http.Request) (*http.Response, error) {
					requests.Add(1)
					return proxyTransportResponse(r), nil
				}, close: func() error {
					close(closeStarted)
					<-finishClose
					return problem
				}}, nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		requestDone := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, ownedProxyRequest("/"))
			requestDone <- response
		}()
		awaitProxyTest(t, creating)
		finished := make(chan error, 1)
		go func() { finished <- handler.Close() }()
		synctest.Wait()
		select {
		case <-finished:
			t.Fatal("close ignored the pending transport factory")
		default:
		}
		unblockCreate()
		awaitProxyTest(t, closeStarted)
		synctest.Wait()
		select {
		case <-finished:
			t.Fatal("close ignored the late transport's shutdown")
		default:
		}
		unblockClose()
		if err := awaitProxyTest(t, finished); !errors.Is(err, problem) {
			t.Fatal("close lost the late owner's independent error", err)
		}
		if response := awaitProxyTest(t, requestDone); response.Code != http.StatusBadGateway ||
			requests.Load() != 0 || resolutions.Load() != 1 || creations.Load() != 1 {
			t.Fatal("late creation escaped the closed entry fence", response.Code, requests.Load(), resolutions.Load(), creations.Load())
		}
	})
}

func TestNewFailureClosesExistingAndPartialTransportOwners(t *testing.T) {
	creation, baseClose, partialClose := errors.New("creation failed"), errors.New("base close failed"), errors.New("partial close failed")
	var creations int
	var closed [2]atomic.Int32
	handler, err := New(Config{Target: "3000", Hostname: "preview.example", Mounts: []Mount{{Prefix: "/api", Target: "4000"}},
		Transport: func(*url.URL, TargetOptions, bool) (Transport, error) {
			index := creations
			creations++
			owner := &ownedProxyTransport{close: func() error {
				closed[index].Add(1)
				return []error{baseClose, partialClose}[index]
			}}
			if index == 1 {
				return owner, creation
			}
			return owner, nil
		}})
	if handler != nil || !errors.Is(err, creation) || !errors.Is(err, baseClose) || !errors.Is(err, partialClose) ||
		closed[0].Load() != 1 || closed[1].Load() != 1 {
		t.Fatal("failed setup leaked an owner or lost a cleanup error", handler, err)
	}
	if strings.Count(err.Error(), baseClose.Error()) != 1 || strings.Count(err.Error(), partialClose.Error()) != 1 {
		t.Fatal("failed setup reported a cleanup error twice", err)
	}
}
