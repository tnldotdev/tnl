package httpstream

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type upgradeTestTransport func(*http.Request) (*http.Response, error)

func (f upgradeTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type upgradeTestBody struct {
	reader io.Reader
	read   func([]byte) (int, error)
	write  func([]byte) (int, error)
	close  func() error
}

func (b *upgradeTestBody) Read(p []byte) (int, error) {
	if b.read != nil {
		return b.read(p)
	}
	return b.reader.Read(p)
}
func (b *upgradeTestBody) Write(p []byte) (int, error) {
	if b.write != nil {
		return b.write(p)
	}
	return len(p), nil
}
func (b *upgradeTestBody) Close() error { return b.close() }

type upgradeTestHalfClose struct {
	*upgradeTestBody
	halfClose func() error
}

func (b *upgradeTestHalfClose) CloseWrite() error { return b.halfClose() }

type upgradeTestWriter struct {
	*httptest.ResponseRecorder
	conn  net.Conn
	panic any
}

func (w *upgradeTestWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.panic != nil {
		panic(w.panic)
	}
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func upgradeTestProxy(body io.ReadWriteCloser) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(&url.URL{Scheme: "http", Host: "target.test"}) },
		Transport: upgradeTestTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"test"}}, Body: body, Request: r}, nil
		}),
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

func upgradeTestRequest() *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/upgrade", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "test")
	return request
}

func TestServeProxyJoinsAsynchronousUpgradeCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cleanup := errors.New("upgrade cleanup failed")
		closeEntered, releaseClose := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(releaseClose) })
		defer unblock()
		var closes atomic.Int32
		body := &upgradeTestBody{reader: strings.NewReader("hot"), close: func() error {
			closes.Add(1)
			close(closeEntered)
			<-releaseClose
			return errors.Join(context.Canceled, cleanup)
		}}
		configured := upgradeTestProxy(body)
		var hooks atomic.Int32
		configured.ModifyResponse = func(response *http.Response) error {
			if response.Body != body {
				t.Error("upgrade completion ran before existing response hooks")
			}
			hooks.Add(1)
			return nil
		}
		visitor, proxy := net.Pipe()
		defer visitor.Close()
		defer proxy.Close()
		finished := make(chan error, 1)
		go func() {
			var recorded error
			ServeProxy(configured, &upgradeTestWriter{ResponseRecorder: httptest.NewRecorder(), conn: proxy}, upgradeTestRequest(), func(err error) { recorded = err })
			finished <- recorded
		}()
		reader := bufio.NewReader(visitor)
		response, err := http.ReadResponse(reader, nil)
		if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatal("upgrade failed", response, err)
		}
		var hot [3]byte
		if _, err := io.ReadFull(reader, hot[:]); err != nil || string(hot[:]) != "hot" {
			t.Fatal("upgrade bytes changed", string(hot[:]), err)
		}
		<-closeEntered
		synctest.Wait()
		select {
		case err := <-finished:
			t.Fatal("proxy returned before asynchronous upgrade Close joined", err)
		default:
		}
		unblock()
		err = <-finished
		if !errors.Is(err, cleanup) || !errors.Is(err, context.Canceled) || closes.Load() != 1 || hooks.Load() != 1 {
			t.Fatal("upgrade completion lost its cleanup cause or repeated hooks/Close", err, closes.Load(), hooks.Load())
		}
	})
}

func TestServeProxyJoinsUpgradeOnHookAndHijackFailures(t *testing.T) {
	for _, mode := range []string{"hook error", "hook panic", "hijack error", "hijack panic"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cleanup := errors.New("independent upgrade cleanup")
				operation := errors.New("original hook or hijack panic")
				entered, release := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				var closes atomic.Int32
				body := &upgradeTestBody{reader: strings.NewReader(""), close: func() error {
					closes.Add(1)
					close(entered)
					<-release
					return cleanup
				}}
				configured := upgradeTestProxy(body)
				configured.ModifyResponse = func(*http.Response) error {
					switch mode {
					case "hook error":
						return operation
					case "hook panic":
						panic(operation)
					}
					return nil
				}
				var writer http.ResponseWriter = httptest.NewRecorder()
				if mode == "hijack panic" {
					writer = &upgradeTestWriter{ResponseRecorder: httptest.NewRecorder(), panic: operation}
				}
				finished := make(chan any, 1)
				var recorded error
				go func() {
					defer func() { finished <- recover() }()
					ServeProxy(configured, writer, upgradeTestRequest(), func(err error) { recorded = err })
				}()
				<-entered
				synctest.Wait()
				select {
				case value := <-finished:
					t.Fatal("failure/panic escaped before upgrade cleanup joined", value)
				default:
				}
				unblock()
				value := <-finished
				if strings.HasSuffix(mode, "panic") && value != operation || !strings.HasSuffix(mode, "panic") && value != nil ||
					!errors.Is(recorded, cleanup) || closes.Load() != 1 {
					t.Fatal("upgrade cleanup replaced the original panic or lost its independent failure", value, recorded, closes.Load())
				}
			})
		})
	}
}

func TestJoinedUpgradeFencesLateIOAndJoinsHalfClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		readEntered, writeEntered, halfEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
		releaseIO, closeEntered, releaseClose := make(chan struct{}), make(chan struct{}), make(chan struct{})
		unblockIO := sync.OnceFunc(func() { close(releaseIO) })
		unblockClose := sync.OnceFunc(func() { close(releaseClose) })
		defer unblockIO()
		defer unblockClose()
		cleanup, halfFailure := errors.New("close failed"), errors.New("half-close failed")
		var closes atomic.Int32
		body := &upgradeTestHalfClose{upgradeTestBody: &upgradeTestBody{
			read: func(p []byte) (int, error) {
				close(readEntered)
				<-releaseIO
				p[0] = 'x'
				return 1, nil
			},
			write: func(p []byte) (int, error) {
				close(writeEntered)
				<-releaseIO
				return len(p), nil
			},
			close: func() error {
				closes.Add(1)
				close(closeEntered)
				<-releaseClose
				return errors.Join(net.ErrClosed, cleanup)
			},
		}, halfClose: func() error {
			close(halfEntered)
			<-releaseIO
			return halfFailure
		}}
		_, wrapped := newJoinedUpgrade(body)
		if _, ok := wrapped.(io.ReaderFrom); ok {
			t.Fatal("upgrade exposed an IO accounting bypass")
		}
		if _, ok := wrapped.(io.WriterTo); ok {
			t.Fatal("upgrade exposed an IO accounting bypass")
		}
		half := wrapped.(interface{ CloseWrite() error })
		read, write, halfClosed := make(chan error, 1), make(chan error, 1), make(chan error, 1)
		go func() { var value [1]byte; _, err := wrapped.Read(value[:]); read <- err }()
		go func() { _, err := wrapped.Write([]byte("x")); write <- err }()
		go func() { halfClosed <- half.CloseWrite() }()
		<-readEntered
		<-writeEntered
		<-halfEntered
		closed := make(chan error, 3)
		go func() { closed <- wrapped.Close() }()
		<-closeEntered
		for range 2 {
			go func() { closed <- wrapped.Close() }()
		}
		if _, err := wrapped.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatal("late read crossed the close fence", err)
		}
		if _, err := wrapped.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
			t.Fatal("late write crossed the close fence", err)
		}
		if err := half.CloseWrite(); !errors.Is(err, net.ErrClosed) {
			t.Fatal("late half-close crossed the close fence", err)
		}
		unblockClose()
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatal("Close did not join entered upgrade IO", err)
		default:
		}
		unblockIO()
		if err := <-read; err != nil {
			t.Fatal(err)
		}
		if err := <-write; err != nil {
			t.Fatal(err)
		}
		if err := <-halfClosed; err != halfFailure {
			t.Fatal("half-close behavior changed", err)
		}
		first := <-closed
		if !errors.Is(first, cleanup) || !errors.Is(first, halfFailure) {
			t.Fatal("joined cleanup lost independent close failures", first)
		}
		for range 2 {
			if err := <-closed; err != first {
				t.Fatal("concurrent Close changed the retained cleanup result", err)
			}
		}
		if closes.Load() != 1 || wrapped.Close() != first {
			t.Fatal("repeated Close touched the underlying upgrade again")
		}
		_, plain := newJoinedUpgrade(body.upgradeTestBody)
		if _, ok := plain.(interface{ CloseWrite() error }); ok {
			t.Fatal("upgrade invented unsupported half-close behavior")
		}
	})
}

func TestServeProxyLeavesOrdinaryResponsesUnchanged(t *testing.T) {
	var closes atomic.Int32
	body := &upgradeTestBody{reader: strings.NewReader("ordinary"), close: func() error { closes.Add(1); return nil }}
	configured := upgradeTestProxy(body)
	configured.Transport = upgradeTestTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, ContentLength: 8, Request: r}, nil
	})
	response := httptest.NewRecorder()
	ServeProxy(configured, response, httptest.NewRequest(http.MethodGet, "/", nil), func(err error) { t.Error("ordinary response acquired upgrade cleanup", err) })
	if response.Code != http.StatusOK || response.Body.String() != "ordinary" || closes.Load() != 1 || configured.ModifyResponse != nil {
		t.Fatal("upgrade completion changed an ordinary response or mutated its configured proxy", response.Code, response.Body.String(), closes.Load())
	}
}
