package daemon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/testutil"
	"golang.org/x/net/websocket"
)

func TestIntegrationPublicViteHMR(t *testing.T) {
	testPublicFrameworkHMR(t, "vite")
}

func TestIntegrationPublicNextHMR(t *testing.T) {
	testPublicFrameworkHMR(t, "next")
}

// the sdk registers its actual bound app listener with a real native owner.
// every visitor request and websocket crosses the public front, ingress,
// relay, and publisher, with the assigned hostname and verified visitor tls.
func testPublicFrameworkHMR(t *testing.T, framework string) {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newSplitPublishFixture(t, "public-"+framework)
	repo := integrationRepositoryRoot(t)
	directory := publicFrameworkWorkspace(t, repo, framework)
	quic, tcp := f.connectors()
	native := startFrameworkNativeOwner(t, directory, config.Services{
		"web": {Public: new(true), HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}},
	}, frameworkNativeSetup{controlURL: f.identity.controlOrigin, state: f.identity.state, controlHTTP: f.controlHTTP,
		publicHTTP: f.visitor.client, publicDomain: f.controlConfig.ManagedDomain, publicRootPEM: f.pebble.rootPEM,
		relayTLS: f.roots, quic: quic, tcp: tcp})
	defer native.stop()
	var command *exec.Cmd
	if framework == "vite" {
		command = exec.Command("node", filepath.Join(repo, "packages/ts/test/fixtures/connector-vite.ts"))
	} else {
		// next itself owns its port-0 listener before withTnl loads config.
		// no reserve-close-rebind port probe or fabricated post-bind origin.
		command = exec.Command("node", filepath.Join(repo, "packages/ts/node_modules/next/dist/bin/next"),
			"dev", "--hostname", "127.0.0.1", "--port", "0")
	}
	command.Dir = directory
	command.Env = append(os.Environ(), "TNL_APP_ENDPOINT="+native.endpoint, "TNL_NO_TELEMETRY=1", "TNL_PREVIEW=required")
	var output synchronizedBuffer
	command.Stdout, command.Stderr = &output, &output
	process, err := startOwnedCommand(command, isolateIntegrationCommand(t, command))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := process.shutdown(10*time.Second, 3*time.Second); err != nil {
			t.Error("framework shutdown", err)
		}
		if err := process.result(); err != nil {
			t.Error("framework process", err)
		}
		if t.Failed() {
			t.Log(output.String())
		}
	}()
	var serviceID string
	select {
	case serviceID = <-native.routable:
	case <-process.done:
		t.Fatal("framework exited before native publication readiness", process.result(), output.String())
	case <-time.After(35 * time.Second):
		t.Fatal("native framework publication did not become routable", output.String())
	}
	service, err := f.identity.routes.GetService(t.Context(), serviceID)
	if err != nil || service.Endpoint == nil || !service.Endpoint.Public || service.Endpoint.Port != 443 {
		t.Fatal("framework did not receive its real public HTTPS endpoint", err)
	}
	base := "https://" + service.Endpoint.Hostname
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(integrationPublisherDiagnostics(f.inspect, f.pebble.logPath))
		}
	})
	read := func(path, origin string) string {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		response, body, err := f.visitor.request(request)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("public %s request %s: response=%v err=%v body=%s", framework, path, response, err, body)
		}
		assertIntegrationPublicURLCertificate(t, response, service.Endpoint.Hostname)
		return string(body)
	}
	page := read("/", "")
	marker := "Vite fixture"
	source := filepath.Join(directory, "src/main.ts")
	socketPath, protocol := "", "vite-hmr"
	var nextChunk, nextChunkList string
	if framework == "vite" {
		if !strings.Contains(page, marker) {
			t.Fatal("public endpoint did not serve the actual Vite app")
		}
		module := read("/src/main.ts", "")
		if !strings.Contains(module, marker) || !strings.Contains(module, "import.meta.hot") {
			t.Fatal("public Vite module did not establish the real HMR graph")
		}
		client := read("/@vite/client", base)
		token := regexp.MustCompile(`\b(?:const|let|var)\s+wsToken\s*=\s*["']([^"']+)["']`).FindStringSubmatch(client)
		environment := regexp.MustCompile(`\bimport\s*["'](/[^"']*/env\.mjs(?:\?[^"']*)?)["']`).FindStringSubmatch(client)
		if len(token) != 2 || len(environment) != 2 {
			t.Fatal("served Vite client omitted its HMR token or environment module")
		}
		metadata := read(environment[1], "")
		if !strings.Contains(metadata, base) || !strings.Contains(metadata, service.Endpoint.Hostname) {
			t.Fatal("public Vite runtime metadata lost the assigned endpoint")
		}
		socketPath = "/?token=" + url.QueryEscape(token[1])
	} else {
		marker, source, socketPath, protocol = "Next.js fixture", filepath.Join(directory, "app/page.tsx"), "/_next/hmr?id=tnl-public-hmr", ""
		for _, value := range []string{marker, "url:" + base, "hostname:" + service.Endpoint.Hostname, "under-dev:true"} {
			if !strings.Contains(page, value) {
				t.Fatalf("public Next page lost runtime metadata %q", value)
			}
		}
		asset := regexp.MustCompile(`src="([^"]*/_next/static/[^"]+\.js[^"]*)"`).FindStringSubmatch(page)
		if len(asset) != 2 {
			t.Fatal("public Next page omitted its development asset")
		}
		read(html.UnescapeString(asset[1]), base)
		// fetch the page's real client chunk through public https before
		// subscribing, just as the browser loads it before the first edit.
		chunkLists := make(map[string][]string)
		for _, script := range regexp.MustCompile(`src="([^"]*/_next/static/[^"]+\.js[^"]*)"`).FindAllStringSubmatch(page, -1) {
			path := html.UnescapeString(script[1])
			body := read(path, base)
			scriptURL, err := url.Parse(path)
			if err != nil {
				t.Fatal(err)
			}
			chunkPath := strings.TrimPrefix(scriptURL.Path, "/_next/")
			if strings.Contains(body, marker) {
				nextChunk = chunkPath
			}
			if strings.HasPrefix(body, `(globalThis["TURBOPACK_CHUNK_LISTS"]`) {
				chunks := regexp.MustCompile(`(?m)^\s*chunks:\s*(\[[^\r\n]*\]),?\s*$`).FindStringSubmatch(body)
				if len(chunks) != 2 {
					t.Fatal("public Next chunk-list registration omitted its chunks")
				}
				var paths []string
				if err := json.Unmarshal([]byte(chunks[1]), &paths); err != nil {
					t.Fatal("invalid public Next chunk list", err)
				}
				chunkLists[chunkPath] = paths
			}
		}
		if nextChunk == "" {
			t.Fatal("public Next page did not load its actual client component chunk")
		}
		for path, chunks := range chunkLists {
			for _, chunk := range chunks {
				if chunk == nextChunk {
					if nextChunkList != "" {
						t.Fatal("public Next page registered its component in multiple chunk lists")
					}
					nextChunkList = path
				}
			}
		}
		if nextChunkList == "" {
			t.Fatal("public Next page did not register its component's HMR chunk list")
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+html.UnescapeString(asset[1]), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", "https://unrelated.example")
		response, body, err := f.visitor.request(request)
		if err != nil || response.StatusCode != http.StatusForbidden {
			t.Fatalf("public Next development asset accepted an unrelated origin: response=%v body=%s err=%v", response, body, err)
		}
	}
	connection := publicFrameworkWebSocket(t, f, base, socketPath, protocol)
	defer func() {
		if err := connection.Close(); err != nil {
			t.Error("close public framework websocket", err)
		}
	}()
	if framework == "vite" {
		awaitPublicHMR(t, connection, "Vite connection", func(message publicHMRMessage) bool { return message.Type == "connected" })
	} else {
		// consume initial synchronization and subscribe to the actual page
		// chunk list. built alone also reports no-op request/render compilations.
		awaitPublicHMR(t, connection, "Next synchronization", func(message publicHMRMessage) bool { return message.Type == "sync" })
		if err := websocket.JSON.Send(connection, struct {
			Type string `json:"type"`
			Path string `json:"path"`
		}{Type: "turbopack-subscribe", Path: nextChunkList}); err != nil {
			t.Fatal("subscribe to public Next page HMR", err)
		}
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	refreshed := marker + " public HMR"
	if !strings.Contains(string(original), marker) {
		t.Fatal("framework edit marker is missing")
	}
	if err := os.WriteFile(source, []byte(strings.ReplaceAll(string(original), marker, refreshed)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: edited %s", framework, filepath.Base(source))
	if framework == "vite" {
		awaitPublicHMR(t, connection, "Vite source update", func(message publicHMRMessage) bool {
			if message.Type != "update" {
				return false
			}
			for _, update := range message.Updates {
				if update.Path == "/src/main.ts" && update.AcceptedPath == "/src/main.ts" {
					return true
				}
			}
			return false
		})
		if !strings.Contains(read("/src/main.ts?t="+strconv.FormatInt(time.Now().UnixMilli(), 10), ""), refreshed) {
			t.Fatal("Vite HMR frame did not correspond to the actual edited public module")
		}
	} else {
		// next suppresses building for fast compilations. require the actual
		// changed component's module over wss, not optional progress frames.
		awaitPublicHMR(t, connection, "Next edited component update", func(message publicHMRMessage) bool {
			if message.Type != "turbopack-message" {
				return false
			}
			var updates []struct {
				Type     string `json:"type"`
				Resource struct {
					Path string `json:"path"`
				} `json:"resource"`
				Instruction struct {
					Type   string `json:"type"`
					Merged []struct {
						Entries map[string]json.RawMessage `json:"entries"`
					} `json:"merged"`
				} `json:"instruction"`
			}
			if err := json.Unmarshal(message.Data, &updates); err != nil {
				t.Fatal("invalid public Next chunk update", err)
			}
			for _, update := range updates {
				if update.Resource.Path != nextChunkList {
					continue
				}
				if update.Type == "restart" {
					t.Fatal("public Next HMR requested a restart instead of a component update")
				}
				if update.Type != "partial" || update.Instruction.Type != "ChunkListUpdate" {
					continue
				}
				for _, merged := range update.Instruction.Merged {
					for module := range merged.Entries {
						if strings.Contains(module, "/app/page.tsx [app-client]") {
							t.Logf("public Next HMR updated module %s", module)
							return true
						}
					}
				}
			}
			return false
		})
		awaitPublicHMR(t, connection, "Next built", func(message publicHMRMessage) bool { return message.Type == "built" })
		if !strings.Contains(read("/", ""), refreshed) {
			t.Fatal("Next build frame did not correspond to the actual edited public page")
		}
		if !strings.Contains(read("/_next/"+nextChunk, base), refreshed) {
			t.Fatal("Next HMR update did not correspond to the actual edited public client chunk")
		}
	}
	t.Logf("%s: real file edit -> public WSS HMR update -> changed public HTTPS content at %s", framework, base)
}

func publicFrameworkWorkspace(t *testing.T, repo, framework string) string {
	t.Helper()
	fixtures := filepath.Join(repo, "packages/ts/test/fixtures", framework)
	directory, err := os.MkdirTemp(fixtures, "workspace-public-hmr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := os.CopyFS(directory, os.DirFS(filepath.Join(fixtures, "app"))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"name":"tnl-public-hmr-fixture","private":true,"type":"module"}`), 0600); err != nil {
		t.Fatal(err)
	}
	// resolve the actual built sdk, as the local framework fixtures do, but
	// use real native ipc instead of installing a simulated bootstrap endpoint.
	sdk := filepath.Join(directory, "node_modules/@tnldotdev/tnl")
	if err := os.CopyFS(filepath.Join(sdk, "dist"), os.DirFS(filepath.Join(repo, "packages/ts/dist"))); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(repo, "packages/ts/package.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdk, "package.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "src/main.ts")
	if framework == "next" {
		source = filepath.Join(directory, "app/page.tsx")
	}
	value, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(strings.ReplaceAll(string(value), "services.api", "services.web")), 0600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func publicFrameworkWebSocket(t *testing.T, f *splitPublishFixture, base, path, protocol string) *websocket.Conn {
	t.Helper()
	settings, err := websocket.NewConfig("wss://"+strings.TrimPrefix(base, "https://")+path, base)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != "" {
		settings.Protocol = []string{protocol}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// change only socket addressing. sni, certificate validation, Host, and
	// Origin retain the actual public endpoint throughout the real tls/wss path.
	settings.TlsConfig = f.visitor.transport.TLSClientConfig.Clone()
	settings.TlsConfig.ServerName = settings.Location.Hostname()
	raw, err := f.visitor.transport.DialContext(ctx, "tcp", settings.Location.Host+":443")
	if err != nil {
		t.Fatal(err)
	}
	secured := tls.Client(raw, settings.TlsConfig)
	if err := secured.HandshakeContext(ctx); err != nil {
		_ = secured.Close()
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	if err := secured.SetDeadline(deadline); err != nil {
		_ = secured.Close()
		t.Fatal(err)
	}
	connection, err := websocket.NewClient(settings, secured)
	if err != nil {
		_ = secured.Close()
		t.Fatal("public WSS upgrade", err)
	}
	connection.MaxPayloadBytes = 1 << 20
	if err := connection.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	return connection
}

type publicHMRMessage struct {
	Type    string            `json:"type"`
	Data    json.RawMessage   `json:"data"`
	Errors  []json.RawMessage `json:"errors"`
	Updates []struct {
		Path         string `json:"path"`
		AcceptedPath string `json:"acceptedPath"`
	} `json:"updates"`
}

func awaitPublicHMR(t *testing.T, connection *websocket.Conn, stage string, matches func(publicHMRMessage) bool) {
	t.Helper()
	t.Logf("public HMR: waiting for %s", stage)
	var recent []string
	for {
		var raw string
		if err := websocket.Message.Receive(connection, &raw); err != nil {
			t.Fatalf("public framework HMR %s: recent frame types=%q: %v", stage, recent, err)
		}
		var message publicHMRMessage
		if err := json.Unmarshal([]byte(raw), &message); err != nil {
			t.Fatal("framework sent invalid HMR JSON", err)
		}
		if len(message.Errors) != 0 || message.Type == "error" {
			t.Fatal("framework HMR reported a compilation error", raw)
		}
		if len(recent) == 12 {
			recent = recent[1:]
		}
		recent = append(recent, message.Type)
		if matches(message) {
			t.Logf("public HMR: received %s; frame types=%q", stage, recent)
			return
		}
	}
}
