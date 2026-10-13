package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

func TestDockerOwnerRequestStaysInsidePublisherClientState(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "tnl.json"), []byte(`{"version":1,"tnl":{"publisher":{"type":"docker","container":"publisher","container_port":8765}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	options := runtimeOptions{Directory: project, StateDir: filepath.Join(t.TempDir(), "state")}
	selected, state, err := runtimeProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	key, err := runtimeKey(selected.Root, state)
	if err != nil {
		t.Fatal(err)
	}
	handler := http.NewServeMux()
	handler.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		privateprotocol.Write(w, http.StatusOK, map[string]string{"project": project})
	})
	server, _, err := localpublisher.StartAPI(key, handler, "127.0.0.1:0", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = localpublisher.StopAPI(context.Background(), server, key) })
	owner, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runRuntimeOwner(t.Context(), options, strings.NewReader(`{"method":"GET","path":"/v1/status"}`), &output); err != nil {
		t.Fatal(err)
	}
	var response dockerOwnerResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.Status != 200 || !bytes.Contains(response.Body, []byte(project)) || bytes.Contains(output.Bytes(), []byte(owner.Credential)) {
		t.Fatalf("owner response status=%d, body=%s, error=%v", response.Status, response.Body, err)
	}
	output.Reset()
	if err := runRuntimeOwner(t.Context(), options, strings.NewReader(`{"method":"GET","path":"http://untrusted.example/v1/status"}`), &output); err == nil {
		t.Fatal("owner proxy accepted an external target")
	}
}
