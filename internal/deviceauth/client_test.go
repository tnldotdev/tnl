package deviceauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginFollowsDeviceAuthorizationContract(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("request headers = %#v", request.Header)
		}
		switch request.URL.Path {
		case "/device/code":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["client_id"] != "tnl-cli" || body["scope"] != "tnl:core" {
				t.Errorf("device request = %#v", body)
			}
			_ = json.NewEncoder(response).Encode(map[string]any{
				"device_code": "device-code", "user_code": "ABCD2345",
				"verification_uri":          server.URL + "/device",
				"verification_uri_complete": server.URL + "/device?user_code=ABCD2345",
				"expires_in":                5, "interval": 1,
			})
		case "/device/token":
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["grant_type"] != "urn:ietf:params:oauth:grant-type:device_code" ||
				body["device_code"] != "device-code" || body["client_id"] != "tnl-cli" {
				t.Errorf("token request = %#v", body)
			}
			_ = json.NewEncoder(response).Encode(map[string]any{
				"access_token": "external-session", "token_type": "Bearer", "expires_in": 604800, "scope": "tnl:core",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	token, err := Login(context.Background(), Config{
		Issuer:                      server.URL,
		DeviceAuthorizationEndpoint: server.URL + "/device/code",
		TokenEndpoint:               server.URL + "/device/token", ClientID: "tnl-cli", Scope: "tnl:core",
		HTTPClient: server.Client(),
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if token != "external-session" || !strings.Contains(output.String(), "ABCD2345") ||
		!strings.Contains(output.String(), server.URL+"/device?user_code=ABCD2345") {
		t.Fatalf("token = %q, output = %q", token, output.String())
	}
}

func TestPollAcceptsBetterAuthErrorDescription(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(response).Encode(map[string]string{
			"error": "authorization_pending", "error_description": "Authorization is pending",
		})
	}))
	defer server.Close()

	_, code, err := poll(context.Background(), server.Client(), server.URL, "tnl-cli", "device-code")
	if code != "authorization_pending" || err == nil {
		t.Fatalf("code = %q, error = %v", code, err)
	}
}
