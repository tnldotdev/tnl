package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func deploymentFixture(t *testing.T) DeploymentCredential {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return DeploymentCredential{Version: 1, ControlURL: "https://control.example.test", Team: "acme", Approval: controlv1.DeploymentCredential{TeamId: "tm_" + strings.Repeat("a", 22), ClientId: "pub_" + strings.Repeat("a", 22), KeyId: "pkey_" + strings.Repeat("a", 22), GrantId: "pgrant_" + strings.Repeat("a", 22), ProjectKey: "shop", ExpiresAt: time.Now().Add(time.Hour)}, PrivateKey: base64.RawURLEncoding.EncodeToString(key)}
}

func TestDeploymentCredentialPortableSigningAndExactSelection(t *testing.T) {
	value := deploymentFixture(t)
	encoded, err := value.Encode()
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := ParseDeploymentCredential(encoded)
	if err != nil {
		t.Fatal(err)
	}
	public, err := recovered.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("exact connector proof")
	signature, err := recovered.Sign(message)
	if err != nil || !ed25519.Verify(public, message, signature) {
		t.Fatal("portable key changed", err)
	}
	if recovered.Subject() != (tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorRegisteredKey, GrantID: value.Approval.GrantId, KeyID: value.Approval.KeyId}) {
		t.Fatal("borrowed a human or provider subject")
	}
	for _, selected := range []string{"acme/shop", value.Approval.TeamId + "/shop"} {
		if err := recovered.SelectProject(selected); err != nil {
			t.Fatal(err)
		}
	}
	for _, selected := range []string{"other/shop", "acme/other", "shop", "acme/shop/other"} {
		if !errors.Is(recovered.SelectProject(selected), ErrDeploymentCredential) {
			t.Fatal("accepted another project", selected)
		}
	}
	for _, output := range []string{fmt.Sprint(recovered), fmt.Sprintf("%#v", recovered)} {
		if strings.Contains(output, recovered.PrivateKey) {
			t.Fatal("credential leaked to diagnostics")
		}
	}
}

func TestDeploymentCredentialTeamUsesAuthorityLabels(t *testing.T) {
	for _, team := range []string{"123studio", strings.Repeat("a", 33), strings.Repeat("a", 63)} {
		t.Run(team, func(t *testing.T) {
			value := deploymentFixture(t)
			value.Team = team
			encoded, err := value.Encode()
			if err != nil {
				t.Fatal("valid team could not export its credential", err)
			}
			recovered, err := ParseDeploymentCredential(encoded)
			if err != nil || recovered.Team != team {
				t.Fatal("valid team could not consume its credential", err)
			}
			if err := recovered.SelectProject(team + "/shop"); err != nil {
				t.Fatal("valid team could not select its project", err)
			}
		})
	}
	for _, team := range []string{"", "Acme", "-acme", "acme-", "acme.team", "acme_team", strings.Repeat("a", 64)} {
		t.Run("invalid-"+team, func(t *testing.T) {
			value := deploymentFixture(t)
			value.Team = team
			if _, err := value.Encode(); !errors.Is(err, ErrDeploymentCredential) {
				t.Fatal("invalid team exported a credential", err)
			}
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseDeploymentCredential(deploymentTokenPrefix + base64.RawURLEncoding.EncodeToString(data)); !errors.Is(err, ErrDeploymentCredential) {
				t.Fatal("invalid team consumed a credential", err)
			}
		})
	}
}

func TestDeploymentCredentialRejectsInvalidOrExpiredInput(t *testing.T) {
	value := deploymentFixture(t)
	for _, change := range []func(*DeploymentCredential){
		func(v *DeploymentCredential) { v.Version++ },
		func(v *DeploymentCredential) { v.ControlURL = "http://control.example.test" },
		func(v *DeploymentCredential) { v.ControlURL += "/" },
		func(v *DeploymentCredential) { v.Approval.ExpiresAt = time.Now().Add(-time.Second) },
		func(v *DeploymentCredential) { v.Approval.KeyId = "not-a-key" },
		func(v *DeploymentCredential) {
			v.PrivateKey = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize))
		},
	} {
		v := value
		change(&v)
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseDeploymentCredential(deploymentTokenPrefix + base64.RawURLEncoding.EncodeToString(data)); !errors.Is(err, ErrDeploymentCredential) {
			t.Fatal("accepted invalid portable credential", err)
		}
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	data = append([]byte(`{"unexpected":true,`), data[1:]...)
	if _, err := ParseDeploymentCredential(deploymentTokenPrefix + base64.RawURLEncoding.EncodeToString(data)); !errors.Is(err, ErrDeploymentCredential) {
		t.Fatal("accepted unknown private credential field", err)
	}
}

func TestDeploymentCredentialRegistrationRetainsOriginalProtectedKeyAfterLostReply(t *testing.T) {
	value := deploymentFixture(t)
	value.Team = "123" + strings.Repeat("a", 60)
	var public string
	calls := 0
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Idempotency-Key") != "original" || r.URL.Query().Get("team_id") != value.Approval.TeamId {
			t.Error("registration lost original request selection")
		}
		var body controlv1.RegisterDeploymentCredentialRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if public == "" {
			public = body.PublicKey
		} else if public != body.PublicKey {
			t.Fatal("lost registration reply rotated the signing key")
		}
		if calls == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		return jsonResponse(http.StatusCreated, value.Approval), nil
	})
	control, err := clientcontrol.NewExternallyAuthenticated(testControlOrigin, f.config.HTTPClient)
	if err != nil {
		t.Fatal(err)
	}
	body := controlv1.RegisterDeploymentCredentialRequest{Name: "backend", ExpiresIn: 3600}
	body.AllDeployments = new(controlv1.RegisterDeploymentCredentialRequestAllDeployments(true))
	body.Permissions.Connect = new(controlv1.DeploymentCredentialServiceSelection{"db"})
	register := func() (DeploymentCredential, error) {
		return RegisterDeploymentCredential(t.Context(), f.store, control, testControlOrigin, value.Approval.TeamId, value.Team, "shop", "original", body)
	}
	if _, err := register(); err == nil {
		t.Fatal("lost reply was reported as success")
	}
	recovered, err := register()
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Team != value.Team || recovered.SelectProject(value.Team+"/shop") != nil {
		t.Fatal("registration lost the authority team label")
	}
	key, err := recovered.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if base64.RawURLEncoding.EncodeToString(key) != public {
		t.Fatal("exported another signing key")
	}
	again, err := register()
	if err != nil {
		t.Fatal(err)
	}
	one, err := recovered.Encode()
	if err != nil {
		t.Fatal(err)
	}
	two, err := again.Encode()
	if err != nil || one != two {
		t.Fatal("original-key recovery changed credential or deadline", err)
	}
}
