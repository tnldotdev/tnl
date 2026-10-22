package controlstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDeviceLoginStageTransitionsClearExchangeMaterial(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	l := DeviceLogin{Status: DevicePending, UserCode: "unchanged", ExpiresAt: now.Add(time.Minute)}
	binding := bytes.Repeat([]byte{1}, 32)
	exchange := deviceBrowserExchange{strings.Repeat("s", 43), strings.Repeat("n", 43), strings.Repeat("v", 43), binding}
	intent := &CompanyLoginIntent{ID: "intent", BindingToken: "binding", RedirectURI: "https://control.example/callback"}
	if err := l.beginBrowser(exchange, "team", intent); err != nil {
		t.Fatal(err)
	}
	identity := OIDCIdentity{Subject: "verified", AssertionExpiry: now.Add(time.Minute)}
	if err := l.verifyBrowser(binding, identity); !errors.Is(err, ErrDeviceLogin) {
		t.Fatal("identity was verified before the browser exchange was consumed", err)
	}
	if err := l.consumeBrowser(bytes.Repeat([]byte{2}, 32)); !errors.Is(err, ErrDeviceLogin) || l.State == "" {
		t.Fatal("wrong browser consumed the exchange", err)
	}
	if err := l.consumeBrowser(binding); err != nil {
		t.Fatal(err)
	}
	if err := l.consumeBrowser(binding); !errors.Is(err, ErrDeviceLogin) {
		t.Fatal("consumed exchange was reusable", err)
	}
	if err := l.verifyBrowser(binding, identity); err != nil {
		t.Fatal(err)
	}
	stage, err := l.stage()
	verified, ok := stage.(deviceVerifiedIdentity)
	if err != nil || !ok || verified.identity.CompanyIntent == nil || verified.identity.CompanyIntent.ID != intent.ID || l.Nonce != "" || l.Verifier != "" || l.State != "" {
		t.Fatalf("verified stage retained exchange material or lost company binding: %+v, %v", l, err)
	}
	if err := l.beginBrowser(exchange, "team", intent); !errors.Is(err, ErrDeviceLogin) {
		t.Fatal("browser restart replaced a verified identity", err)
	}
	l.issueSession(ControlSession{SessionID: "session"})
	stage, err = l.stage()
	if issued, ok := stage.(deviceIssuedSession); err != nil || !ok || issued.session.SessionID != "session" || l.Identity != nil || l.CompanyIntent != nil || len(l.Binding) != 0 {
		t.Fatalf("issued stage retained browser material: %+v, %v", l, err)
	}
	encoded, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	var restored DeviceLogin
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if stage, err := restored.stage(); err != nil {
		t.Fatal("unchanged persisted representation lost its stage", stage, err)
	}
	l.clearBrowser(DeviceCancelled)
	if _, err := l.stage(); err != nil || l.Session != nil || l.UserCode != "unchanged" || !l.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatal("cancellation did not retain only login metadata", err)
	}
}

func TestDeviceLoginStageRejectsMixedPayloads(t *testing.T) {
	for _, l := range []DeviceLogin{
		{Status: DevicePending, Session: &ControlSession{}},
		{Status: DevicePending, Identity: &OIDCIdentity{}},
		{Status: DevicePending, Binding: bytes.Repeat([]byte{1}, 32)},
		{Status: DeviceApproved},
		{Status: DeviceApproved, Session: &ControlSession{}, Identity: &OIDCIdentity{}},
		{Status: DeviceApproved, Session: &ControlSession{}, State: strings.Repeat("s", 43)},
		{Status: DeviceCancelled, Session: &ControlSession{}},
		{Status: DeviceDenied, CompanyIntent: &CompanyLoginIntent{}},
		{Status: "unknown"},
	} {
		if _, err := l.stage(); !errors.Is(err, ErrDeviceLogin) {
			t.Fatalf("mixed device payload accepted: %+v, %v", l, err)
		}
	}
}
