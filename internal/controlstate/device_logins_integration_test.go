package controlstate

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIntegrationDeviceLoginStagesAndAtomicCancellation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "device_stages")
	l, credential, err := d.CreateDeviceLogin(t.Context(), DeviceLoginOptions{}, now)
	if err != nil {
		t.Fatal(err)
	}
	state, nonce, verifier := strings.Repeat("s", 43), strings.Repeat("n", 43), strings.Repeat("v", 43)
	binding := bytes.Repeat([]byte{1}, 32)
	if err := d.BeginDeviceBrowser(t.Context(), l.UserCode, state, nonce, verifier, binding, "", nil, now); err != nil {
		t.Fatal(err)
	}
	identity := OIDCIdentity{Issuer: "https://identity.example", Subject: "device-subject", DisplayName: "Device user", AssertionDigest: sha256.Sum256([]byte("device-assertion")), AssertionExpiry: now.Add(time.Minute)}
	if err := d.VerifyDeviceBrowser(t.Context(), l.UserCode, binding, identity, now); !errors.Is(err, ErrDeviceLogin) {
		t.Fatal("verified before consuming upstream exchange", err)
	}
	consumed, err := d.ConsumeDeviceBrowser(t.Context(), state, binding, now)
	if err != nil || consumed.State != "" || consumed.Nonce != nonce || consumed.Verifier != verifier {
		t.Fatal("consumed exchange lost the one-use upstream inputs", err)
	}
	if _, err := d.ConsumeDeviceBrowser(t.Context(), state, binding, now); !errors.Is(err, ErrDeviceLogin) {
		t.Fatal("upstream exchange was replayed", err)
	}
	if err := d.ApproveDeviceLogin(t.Context(), l.UserCode, binding, "tunnels.example.test", time.Hour, 24*time.Hour, now); !errors.Is(err, ErrDeviceLogin) {
		t.Fatal("unverified exchange issued a session", err)
	}
	if err := d.VerifyDeviceBrowser(t.Context(), l.UserCode, binding, identity, now); err != nil {
		t.Fatal(err)
	}
	if err := d.ApproveDeviceLogin(t.Context(), l.UserCode, binding, "tunnels.example.test", time.Hour, 24*time.Hour, identity.AssertionExpiry); !errors.Is(err, ErrDeviceLogin) {
		t.Fatal("expired verified assertion issued a session", err)
	}
	if err := d.ApproveDeviceLogin(t.Context(), l.UserCode, binding, "tunnels.example.test", time.Hour, 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	issued, err := d.PollDeviceLogin(t.Context(), credential, now)
	if err != nil || issued.Status != DeviceApproved || issued.Session == nil || issued.Identity != nil || len(issued.Binding) != 0 || issued.State != "" || issued.Nonce != "" || issued.Verifier != "" {
		t.Fatalf("issued device result = %+v, %v", issued, err)
	}
	retry, err := d.PollDeviceLogin(t.Context(), credential, now)
	if err != nil || retry.Session == nil || retry.Session.AccessToken != issued.Session.AccessToken || retry.Session.RefreshToken != issued.Session.RefreshToken {
		t.Fatal("private poll changed the issued session", err)
	}
	if _, err := d.pool.Exec(t.Context(), `CREATE FUNCTION control.reject_device_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'device update rejected'; END $$; CREATE TRIGGER reject_device_update BEFORE UPDATE ON control.device_logins FOR EACH ROW EXECUTE FUNCTION control.reject_device_update()`); err != nil {
		t.Fatal(err)
	}
	if err := d.CancelDeviceLogin(t.Context(), credential, now); err == nil {
		t.Fatal("forced login persistence failure was ignored")
	}
	if _, err := d.AuthenticateAccessToken(t.Context(), issued.Session.AccessToken, now); err != nil {
		t.Fatal("failed cancellation committed session revocation", err)
	}
	if _, err := d.pool.Exec(t.Context(), `DROP TRIGGER reject_device_update ON control.device_logins`); err != nil {
		t.Fatal(err)
	}
	if err := d.CancelDeviceLogin(t.Context(), credential, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticateAccessToken(t.Context(), issued.Session.AccessToken, now); err == nil {
		t.Fatal("cancelled device session remained usable")
	}
	cancelled, err := d.PollDeviceLogin(t.Context(), credential, now)
	if err != nil || cancelled.Status != DeviceCancelled || cancelled.Session != nil || cancelled.Identity != nil || len(cancelled.Binding) != 0 {
		t.Fatal("cancellation retained an issued credential", err)
	}
}
