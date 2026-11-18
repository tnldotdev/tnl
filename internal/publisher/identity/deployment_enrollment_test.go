package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type enrollmentFiles struct {
	data                 []byte
	locked               bool
	failWrite, failClose error
	writes               int
}
type enrollmentUnlock struct{ files *enrollmentFiles }

func (l enrollmentUnlock) Close() error { l.files.locked = false; return l.files.failClose }
func (f *enrollmentFiles) Lock(context.Context, string) (io.Closer, error) {
	if f.locked {
		return nil, ErrScope
	}
	f.locked = true
	return enrollmentUnlock{f}, nil
}
func (f *enrollmentFiles) Read(context.Context, string, int64) ([]byte, bool, error) {
	return bytes.Clone(f.data), f.data != nil, nil
}
func (f *enrollmentFiles) Write(_ context.Context, _ string, data []byte) error {
	f.writes++
	if f.failWrite != nil {
		return f.failWrite
	}
	f.data = bytes.Clone(data)
	return nil
}

type enrollmentBackend struct {
	files             *enrollmentFiles
	member            controlv1.DeploymentPublisherIdentity
	public            ed25519.PublicKey
	enrolls, verifies int
	lost              bool
	verifyErr         error
}

func (b *enrollmentBackend) RedeemScopedDeploymentPublisherEnrollment(_ context.Context, _ string, public ed25519.PublicKey, deployment, project string) (controlv1.DeploymentPublisherIdentity, error) {
	if b.files.data == nil {
		panic("signing key was not durable before redemption")
	}
	b.enrolls++
	if deployment != b.member.DeploymentId || project != b.member.ProjectKey {
		return controlv1.DeploymentPublisherIdentity{}, ErrScope
	}
	if b.public != nil && !bytes.Equal(b.public, public) {
		return controlv1.DeploymentPublisherIdentity{}, ErrScope
	}
	b.public = bytes.Clone(public)
	if b.lost {
		b.lost = false
		return controlv1.DeploymentPublisherIdentity{}, io.ErrUnexpectedEOF
	}
	return b.member, nil
}
func (b *enrollmentBackend) VerifyDeploymentIdentity(_ context.Context, r controlv1.DeploymentPublisherLeaseRequest) (controlv1.DeploymentPublisherVerification, error) {
	b.verifies++
	if _, err := publisherproof.Verify(r.Assertion, b.member.PublisherIdentityId, b.member.KeyId, b.member.DeploymentId, "https://control.example/v1/publisher/deployments/verify", b.public, time.Now()); err != nil {
		return controlv1.DeploymentPublisherVerification{}, err
	}
	return controlv1.DeploymentPublisherVerification{Member: b.member, DeploymentNames: []string{"production"}}, b.verifyErr
}
func enrollmentFixture() (*enrollmentFiles, *enrollmentBackend, EnrollmentSelection, string) {
	files := &enrollmentFiles{}
	backend := &enrollmentBackend{files: files, member: controlv1.DeploymentPublisherIdentity{TeamId: "team", ProjectKey: "example", DeploymentId: "dpl_" + strings.Repeat("d", 22), DeploymentName: "production", PublisherIdentityId: "pub_" + strings.Repeat("p", 22), KeyId: "pkey_" + strings.Repeat("k", 22)}}
	return files, backend, EnrollmentSelection{ControlURL: "https://control.example", ProjectKey: "example", DeploymentID: backend.member.DeploymentId, Instance: "browser"}, "pen_" + strings.Repeat("e", 22) + ".private-bootstrap"
}
func TestEnrolledIdentityRetainsPendingKeyAndReloadsWithoutBootstrap(t *testing.T) {
	files, backend, selection, secret := enrollmentFixture()
	backend.lost = true
	if _, err := OpenEnrolledIdentity(t.Context(), files, backend, selection, secret); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if files.locked || backend.enrolls != 1 || files.writes != 1 {
		t.Fatal("failed redemption lost pending state or lock")
	}
	if bytes.Contains(files.data, []byte(secret)) {
		t.Fatal("durable record retained bootstrap secret")
	}
	if _, err := OpenEnrolledIdentity(t.Context(), files, backend, selection, secret+"-changed"); !errors.Is(err, ErrScope) || backend.enrolls != 1 || files.locked {
		t.Fatal("pending recovery accepted a different enrollment key", err)
	}
	owner, err := OpenEnrolledIdentity(t.Context(), files, backend, selection, secret)
	if err != nil {
		t.Fatal(err)
	}
	first := bytes.Clone(owner.Private)
	if _, err := OpenEnrolledIdentity(t.Context(), files, backend, selection, secret); !errors.Is(err, ErrScope) {
		t.Fatal("competing owner admitted", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(owner.Private, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("released owner retained key")
	}
	reloaded, err := OpenEnrolledIdentity(t.Context(), files, backend, selection, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if !bytes.Equal(first, reloaded.Private) || reloaded.Member != owner.Member || backend.enrolls != 2 || backend.verifies != 2 {
		t.Fatal("reload redeemed again or changed signing identity")
	}
}
func TestEnrolledIdentityStorageAndDenialNeverReplaceKey(t *testing.T) {
	files, backend, selection, secret := enrollmentFixture()
	files.failWrite = io.ErrClosedPipe
	if _, err := OpenEnrolledIdentity(t.Context(), files, backend, selection, secret); !errors.Is(err, io.ErrClosedPipe) || backend.enrolls != 0 {
		t.Fatal("undurable key was redeemed", err)
	}
	files.failWrite = nil
	owner, err := OpenEnrolledIdentity(t.Context(), files, backend, selection, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	saved := bytes.Clone(files.data)
	backend.verifyErr = ErrScope
	if _, err := OpenEnrolledIdentity(t.Context(), files, backend, selection, secret); !errors.Is(err, ErrScope) || backend.enrolls != 1 || !bytes.Equal(saved, files.data) || files.locked {
		t.Fatal("denied identity fell back to bootstrap", err)
	}
	files.data = []byte(`{"version":1,"private_key":"malformed"}`)
	if _, err := OpenPublisherIdentity(t.Context(), files, func(string) (EnrollmentControl, error) {
		return backend, nil
	}, selection, func(context.Context) (string, error) {
		t.Error("corrupt identity called the bootstrap source")
		return secret, nil
	}); !errors.Is(err, ErrScope) || backend.enrolls != 1 {
		t.Fatal("corrupt record replaced its identity", err)
	}
}
