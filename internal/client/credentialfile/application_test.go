package credentialfile

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestApplicationResponseOwnsAllGrantPointers(t *testing.T) {
	f := fixture(t)
	key, err := f.Validate()
	if err != nil {
		t.Fatal(err)
	}
	application := controlv1.RegisteredApplication{ClientId: f.ClientID, KeyId: f.KeyID, TeamId: f.TeamID, Grants: []controlv1.PublisherGrant{
		{Id: f.Grants[0].ID, Operation: controlv1.ApplicationPublish, Kind: controlv1.PublisherGrantKindSavedPublicUrl, PublicUrlId: new(*f.Grants[0].PublicURLID), ExpiresAt: new(time.Now().Add(time.Hour))},
		{Id: "pgrant_" + strings.Repeat("S", 22), Operation: controlv1.ApplicationVisit, Kind: controlv1.PublisherGrantKindService, ServiceId: new("svc_" + strings.Repeat("S", 22))},
		{Id: "pgrant_" + strings.Repeat("N", 22), Operation: controlv1.ApplicationAllocate, Kind: controlv1.PublisherGrantKindNamespace, DomainId: new("dom_" + strings.Repeat("N", 22)), Namespace: new("member.example.test")},
	}}
	document, err := NewApplication(f.ControlURL, application, key)
	if err != nil {
		t.Fatal(err)
	}
	untouched, err := NewApplication(f.ControlURL, application, key)
	if err != nil {
		t.Fatal(err)
	}
	*application.Grants[0].PublicUrlId = "changed"
	*application.Grants[0].ExpiresAt = time.Time{}
	*application.Grants[1].ServiceId = "changed"
	*application.Grants[2].DomainId = "changed"
	*application.Grants[2].Namespace = "changed"
	if !reflect.DeepEqual(document, untouched) {
		t.Fatal("response mutation changed a prepared credential")
	}
	*document.Grants[0].PublicURLID = "changed again"
	*document.Grants[0].ExpiresAt = time.Time{}
	*document.Grants[1].ServiceID = "changed again"
	*document.Grants[2].DomainID = "changed again"
	*document.Grants[2].Namespace = "changed again"
	if _, err := untouched.Validate(); err != nil {
		t.Fatal("independent preparations shared pointers", err)
	}
}

func TestApplicationResponseAllowsEmptyAuthorityButNotExecutableCredential(t *testing.T) {
	f := fixture(t)
	key, err := f.Validate()
	if err != nil {
		t.Fatal(err)
	}
	application := controlv1.RegisteredApplication{ClientId: f.ClientID, KeyId: f.KeyID, TeamId: f.TeamID, Grants: []controlv1.PublisherGrant{}}
	if grants, err := ApplicationGrants(application); err != nil || len(grants) != 0 {
		t.Fatal("fully narrowed response was rejected", err)
	}
	if _, err := NewApplication(f.ControlURL, application, key); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty authority became an executable credential", err)
	}
}
