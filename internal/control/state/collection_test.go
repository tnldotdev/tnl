package state

import (
	"bytes"
	"errors"
	"testing"
)

func TestCollectionSelectionRequiresExplicitScopeAndPrecondition(t *testing.T) {
	base := CreateEnvironmentRequest{ProjectKey: "project", SourceFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "environment", DefinitionRevision: 1}
	for _, change := range []func(*CreateEnvironmentRequest){
		func(r *CreateEnvironmentRequest) { r.DefinitionRevision = 0 },
		func(r *CreateEnvironmentRequest) { r.ExpectedCollectionRevision = 1 },
		func(r *CreateEnvironmentRequest) {
			r.CollectionID = "env_AAAAAAAAAAAAAAAAAAAAAA"
			r.ExpectedCollectionRevision = 1
		},
		func(r *CreateEnvironmentRequest) { r.CollectionID = "coll_AAAAAAAAAAAAAAAAAAAAAA" },
		func(r *CreateEnvironmentRequest) {
			r.CollectionID = "coll_AAAAAAAAAAAAAAAAAAAAAA"
			r.ExpectedCollectionRevision = -1
		},
		func(r *CreateEnvironmentRequest) {
			r.CollectionID = "coll_AAAAAAAAAAAAAAAAAAAAAA"
			r.ExpectedCollectionRevision = 1
			r.DefinitionRevision = -1
		},
	} {
		r := base
		change(&r)
		if _, err := (&Database{}).CreateEnvironment(t.Context(), r); !errors.Is(err, ErrEnvironmentInvalid) {
			t.Fatal("invalid collection selection reached the database", r, err)
		}
	}
	for _, revision := range []int64{0, -1, 1<<63 - 1} {
		_, err := (&Database{}).UpdateCollectionDefault(t.Context(), UpdateCollectionDefaultRequest{ProjectKey: "project", CollectionID: "coll_AAAAAAAAAAAAAAAAAAAAAA", ExpectedRevision: revision, DefinitionRevision: 1})
		if !errors.Is(err, ErrCollectionInvalid) {
			t.Fatal("invalid default update precondition reached the database", revision, err)
		}
	}
}

func TestCollectionCreationDigestPinsMembershipAndSelectionMode(t *testing.T) {
	bindings := environmentBindings{"api": {Target: "internal:3000", protocol: "http"}}
	endpoint := environmentEndpointSettings{}
	original := environmentCreationDigest("member", 0, bindings, "coll_AAAAAAAAAAAAAAAAAAAAAA", 1, endpoint)
	for _, changed := range [][]byte{
		environmentCreationDigest("member", 1, bindings, "coll_AAAAAAAAAAAAAAAAAAAAAA", 1, endpoint),
		environmentCreationDigest("member", 0, bindings, "coll_BBBBBBBBBBBBBBBBBBBBBB", 1, endpoint),
		environmentCreationDigest("member", 0, bindings, "", 1, endpoint),
		environmentCreationDigest("member", 0, bindings, "coll_AAAAAAAAAAAAAAAAAAAAAA", 2, endpoint),
		environmentCreationDigest("member", 0, bindings, "coll_AAAAAAAAAAAAAAAAAAAAAA", 1, environmentEndpointSettings{Public: true}),
		environmentCreationDigest("member", 0, bindings, "coll_AAAAAAAAAAAAAAAAAAAAAA", 1, environmentEndpointSettings{DomainID: "another-domain"}),
	} {
		if bytes.Equal(original, changed) {
			t.Fatal("creation digest did not pin membership, definition selection and collection precondition")
		}
	}
	for input, expected := range map[error]error{ErrProjectConfigurationInvalid: ErrCollectionInvalid, ErrServiceDefinitionInvalid: ErrCollectionInvalid} {
		if !errors.Is(collectionOperationError(input), expected) {
			t.Fatal("wrong collection diagnostic", input)
		}
	}
}
