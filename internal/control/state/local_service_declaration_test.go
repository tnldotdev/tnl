package state

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestLocalServiceMountUsesLogicalKeyNotSavedName(t *testing.T) {
	declaration := LocalServiceDeclaration{Name: "saved-name", Protocol: "http", Target: "app", PublicURL: &ProjectServicePublicURL{}, HTTP: &config.HTTPService{Paths: map[string]config.PathMount{"/api": {Service: "web"}}}}
	if _, err := normalizeLocalService("web", declaration); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("mount accepted its own logical service when saved name differs", err)
	}
	declaration.HTTP.Paths["/api"] = config.PathMount{Service: "saved-name"}
	if _, err := normalizeLocalService("web", declaration); err != nil {
		t.Fatal("another logical service was confused with the saved name", err)
	}
}
