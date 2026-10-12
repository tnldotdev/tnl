package main

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestContainerAppEndpointUsesOnlyTheScopedCredentialAndPrivateComposeOrigin(t *testing.T) {
	port := 3781
	publisher := config.ProjectPublisher{Type: "docker", DockerSelection: config.DockerSelection{
		Compose: &config.ComposeSelection{File: "compose.yaml", Project: "shop-k7n2p9", Service: "publisher"}, ContainerPort: &port,
	}}
	owner, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	app, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := containerAppEndpoint(publisher, localPublisherEndpoint{Version: 1, URL: "http://127.0.0.1:49153", Credential: app})
	if err != nil || endpoint.URL != "http://publisher:3781" || endpoint.Credential != app || endpoint.Credential == owner {
		t.Fatalf("exported Compose app endpoint = %+v, %v", endpoint, err)
	}
	publisher.Compose = nil
	if _, err := containerAppEndpoint(publisher, endpoint); err == nil {
		t.Fatal("allowed an app endpoint without a Compose publisher service")
	}
}
