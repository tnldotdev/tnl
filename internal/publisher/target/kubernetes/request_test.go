package kubernetes

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClassificationOmitsUnboundedNamesAndQueries(t *testing.T) {
	for _, path := range []string{
		"/api/v1/namespaces/customer-secret/pods/private-pod/exec?command=private-command&stdin=true",
		"/apis/customer-secret.example/v1/namespaces/customer-secret/private-resource/private-object?token=private-token",
	} {
		c := Classify(httptest.NewRequest("GET", path, nil))
		if strings.Contains(c.Verb+c.APIGroup+c.Resource+c.Subresource, "private") || strings.Contains(c.APIGroup, "customer") {
			t.Fatal("unbounded identity entered classification")
		}
	}
	watch := Classify(httptest.NewRequest("GET", "/apis/apps/v1/namespaces/dev/deployments?watch=true", nil))
	if !watch.LongRunning || watch.Verb != "watch" || watch.APIGroup != "apps" || watch.Resource != "deployments" {
		t.Fatal("rollout watch classification failed")
	}
}
