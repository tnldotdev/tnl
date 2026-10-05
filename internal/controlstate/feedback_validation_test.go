package controlstate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFeedbackEvidenceDropsExecutableMarkupAndFormValues(t *testing.T) {
	element, err := normalizeFeedbackElement(json.RawMessage(`{"kind":"element","role":"button","label":"Save","html":"<div onclick='steal()'><button data-testid='save' formaction='javascript:steal()'>Save</button><input type='password' value='secret'><script>alert('secret')</script><textarea>typed secret</textarea></div>"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"onclick", "formaction", "javascript:", "value=", "typed secret", "<script>", "alert("} {
		if strings.Contains(string(element), forbidden) {
			t.Fatalf("submitted element contains %q: %s", forbidden, element)
		}
	}
	if !strings.Contains(string(element), `data-testid`) || !strings.Contains(string(element), "Save") {
		t.Fatalf("sanitizer discarded meaningful element context: %s", element)
	}
	if _, err := normalizeFeedbackEvidence(json.RawMessage(`{"actions":[],"failed_requests":[{"method":"GET","path":"/api/users?token=secret","status":500,"duration_ms":20}]}`)); err == nil {
		t.Fatal("failed request query carrying credentials was stored")
	}
}

func TestFeedbackCheckoutMarkerStoresHashesAndRejectsPathsOutsideProject(t *testing.T) {
	marker := feedbackTestCheckout(t)
	if _, err := normalizeCheckoutMarker(marker); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/Users/dev/.env", "../secrets", "apps\\web\\secret"} {
		var value map[string]any
		if err := json.Unmarshal(marker, &value); err != nil {
			t.Fatal(err)
		}
		files := value["changed_files"].([]any)
		files[0].(map[string]any)["path"] = path
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := normalizeCheckoutMarker(encoded); err == nil {
			t.Fatalf("checkout marker escaped project with path %q", path)
		}
	}
}
