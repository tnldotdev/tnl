package controlstate

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestFeedbackEvidenceDropsExecutableMarkupAndFormValues(t *testing.T) {
	element, err := normalizeFeedbackElement(json.RawMessage(`{"role":"button","label":"Save","html":"<div onclick='steal()'><button data-testid='save' formaction='javascript:steal()'>Save</button><input type='password' value='secret'><script>alert('secret')</script><textarea>typed secret</textarea></div>"}`))
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
	if _, err := normalizeFeedbackEvidence(json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[{"method":"GET","path":"/api/users?token=secret","status":500,"duration_ms":20}]}`)); err == nil {
		t.Fatal("failed request query carrying credentials was stored")
	}
}

func TestFeedbackConversationTransitions(t *testing.T) {
	for _, actor := range []string{"implementer", "reviewer"} {
		for _, transition := range []struct {
			state FeedbackThreadState
			event FeedbackEventType
			want  FeedbackThreadState
		}{
			{FeedbackOpen, FeedbackReply, FeedbackOpen},
			{FeedbackOpen, FeedbackThreadResolved, FeedbackResolved},
			{FeedbackResolved, FeedbackThreadReopened, FeedbackOpen},
			{FeedbackResolved, FeedbackReply, ""},
			{FeedbackOpen, FeedbackThreadReopened, ""},
			{FeedbackResolved, FeedbackThreadResolved, ""},
		} {
			got, err := nextFeedbackState(transition.state, transition.event, actor)
			if got != transition.want || (transition.want == "" && !errors.Is(err, ErrFeedbackState)) || (transition.want != "" && err != nil) {
				t.Fatalf("%s: %s + %s = %s, %v", actor, transition.state, transition.event, got, err)
			}
		}
	}
	if got, err := nextFeedbackState(FeedbackOpen, FeedbackUpdate, "implementer"); err != nil || got != FeedbackOpen {
		t.Fatalf("source update changed state: %s, %v", got, err)
	}
	if validFeedbackEventPayload(AppendFeedbackRequest{Type: FeedbackUpdate, Text: "forged", SourceState: feedbackTestSource(t), Actor: FeedbackActor{Kind: "reviewer"}}) {
		t.Fatal("preview access can forge an implementer source update")
	}
}

func TestFeedbackSourceStateRejectsPathsOutsideProject(t *testing.T) {
	source := feedbackTestSource(t)
	if _, err := normalizeSourceState(source); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/Users/dev/.env", "../secrets", "apps\\web\\secret"} {
		var value map[string]any
		if err := json.Unmarshal(source, &value); err != nil {
			t.Fatal(err)
		}
		files := value["changed_files"].([]any)
		files[0].(map[string]any)["path"] = path
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := normalizeSourceState(encoded); err == nil {
			t.Fatalf("source state escaped project with path %q", path)
		}
	}
}

func TestFeedbackSourceStateRequiresComparableCompleteFiles(t *testing.T) {
	for _, change := range []func(*SourceState){
		func(state *SourceState) { state.HeadCommit = "" },
		func(state *SourceState) { state.ProjectPath = "../other" },
		func(state *SourceState) { state.ChangedFiles[0].BlobID = "" },
		func(state *SourceState) { state.ChangedFiles[0].BlobID = strings.Repeat("b", 64) },
		func(state *SourceState) { state.ChangedFiles[0].Mode = "120000" },
		func(state *SourceState) { state.ChangedFiles[0].Status = "deleted" },
		func(state *SourceState) { state.ChangedFiles = append(state.ChangedFiles, state.ChangedFiles[0]) },
	} {
		var state SourceState
		if err := json.Unmarshal(feedbackTestSource(t), &state); err != nil {
			t.Fatal(err)
		}
		change(&state)
		encoded, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := normalizeSourceState(encoded); err == nil {
			t.Fatalf("invalid complete source state accepted: %s", encoded)
		}
	}
	partial := json.RawMessage(`{"schema_version":1,"head_commit":"","project_path":"","branch":"","changed_files":[],"complete":false}`)
	if _, err := normalizeSourceState(partial); err != nil {
		t.Fatalf("source outside Git must remain explicitly incomplete: %v", err)
	}
}

func TestFeedbackAnchorVersionAndBounds(t *testing.T) {
	valid := json.RawMessage(`{"schema_version":1,"selectors":["#intro","body>p:first-of-type"],"x":0.25,"y":0.75,"selection":{"start":{"selectors":["#intro"],"text_node":0,"offset":1},"end":{"selectors":["#intro>strong"],"text_node":0,"offset":4},"text":"orl"}}`)
	if _, err := normalizeFeedbackAnchor(valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(map[string]any){
		func(value map[string]any) { delete(value, "schema_version") },
		func(value map[string]any) { value["schema_version"] = 2 },
		func(value map[string]any) { value["x"] = 1.1 },
		func(value map[string]any) { value["y"] = -0.1 },
		func(value map[string]any) { value["selectors"] = []string{} },
		func(value map[string]any) { value["selectors"] = []string{"#a", "#a"} },
		func(value map[string]any) {
			value["selection"].(map[string]any)["start"].(map[string]any)["offset"] = -1
		},
	} {
		var value map[string]any
		_ = json.Unmarshal(valid, &value)
		change(value)
		encoded, _ := json.Marshal(value)
		if _, err := normalizeFeedbackAnchor(encoded); err == nil {
			t.Fatalf("invalid anchor accepted: %s", encoded)
		}
	}
	if value, err := normalizeFeedbackAnchor(nil); err != nil || value != nil {
		t.Fatal("page feedback requires no anchor")
	}
}
