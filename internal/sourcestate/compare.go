package sourcestate

import "github.com/tnldotdev/tnl/pkg/api/controlv1"

type Comparison string

const (
	Matches      Comparison = "matches"
	Different    Comparison = "different"
	Inconclusive Comparison = "inconclusive"
)

// Compare uses the commit, project path, and file identifiers. branch names and
// whether changes were staged do not identify different source contents.
func Compare(current, recorded controlv1.SourceState) Comparison {
	if !comparable(current) || !comparable(recorded) {
		return Inconclusive
	}
	if current.HeadCommit != recorded.HeadCommit || current.ProjectPath != recorded.ProjectPath || len(current.ChangedFiles) != len(recorded.ChangedFiles) {
		return Different
	}
	for index, file := range current.ChangedFiles {
		other := recorded.ChangedFiles[index]
		if file.Path != other.Path || file.Status != other.Status || stringValue(file.BlobId) != stringValue(other.BlobId) || stringValue(file.Mode) != stringValue(other.Mode) {
			return Different
		}
	}
	return Matches
}

func comparable(state controlv1.SourceState) bool {
	if state.SchemaVersion != 1 || !state.Complete || !validObjectID(state.HeadCommit) || len(state.ChangedFiles) > maximumFiles || state.ChangedFiles == nil || state.ProjectPath != "" && !validPath(state.ProjectPath) {
		return false
	}
	previous := ""
	for _, file := range state.ChangedFiles {
		if !validPath(file.Path) || file.Path <= previous || !file.Status.Valid() {
			return false
		}
		if file.Status == controlv1.Deleted {
			if file.BlobId != nil || file.Mode != nil {
				return false
			}
		} else if !validObjectID(stringValue(file.BlobId)) || len(stringValue(file.BlobId)) != len(state.HeadCommit) || stringValue(file.Mode) != "100644" && stringValue(file.Mode) != "100755" {
			return false
		}
		previous = file.Path
	}
	return true
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
