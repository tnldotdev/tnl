package controlv1

import (
	"encoding/json"
	"strconv"
)

// RevisionList keeps revisions numeric in Go and exact decimal strings in JSON.
// encoding/json's string field option does not apply to slice elements.
type RevisionList []int64

func (revisions RevisionList) MarshalJSON() ([]byte, error) {
	if revisions == nil {
		return []byte("null"), nil
	}
	values := make([]string, len(revisions))
	for i, revision := range revisions {
		values[i] = strconv.FormatInt(revision, 10)
	}
	return json.Marshal(values)
}

func (revisions *RevisionList) UnmarshalJSON(data []byte) error {
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	if values == nil {
		*revisions = nil
		return nil
	}
	result := make(RevisionList, len(values))
	for i, value := range values {
		revision, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		result[i] = revision
	}
	*revisions = result
	return nil
}
