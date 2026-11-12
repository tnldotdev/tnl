package meta

import "encoding/json"

const GeneratedDirectoryName = ".tnl/generated"

func typeScriptString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
