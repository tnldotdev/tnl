package observability

import (
	"embed"
	"io/fs"
	"strings"
)

// DatabaseOperationName can only come from a compiled SQL source catalog. it
// carries the name alone, never SQL, arguments, or a backing provider buffer.
type DatabaseOperationName struct{ name operationName }

func (v DatabaseOperationName) String() string {
	if v.name == "" {
		return "unknown"
	}
	return v.name.String()
}

type DatabaseOperationCatalog struct {
	names map[string]DatabaseOperationName
}

// DatabaseOperations reads sqlc declarations embedded in the caller's binary.
// accepting embed.FS rather than fs.FS keeps runtime files and supplied strings
// out of this authoring boundary. Lookup validates driver names against it.
func DatabaseOperations(sources embed.FS) DatabaseOperationCatalog {
	catalog := DatabaseOperationCatalog{names: make(map[string]DatabaseOperationName)}
	_ = fs.WalkDir(sources, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}
		data, err := sources.ReadFile(path)
		if err != nil {
			return err
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 4 || fields[0] != "--" || fields[1] != "name:" {
				continue
			}
			name := fields[2]
			if len(name) == 0 || len(name) > 128 {
				continue
			}
			valid := true
			for _, c := range name {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
					valid = false
					break
				}
			}
			if valid {
				name = strings.Clone(name)
				catalog.names[name] = DatabaseOperationName{operationName(name)}
			}
		}
		return nil
	})
	return catalog
}

func (c DatabaseOperationCatalog) Contains(name string) bool {
	_, ok := c.names[name]
	return ok
}

// Lookup never retains an unknown input, even when it resembles a query name.
func (c DatabaseOperationCatalog) Lookup(name string) DatabaseOperationName {
	switch name {
	case "begin":
		return DatabaseOperationName{"begin"}
	case "commit":
		return DatabaseOperationName{"commit"}
	case "rollback":
		return DatabaseOperationName{"rollback"}
	}
	return c.names[name]
}

func (v DatabaseOperationName) operation() operationName { return operationName(v.String()) }
