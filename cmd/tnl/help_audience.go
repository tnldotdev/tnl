package main

import (
	"os"
	"strings"
	"unicode"
)

type helpAudience string

const (
	helpHuman helpAudience = "human"
	helpAgent helpAudience = "agent"
)

func currentHelpAudience(explicit helpAudience) helpAudience {
	return resolveHelpAudience(explicit, os.Getenv, func(path string) error {
		_, err := os.Stat(path)
		return err
	})
}

// follow @vercel/detect-agent at 84878e532142f0ac584953695658b324eb9e5b80,
// but retain only the help audience.
func resolveHelpAudience(explicit helpAudience, getenv func(string) string, checkExists func(string) error) helpAudience {
	if explicit != "" {
		return explicit
	}
	set := func(keys ...string) bool {
		for _, key := range keys {
			if getenv(key) != "" {
				return true
			}
		}
		return false
	}
	switch {
	case strings.TrimFunc(getenv("AI_AGENT"), agentHintSpace) != "":
		return helpAgent
	case set("CURSOR_TRACE_ID"):
		return helpAgent
	case set("CURSOR_AGENT") || getenv("CURSOR_EXTENSION_HOST_ROLE") == "agent-exec":
		return helpAgent
	case set("GEMINI_CLI"):
		return helpAgent
	case set("CODEX_SANDBOX", "CODEX_CI", "CODEX_THREAD_ID"):
		return helpAgent
	case set("ANTIGRAVITY_AGENT"):
		return helpAgent
	case set("AUGMENT_AGENT"):
		return helpAgent
	case getenv("OPENCODE") == "1" || set("OPENCODE_CLIENT"):
		return helpAgent
	case set("CLAUDECODE", "CLAUDE_CODE"):
		// Claude and Cowork select the same audience.
		return helpAgent
	case set("REPL_ID"):
		return helpAgent
	case set("COPILOT_MODEL", "COPILOT_ALLOW_ALL", "COPILOT_GITHUB_TOKEN"):
		return helpAgent
	case checkExists("/opt/.devin") == nil:
		return helpAgent
	default:
		return helpHuman
	}
}

// JavaScript's trim includes the BOM but not the Unicode next-line character.
func agentHintSpace(r rune) bool { return r == '\uFEFF' || r != '\u0085' && unicode.IsSpace(r) }
