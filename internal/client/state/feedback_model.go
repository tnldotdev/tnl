package state

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming"
)

const ReviewSchemaVersion = 1

var (
	ErrFeedbackNotFound    = errors.New("clientstate: feedback thread not found")
	ErrFeedbackInvalid     = errors.New("clientstate: feedback request is invalid")
	ErrFeedbackAccess      = errors.New("clientstate: feedback access denied")
	ErrFeedbackIdempotency = errors.New("clientstate: feedback idempotency conflict")
	ErrFeedbackState       = errors.New("clientstate: feedback state changed")
)

type FeedbackThreadState string
type FeedbackEventType string

const (
	FeedbackOpen           FeedbackThreadState = "open"
	FeedbackResolved       FeedbackThreadState = "resolved"
	FeedbackCreated        FeedbackEventType   = "thread.created"
	FeedbackReply          FeedbackEventType   = "reply"
	FeedbackUpdate         FeedbackEventType   = "update"
	FeedbackThreadResolved FeedbackEventType   = "thread.resolved"
	FeedbackThreadReopened FeedbackEventType   = "thread.reopened"
)

func (state FeedbackThreadState) transition(event FeedbackEventType) (FeedbackThreadState, error) {
	switch event {
	case FeedbackReply:
		if state == FeedbackOpen || state == FeedbackResolved {
			return state, nil
		}
	case FeedbackUpdate:
		if state == FeedbackOpen {
			return state, nil
		}
	case FeedbackThreadReopened:
		if state == FeedbackResolved {
			return FeedbackOpen, nil
		}
	case FeedbackThreadResolved:
		if state == FeedbackOpen {
			return FeedbackResolved, nil
		}
	}
	return "", ErrFeedbackState
}

func validFeedbackPath(value string) bool {
	return naming.ValidRequestPath(value)
}
func validFeedbackKey(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && strings.TrimSpace(value) == value
}
func validFeedbackText(value string, maxLength int) bool {
	return strings.TrimSpace(value) != "" && len([]rune(value)) <= maxLength && !strings.ContainsRune(value, '\x00')
}
func validFeedbackJSON(value json.RawMessage, maxBytes int) bool {
	return len(value) >= 2 && len(value) <= maxBytes && value[0] == '{' && json.Valid(value)
}

func localFeedbackPermits(actor, operation string) bool {
	if actor != "reviewer" && actor != "implementer" {
		return false
	}
	switch operation {
	case "read", "reply", "thread.resolved", "thread.reopened":
		return true
	case "report":
		return actor == "reviewer"
	case "update", "delete":
		return actor == "implementer"
	}
	return false
}

func validLocalFeedbackPayload(actor, operation, text string, source json.RawMessage) bool {
	return localFeedbackPermits(actor, operation) && (operation != "reply" && operation != "update" || validFeedbackText(text, 4000)) &&
		(operation == "update") == (len(source) > 0)
}
