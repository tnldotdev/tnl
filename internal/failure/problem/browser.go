package problem

import (
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/browserpage"
)

type browserResponse struct {
	http.ResponseWriter
	head bool
}

func (w *browserResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// BrowserResponse opts a browser endpoint into html problems without changing
// api responses. the existing problem writer still owns codes and correlation.
func BrowserResponse(w http.ResponseWriter, r *http.Request) http.ResponseWriter {
	w.Header().Add("Vary", "Accept")
	if !browserpage.AcceptsHTML(r.Header.Get("Accept")) {
		return w
	}
	return &browserResponse{ResponseWriter: w, head: r.Method == http.MethodHead}
}

func (w *browserResponse) write(value Problem, help string) {
	browserpage.Headers(w)
	w.WriteHeader(value.Status)
	if !w.head {
		title := value.Title
		if title == value.Detail {
			title = strings.ToLower(http.StatusText(value.Status))
		}
		_, _ = w.Write([]byte(browserpage.MessageHTML(browserpage.Message{
			Title: title, Summary: value.Detail, Code: value.Code,
			RequestID: value.RequestID, HelpURL: help,
		})))
	}
}
