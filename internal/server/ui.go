package server

import (
	_ "embed"
	"net/http"
)

//go:embed ui/index.html
var embeddedUI []byte

func (s *Server) handleRootOrUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/ui" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(embeddedUI)
}
