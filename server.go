package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	maxBodyBytes    = 256 * 1024
	maxPollWaitSecs = 60
	pollInterval    = 400 * time.Millisecond
)

type server struct {
	store *Store
	mux   *http.ServeMux
}

func newServer(store *Store) *server {
	s := &server{store: store, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("POST /api/requests", s.handleCreate)
	s.mux.HandleFunc("GET /r/{id}", s.handleForm)
	s.mux.HandleFunc("POST /r/{id}/submit", s.handleSubmit)
	s.mux.HandleFunc("POST /r/{id}/decline", s.handleDecline)
	s.mux.HandleFunc("GET /api/requests/{id}/result", s.handleResult)
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// serve runs the HTTP server and a periodic expiry sweep until ctx is done.
func serve(ctx context.Context, addr string, store *Store) error {
	s := newServer(store)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Writes may block for up to maxPollWaitSecs on long-poll results.
		WriteTimeout: maxPollWaitSecs*time.Second + 10*time.Second,
		IdleTimeout:  120 * time.Second,
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				store.Sweep()
			}
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	log.Printf("secure-input server listening on http://%s", listener.Addr())
	err = httpServer.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writePage(w http.ResponseWriter, status int, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pageTemplate.Execute(w, data); err != nil {
		log.Printf("render page: %v", err)
	}
}

// requestOrigin reconstructs the public origin from the incoming request so
// the fill URL works behind proxies too.
func requestOrigin(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	writePage(w, http.StatusOK, renderMessagePage(
		"secure-input",
		"secure-input is running.",
		"Environment value requests arrive here as single-use links.",
	))
}

func (s *server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var spec Spec
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(body).Decode(&spec); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}
	if err := validateSpec(&spec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req := s.store.Create(spec)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        req.ID,
		"url":       fmt.Sprintf("%s/r/%s", requestOrigin(r), req.ID),
		"expiresAt": req.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (s *server) handleForm(w http.ResponseWriter, r *http.Request) {
	req := s.store.Get(r.PathValue("id"))
	if req == nil {
		writePage(w, http.StatusGone, renderMessagePage(
			"Request expired",
			"This link has expired or was already used.",
			"Ask the agent to run the request command again.",
		))
		return
	}
	if req.Status != StatusPending {
		writePage(w, http.StatusGone, renderMessagePage(
			"Request completed",
			"This request was already answered.",
			"You can close this tab.",
		))
		return
	}
	writePage(w, http.StatusOK, renderFormPage(req))
}

func (s *server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	req := s.store.Get(r.PathValue("id"))
	if req == nil {
		writeError(w, http.StatusGone, "Request expired or was already answered.")
		return
	}
	var body struct {
		Entries []submittedEntry `json:"entries"`
	}
	limited := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(limited).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}
	entries, err := validateEntries(req.Variables, body.Entries)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.store.Submit(req.ID, entries) == nil {
		writeError(w, http.StatusGone, "Request expired or was already answered.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleDecline(w http.ResponseWriter, r *http.Request) {
	req := s.store.Get(r.PathValue("id"))
	if req == nil {
		writeError(w, http.StatusGone, "Request expired or was already answered.")
		return
	}
	if s.store.Decline(req.ID) == nil {
		writeError(w, http.StatusGone, "Request expired or was already answered.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	waitSecs := 0
	if raw := r.URL.Query().Get("wait"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid wait parameter.")
			return
		}
		waitSecs = n
	}
	if waitSecs < 0 {
		waitSecs = 0
	}
	if waitSecs > maxPollWaitSecs {
		waitSecs = maxPollWaitSecs
	}
	deadline := time.Now().Add(time.Duration(waitSecs) * time.Second)
	for {
		req := s.store.Consume(id)
		switch {
		case req == nil:
			writeError(w, http.StatusGone, "Request expired or unknown.")
			return
		case req.Status == StatusSubmitted:
			writeJSON(w, http.StatusOK, map[string]any{
				"status":  req.Status,
				"entries": req.Entries,
			})
			return
		case req.Status == StatusDeclined:
			writeJSON(w, http.StatusOK, map[string]any{"status": req.Status})
			return
		case !time.Now().Before(deadline):
			writeJSON(w, http.StatusOK, map[string]any{"status": StatusPending})
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(pollInterval):
		}
	}
}
