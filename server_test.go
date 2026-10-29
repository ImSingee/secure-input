package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	store := NewStore(RequestTTL)
	srv := httptest.NewServer(newServer(store))
	t.Cleanup(srv.Close)
	return srv, store
}

func postJSON(t *testing.T, url string, body string) *http.Response {
	t.Helper()
	res, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestEndToEnd(t *testing.T) {
	srv, _ := newTestServer(t)

	res := postJSON(t, srv.URL+"/api/requests", `{
		"reason": "Need GitHub access.",
		"variables": [
			{"key": "GITHUB_TOKEN", "description": "From github.com/settings/tokens"},
			{"key": "GH_OWNER", "description": "Your username", "private": false}
		]
	}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %s", res.Status)
	}
	var created createResponse
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !strings.HasPrefix(created.URL, srv.URL+"/r/"+created.ID) {
		t.Fatalf("unexpected fill url %q", created.URL)
	}

	// The form page renders the spec.
	form, err := http.Get(created.URL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(form.Body)
	form.Body.Close()
	if !strings.Contains(string(page), "GITHUB_TOKEN") ||
		!strings.Contains(string(page), "Need GitHub access.") {
		t.Error("form page should contain the reason and variable keys")
	}

	// Submit values; TOKEN omits "private" and keeps the requested default.
	submit := postJSON(t, srv.URL+"/r/"+created.ID+"/submit",
		`{"entries": [{"key":"GITHUB_TOKEN","value":"ghp_secret"},{"key":"GH_OWNER","value":"octocat","private":false}]}`)
	if submit.StatusCode != http.StatusOK {
		t.Fatalf("submit: got %s", submit.Status)
	}
	submit.Body.Close()

	// Result is served exactly once.
	result, err := http.Get(srv.URL + "/api/requests/" + created.ID + "/result")
	if err != nil {
		t.Fatal(err)
	}
	var out resultResponse
	if err := json.NewDecoder(result.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	result.Body.Close()
	if out.Status != StatusSubmitted || len(out.Entries) != 2 {
		t.Fatalf("unexpected result %+v", out)
	}
	if out.Entries[0].Key != "GITHUB_TOKEN" || out.Entries[0].Value != "ghp_secret" || !out.Entries[0].Private {
		t.Errorf("unexpected first entry %+v", out.Entries[0])
	}
	if out.Entries[1].Private {
		t.Error("GH_OWNER should be public")
	}

	again, err := http.Get(srv.URL + "/api/requests/" + created.ID + "/result")
	if err != nil {
		t.Fatal(err)
	}
	again.Body.Close()
	if again.StatusCode != http.StatusGone {
		t.Errorf("second pull should be 410, got %s", again.Status)
	}

	// The form is gone too.
	form2, err := http.Get(created.URL)
	if err != nil {
		t.Fatal(err)
	}
	form2.Body.Close()
	if form2.StatusCode != http.StatusGone {
		t.Errorf("form after completion should be 410, got %s", form2.Status)
	}
}

func TestDeclineFlow(t *testing.T) {
	srv, _ := newTestServer(t)
	res := postJSON(t, srv.URL+"/api/requests",
		`{"reason":"x","variables":[{"key":"TOKEN"}]}`)
	var created createResponse
	json.NewDecoder(res.Body).Decode(&created)
	res.Body.Close()

	dec, err := http.Post(srv.URL+"/r/"+created.ID+"/decline", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	dec.Body.Close()

	result, _ := http.Get(srv.URL + "/api/requests/" + created.ID + "/result")
	var out resultResponse
	json.NewDecoder(result.Body).Decode(&out)
	result.Body.Close()
	if out.Status != StatusDeclined {
		t.Errorf("expected declined, got %q", out.Status)
	}
}

func TestInvalidRequests(t *testing.T) {
	srv, _ := newTestServer(t)
	res := postJSON(t, srv.URL+"/api/requests",
		`{"reason":"x","variables":[{"key":"PATH"}]}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("reserved key should be rejected, got %s", res.Status)
	}
	res.Body.Close()

	res = postJSON(t, srv.URL+"/api/requests", `{"reason":"x","variables":[]}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("empty variables should be rejected, got %s", res.Status)
	}
	res.Body.Close()
}
