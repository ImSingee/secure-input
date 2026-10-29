package main

import (
	"encoding/json"
	"testing"
	"time"
)

func specForTest() Spec {
	return Spec{
		Reason: "Need test access.",
		Variables: []VariableSpec{
			{Key: "TOKEN", Description: "API token.", Private: true},
			{Key: "REGION", Description: "Region name.", Private: false},
		},
	}
}

func TestSpecValidation(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		ok   bool
	}{
		{"valid", specForTest(), true},
		{"empty reason", Spec{Reason: "", Variables: specForTest().Variables}, false},
		{"no variables", Spec{Reason: "x"}, false},
		{"duplicate key", Spec{Reason: "x", Variables: []VariableSpec{
			{Key: "TOKEN"}, {Key: "TOKEN"},
		}}, false},
		{"bad key", Spec{Reason: "x", Variables: []VariableSpec{{Key: "1BAD"}}}, false},
		{"reserved key", Spec{Reason: "x", Variables: []VariableSpec{{Key: "PATH"}}}, false},
		{"reserved prefix", Spec{Reason: "x", Variables: []VariableSpec{{Key: "LD_PRELOAD"}}}, false},
	}
	for _, tc := range cases {
		if err := validateSpec(&tc.spec); (err == nil) != tc.ok {
			t.Errorf("%s: validateSpec() err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestVariableSpecDefaultsPrivate(t *testing.T) {
	var v VariableSpec
	if err := json.Unmarshal([]byte(`{"key":"TOKEN"}`), &v); err != nil {
		t.Fatal(err)
	}
	if !v.Private {
		t.Error("absent private field should default to true")
	}
	if err := json.Unmarshal([]byte(`{"key":"REGION","private":false}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.Private {
		t.Error("explicit private:false should be honored")
	}
}

func TestStoreLifecycle(t *testing.T) {
	store := NewStore(RequestTTL)
	r := store.Create(specForTest())
	if got := store.Get(r.ID); got == nil || got.Status != StatusPending {
		t.Fatal("request should be pending after create")
	}

	priv := false
	entries, err := validateEntries(r.Variables, []submittedEntry{
		{Key: "TOKEN", Value: "s3cret"},
		{Key: "REGION", Value: "us-west", Private: &priv},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Omitted private field falls back to the requested default.
	if !entries[0].Private {
		t.Error("omitted private should fall back to spec default true")
	}
	if entries[1].Private {
		t.Error("explicit private:false should be honored")
	}

	if store.Submit(r.ID, entries) == nil {
		t.Fatal("submit should succeed on a pending request")
	}
	if store.Submit(r.ID, entries) != nil {
		t.Error("second submit should fail")
	}

	got := store.Consume(r.ID)
	if got == nil || got.Status != StatusSubmitted || len(got.Entries) != 2 {
		t.Fatal("consume should return submitted entries")
	}
	if store.Consume(r.ID) != nil {
		t.Error("consume should delete the result (pull-once)")
	}
}

func TestStoreDecline(t *testing.T) {
	store := NewStore(RequestTTL)
	r := store.Create(specForTest())
	if store.Decline(r.ID) == nil {
		t.Fatal("decline should succeed")
	}
	got := store.Consume(r.ID)
	if got == nil || got.Status != StatusDeclined {
		t.Fatal("consume should report declined")
	}
}

func TestStoreExpiry(t *testing.T) {
	store := NewStore(10 * time.Millisecond)
	r := store.Create(specForTest())
	time.Sleep(20 * time.Millisecond)
	if store.Get(r.ID) != nil {
		t.Error("expired request should be gone")
	}
}

func TestSubmittedRefreshTTL(t *testing.T) {
	store := NewStore(40 * time.Millisecond)
	r := store.Create(specForTest())
	time.Sleep(25 * time.Millisecond)
	if store.Submit(r.ID, nil) == nil {
		t.Fatal("submit should succeed")
	}
	time.Sleep(25 * time.Millisecond)
	if got := store.Consume(r.ID); got == nil {
		t.Error("submission should refresh the TTL")
	}
}

func TestValidateEntriesRejectsUnknownAndDuplicates(t *testing.T) {
	vars := specForTest().Variables
	if _, err := validateEntries(vars, []submittedEntry{{Key: "OTHER", Value: "x"}}); err == nil {
		t.Error("unknown key should be rejected")
	}
	if _, err := validateEntries(vars, []submittedEntry{
		{Key: "TOKEN", Value: "a"},
		{Key: "TOKEN", Value: "b"},
	}); err == nil {
		t.Error("duplicate key should be rejected")
	}
	// Missing variables are stored as empty values.
	entries, err := validateEntries(vars, []submittedEntry{{Key: "TOKEN", Value: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[1].Key != "REGION" || entries[1].Value != "" {
		t.Error("missing variables should default to empty values")
	}
}
