package main

import "testing"

func TestSerializeDotenv(t *testing.T) {
	got := SerializeDotenv([]Entry{
		{Key: "TOKEN", Value: "abc123"},
		{Key: "EMPTY", Value: ""},
		{Key: "GREETING", Value: "hello world"},
		{Key: "MULTI", Value: "line1\nline2"},
		{Key: "QUOTED", Value: `say "hi"`},
		{Key: "URL", Value: "https://example.com/path?a=1&b=2"},
	})
	want := `TOKEN=abc123
EMPTY=
GREETING="hello world"
MULTI="line1\nline2"
QUOTED="say \"hi\""
URL="https://example.com/path?a=1&b=2"
`
	if got != want {
		t.Errorf("SerializeDotenv() =\n%q\nwant\n%q", got, want)
	}
}
