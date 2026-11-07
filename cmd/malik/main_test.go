package main

import (
	"errors"
	"testing"
)

func TestParseSetArgs(t *testing.T) {
	prompted := []string{}
	prompt := func(p string) string {
		prompted = append(prompted, p)
		return "S3cret-typed"
	}
	files := map[string]string{`C:\keys\sa.json`: "{\"type\":\"service_account\"}\r\n"}
	readFile := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("not found")
	}

	data, value, err := parseSetArgs([]string{
		"host=100.64.0.10",
		"password=?",
		`key=@C:\keys\sa.json`,
		"handle=@@malik",
	}, "", prompt, readFile)
	if err != nil {
		t.Fatal(err)
	}
	if value != "" {
		t.Fatalf("unexpected plain value %q", value)
	}
	want := map[string]string{
		"host":     "100.64.0.10",
		"password": "S3cret-typed",
		"key":      `{"type":"service_account"}`,
		"handle":   "@malik",
	}
	for k, v := range want {
		if data[k] != v {
			t.Fatalf("%s: want %q, got %q", k, v, data[k])
		}
	}
	if len(prompted) != 1 {
		t.Fatalf("expected exactly one prompt, got %d", len(prompted))
	}

	if _, value, err = parseSetArgs([]string{"?"}, "", prompt, readFile); err != nil || value != "S3cret-typed" {
		t.Fatalf("plain '?' value should be prompted, got %q err=%v", value, err)
	}
	if _, _, err = parseSetArgs([]string{"key=@missing.json"}, "", prompt, readFile); err == nil {
		t.Fatalf("expected an error for a missing @file")
	}
	empty := func(string) string { return "" }
	if _, _, err = parseSetArgs([]string{"password=?"}, "", empty, readFile); err == nil {
		t.Fatalf("expected an error for an empty prompted value")
	}
}

func TestReorderFlagsKeepsBoolFlagsFromEatingPositionals(t *testing.T) {
	got := reorderFlagsFirst([]string{"servidores/web01/ssh", "--merge", "password=?", "--tags", "ssh,web01"})
	want := []string{"--merge", "--tags", "ssh,web01", "servidores/web01/ssh", "password=?"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}
