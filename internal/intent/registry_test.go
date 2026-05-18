package intent

import (
	"errors"
	"testing"
)

func TestResolve_ExactMatch(t *testing.T) {
	cases := []string{"ANALYZE", "EXECUTE", "ESCALATE"}
	for _, c := range cases {
		schema, err := Resolve(c)
		if err != nil {
			t.Errorf("Resolve(%q) unexpected error: %v", c, err)
		}
		if schema.ID != c {
			t.Errorf("Resolve(%q) got ID %q, want %q", c, schema.ID, c)
		}
	}
}

func TestResolve_PrefixMatch(t *testing.T) {
	cases := map[string]string{
		"ANALYZE_v1":  "ANALYZE",
		"EXECUTE_v2":  "EXECUTE",
		"ESCALATE_v1": "ESCALATE",
	}
	for declared, wantID := range cases {
		schema, err := Resolve(declared)
		if err != nil {
			t.Errorf("Resolve(%q) unexpected error: %v", declared, err)
		}
		if schema.ID != wantID {
			t.Errorf("Resolve(%q) got ID %q, want %q", declared, schema.ID, wantID)
		}
	}
}

func TestResolve_CaseInsensitive(t *testing.T) {
	schema, err := Resolve("analyze")
	if err != nil {
		t.Errorf("Resolve(\"analyze\") unexpected error: %v", err)
	}
	if schema.ID != "ANALYZE" {
		t.Errorf("expected ANALYZE, got %q", schema.ID)
	}
}

func TestResolve_MissingIntent(t *testing.T) {
	_, err := Resolve("")
	if !errors.Is(err, ErrIntentMissing) {
		t.Errorf("expected ErrIntentMissing, got %v", err)
	}

	_, err = Resolve("   ")
	if !errors.Is(err, ErrIntentMissing) {
		t.Errorf("expected ErrIntentMissing for whitespace, got %v", err)
	}
}

func TestResolve_UnknownIntent(t *testing.T) {
	cases := []string{"READ", "WRITE", "DELETE", "UNKNOWN", "DATA_READ_v1"}
	for _, c := range cases {
		_, err := Resolve(c)
		if !errors.Is(err, ErrIntentUnknown) {
			t.Errorf("Resolve(%q): expected ErrIntentUnknown, got %v", c, err)
		}
	}
}

func TestList(t *testing.T) {
	list := List()
	if len(list) != 3 {
		t.Errorf("List() returned %d schemas, expected 3", len(list))
	}
}

func TestIsRegistered(t *testing.T) {
	if !IsRegistered("ANALYZE") {
		t.Error("ANALYZE should be registered")
	}
	if IsRegistered("UNKNOWN") {
		t.Error("UNKNOWN should not be registered")
	}
}
