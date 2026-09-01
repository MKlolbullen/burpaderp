package recon

import "testing"

func TestResolveRunIDValidatesOrGeneratesUUID(t *testing.T) {
	provided, err := ResolveRunID("A12B3C4D-1111-4222-8333-1234567890AB")
	if err != nil {
		t.Fatalf("resolve provided UUID: %v", err)
	}
	if got, want := provided, "a12b3c4d-1111-4222-8333-1234567890ab"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	generated, err := ResolveRunID("")
	if err != nil {
		t.Fatalf("generate UUID: %v", err)
	}
	if !runIDPattern.MatchString(generated) {
		t.Fatalf("generated invalid UUID %q", generated)
	}
	if _, err := ResolveRunID("not-a-run-id"); err == nil {
		t.Fatal("expected invalid run ID to be rejected")
	}
}

func TestStampRunIDOverwritesUpstreamRecordID(t *testing.T) {
	input := []Record{{Kind: KindURL, URL: "https://example.com/", RunID: "old"}}
	stamped := StampRunID(input, "a12b3c4d-1111-4222-8333-1234567890ab")
	if got := stamped[0].RunID; got != "a12b3c4d-1111-4222-8333-1234567890ab" {
		t.Fatalf("got run ID %q", got)
	}
	if got := input[0].RunID; got != "old" {
		t.Fatalf("input was mutated: %q", got)
	}
}
