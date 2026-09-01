package recon

import "testing"

// The contract vocabulary is intentionally small and stable. New kinds need a
// matching Record shape, Scope.Validate branch, adapter, and tests; otherwise
// they become unvalidated strings masquerading as typed pipeline data.
func TestCanonicalKindsAreUniqueAndStable(t *testing.T) {
	kinds := []Kind{
		KindDomain,
		KindHostname,
		KindResolvedHost,
		KindIP,
		KindCIDR,
		KindService,
		KindHTTPTarget,
		KindURL,
		KindParameterizedURL,
		KindPayload,
		KindFinding,
	}
	seen := make(map[Kind]struct{}, len(kinds))
	for _, kind := range kinds {
		if kind == "" {
			t.Fatal("canonical kind must not be empty")
		}
		if _, exists := seen[kind]; exists {
			t.Fatalf("duplicate canonical kind %q", kind)
		}
		seen[kind] = struct{}{}
	}
	if got, want := len(seen), 11; got != want {
		t.Fatalf("got %d kinds, want %d", got, want)
	}
}
