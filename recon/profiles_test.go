package recon

import "testing"

func TestDefaultCommandProfilesValidate(t *testing.T) {
	registry := DefaultToolRegistry()
	profiles := ListCommandProfiles()
	if len(profiles) == 0 {
		t.Fatal("expected command profiles")
	}
	for _, profile := range profiles {
		if err := ValidateCommandProfile(profile, registry); err != nil {
			t.Fatalf("profile %s invalid: %v", profile.Tool, err)
		}
	}
}

func TestDefaultPolicyRequiresOptInForNetworkAndVulnerabilityScanning(t *testing.T) {
	registry := DefaultToolRegistry()
	policy := DefaultRunPolicy()
	for _, name := range []string{"subfinder", "puredns", "dnsx", "httpx", "katana", "gau"} {
		spec, _ := registry.MustGet(name)
		if err := policy.Check(spec); err != nil {
			t.Fatalf("default recon policy unexpectedly blocked %s: %v", name, err)
		}
	}
	for _, name := range []string{"naabu", "masscan", "nuclei", "dalfox", "arjun", "crlfuzz"} {
		spec, _ := registry.MustGet(name)
		if err := policy.Check(spec); err == nil {
			t.Fatalf("default policy should require explicit opt-in for %s", name)
		}
	}
}

func TestExplicitPolicyEnablesNetworkAndActiveStages(t *testing.T) {
	registry := DefaultToolRegistry()
	policy := DefaultRunPolicy()
	policy.AllowNetworkProbe = true
	policy.AllowActiveFuzz = true
	for _, name := range []string{"naabu", "nuclei"} {
		spec, _ := registry.MustGet(name)
		if err := policy.Check(spec); err != nil {
			t.Fatalf("explicit policy should allow %s: %v", name, err)
		}
	}
}
