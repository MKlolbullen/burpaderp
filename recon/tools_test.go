package recon

import "testing"

func TestRegistryModelsTypedPipelineEdges(t *testing.T) {
	r := DefaultToolRegistry()
	mustEdge := func(from, to string) {
		t.Helper()
		producer, err := r.MustGet(from)
		if err != nil {
			t.Fatal(err)
		}
		consumer, err := r.MustGet(to)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateGraphEdge(producer, consumer); err != nil {
			t.Fatalf("expected %s -> %s compatible: %v", from, to, err)
		}
	}
	mustEdge("subfinder", "puredns")
	mustEdge("puredns", "dnsx")
	mustEdge("naabu", "httpx")
	mustEdge("httpx", "katana")
	mustEdge("katana", "gf")
	mustEdge("gf", "dalfox")
}

func TestResolvedHostCannotFallStraightIntoNetworkScanner(t *testing.T) {
	r := DefaultToolRegistry()
	dnsx, _ := r.MustGet("dnsx")
	naabu, _ := r.MustGet("naabu")
	if err := ValidateGraphEdge(dnsx, naabu); err == nil {
		t.Fatal("dnsx -> naabu should require the explicit resolved_host -> ip contract transform")
	}
}

func TestNetworkScannersDoNotAcceptHostnames(t *testing.T) {
	r := DefaultToolRegistry()
	for _, name := range []string{"naabu", "masscan"} {
		spec, _ := r.MustGet(name)
		if spec.Accepts(KindHostname) {
			t.Fatalf("%s must not accept hostname scope implicitly", name)
		}
		if !spec.Accepts(KindIP) || !spec.Accepts(KindCIDR) {
			t.Fatalf("%s should accept explicit IP/CIDR contracts", name)
		}
	}
}

func TestExtendedCatalogKeepsInjectionToolsBehindParameterizedURL(t *testing.T) {
	r := DefaultToolRegistry()
	for _, name := range []string{"dalfox", "sqlmap"} {
		spec, err := r.MustGet(name)
		if err != nil {
			t.Fatal(err)
		}
		if !spec.Accepts(KindParameterizedURL) || spec.Accepts(KindURL) {
			t.Fatalf("%s must require an explicit parameterized_url injection point", name)
		}
		if spec.Risk != RiskActiveFuzz {
			t.Fatalf("%s must remain behind the active-fuzz policy gate", name)
		}
	}
}

func TestExtendedCatalogDoesNotTreatWorkflowUtilitiesAsTools(t *testing.T) {
	r := DefaultToolRegistry()
	for _, name := range []string{"jq", "anew", "notify"} {
		if _, ok := r.Get(name); ok {
			t.Fatalf("workflow utility %s must not masquerade as a typed scanner", name)
		}
	}
}

func TestXSStrikeStaysBehindParameterizedURL(t *testing.T) {
	spec, err := DefaultToolRegistry().MustGet("xsstrike")
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Accepts(KindParameterizedURL) || spec.Accepts(KindURL) {
		t.Fatal("xsstrike must require an explicit parameterized_url injection point like dalfox")
	}
	if spec.Risk != RiskActiveFuzz {
		t.Fatal("xsstrike must remain behind the active-fuzz policy gate")
	}
}

func TestSecretScannersProduceFindings(t *testing.T) {
	r := DefaultToolRegistry()
	for _, name := range []string{"gitleaks", "trufflehog", "postleaks", "scan4secrets"} {
		spec, err := r.MustGet(name)
		if err != nil {
			t.Fatal(err)
		}
		if !spec.ProducesKind(KindFinding) {
			t.Fatalf("%s must produce findings", name)
		}
	}
}

func TestActiveWebAndSecretToolsRequireOptIn(t *testing.T) {
	registry := DefaultToolRegistry()
	policy := DefaultRunPolicy()
	for _, name := range []string{"xsstrike", "xsrfprobe", "ssrfire", "scan4secrets"} {
		spec, err := registry.MustGet(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.Check(spec); err == nil {
			t.Fatalf("default policy should require explicit opt-in for %s", name)
		}
	}
	// Passive secret discovery (postleaks keyword search, gitleaks/trufflehog
	// source scans) is not gated behind the active-fuzz switch.
	for _, name := range []string{"postleaks", "gitleaks", "trufflehog"} {
		spec, _ := registry.MustGet(name)
		if err := policy.Check(spec); err != nil {
			t.Fatalf("passive secret scanner %s should run under the default policy: %v", name, err)
		}
	}
}

func TestUnpinnedWebToolOutputFailsClosed(t *testing.T) {
	for _, name := range []string{"xsstrike", "xsrfprobe", "ssrfire", "scan4secrets", "postleaks"} {
		if _, err := ParseToolOutputLine(name, `{"anything":"value"}`); err == nil {
			t.Fatalf("%s output must fail closed until a machine-stable adapter is pinned", name)
		}
	}
}
