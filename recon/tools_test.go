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
