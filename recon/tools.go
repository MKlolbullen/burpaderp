package recon

import (
	"fmt"
	"sort"
	"strings"
)

// RiskClass describes the side-effect profile of a tool. It is metadata for
// planning/policy; it is not a substitute for the request and scope gates at the
// actual network-send boundary.
type RiskClass string

const (
	RiskPassiveOSINT   RiskClass = "passive_osint"
	RiskLocalTransform RiskClass = "local_transform"
	RiskDNSProbe       RiskClass = "dns_probe"
	RiskNetworkProbe   RiskClass = "network_probe"
	RiskHTTPProbe      RiskClass = "http_probe"
	RiskActiveFuzz     RiskClass = "active_fuzz"
)

// ToolSpec is the contract for one external consumer/producer. Anything not
// declared here is incompatible by default; the socket gate will quarantine it.
type ToolSpec struct {
	Name        string    `json:"name"`
	Binary      string    `json:"binary"`
	Consumes    []Kind    `json:"consumes"`
	Produces    []Kind    `json:"produces"`
	Risk        RiskClass `json:"risk"`
	Description string    `json:"description,omitempty"`
}

func (t ToolSpec) Accepts(kind Kind) bool { return containsKind(t.Consumes, kind) }
func (t ToolSpec) ProducesKind(kind Kind) bool { return containsKind(t.Produces, kind) }

// ToolRegistry is intentionally explicit instead of discovering binaries and
// guessing their semantics from PATH. Tool existence and tool compatibility are
// separate questions.
type ToolRegistry struct {
	tools map[string]ToolSpec
}

func DefaultToolRegistry() ToolRegistry {
	specs := []ToolSpec{
		{Name: "subfinder", Binary: "subfinder", Consumes: []Kind{KindDomain}, Produces: []Kind{KindHostname}, Risk: RiskPassiveOSINT, Description: "passive subdomain enumeration"},
		{Name: "amass", Binary: "amass", Consumes: []Kind{KindDomain}, Produces: []Kind{KindHostname}, Risk: RiskPassiveOSINT, Description: "passive/OSINT subdomain enumeration"},
		{Name: "assetfinder", Binary: "assetfinder", Consumes: []Kind{KindDomain}, Produces: []Kind{KindHostname}, Risk: RiskPassiveOSINT, Description: "related-domain and subdomain discovery"},
		{Name: "chaos", Binary: "chaos", Consumes: []Kind{KindDomain}, Produces: []Kind{KindHostname}, Risk: RiskPassiveOSINT, Description: "ProjectDiscovery Chaos subdomain source"},
		{Name: "findomain", Binary: "findomain", Consumes: []Kind{KindDomain}, Produces: []Kind{KindHostname}, Risk: RiskPassiveOSINT, Description: "passive subdomain enumeration"},

		// puredns is treated as a resolver/filter: its normal line output proves the
		// hostname resolved but does not carry the complete A/AAAA/CNAME tuple. dnsx
		// is therefore the record-enrichment boundary that produces resolved_host.
		{Name: "puredns", Binary: "puredns", Consumes: []Kind{KindHostname}, Produces: []Kind{KindHostname}, Risk: RiskDNSProbe, Description: "DNS resolution and wildcard filtering"},
		{Name: "dnsx", Binary: "dnsx", Consumes: []Kind{KindHostname}, Produces: []Kind{KindResolvedHost}, Risk: RiskDNSProbe, Description: "A/AAAA/CNAME resolution and DNS probing"},

		{Name: "alterx", Binary: "alterx", Consumes: []Kind{KindHostname}, Produces: []Kind{KindHostname}, Risk: RiskLocalTransform, Description: "subdomain permutation generation"},
		{Name: "dnsgen", Binary: "dnsgen", Consumes: []Kind{KindHostname}, Produces: []Kind{KindHostname}, Risk: RiskLocalTransform, Description: "subdomain permutation generation"},
		{Name: "mksub", Binary: "mksub", Consumes: []Kind{KindHostname}, Produces: []Kind{KindHostname}, Risk: RiskLocalTransform, Description: "subdomain permutation generation"},

		{Name: "naabu", Binary: "naabu", Consumes: []Kind{KindIP, KindCIDR}, Produces: []Kind{KindService}, Risk: RiskNetworkProbe, Description: "TCP port discovery"},
		{Name: "masscan", Binary: "masscan", Consumes: []Kind{KindIP, KindCIDR}, Produces: []Kind{KindService}, Risk: RiskNetworkProbe, Description: "high-rate network port discovery"},

		{Name: "httpx", Binary: "httpx", Consumes: []Kind{KindHostname, KindService, KindURL}, Produces: []Kind{KindHTTPTarget}, Risk: RiskHTTPProbe, Description: "HTTP service probing and normalization"},

		{Name: "katana", Binary: "katana", Consumes: []Kind{KindHTTPTarget, KindURL}, Produces: []Kind{KindURL}, Risk: RiskHTTPProbe, Description: "active web crawler"},
		{Name: "gau", Binary: "gau", Consumes: []Kind{KindHTTPTarget, KindURL}, Produces: []Kind{KindURL}, Risk: RiskPassiveOSINT, Description: "known/historical URL collection"},
		{Name: "cariddi", Binary: "cariddi", Consumes: []Kind{KindHTTPTarget, KindURL}, Produces: []Kind{KindURL}, Risk: RiskHTTPProbe, Description: "crawler and endpoint/secret discovery"},

		{Name: "arjun", Binary: "arjun", Consumes: []Kind{KindURL}, Produces: []Kind{KindParameterizedURL}, Risk: RiskActiveFuzz, Description: "hidden HTTP parameter discovery"},
		{Name: "gf", Binary: "gf", Consumes: []Kind{KindURL}, Produces: []Kind{KindParameterizedURL}, Risk: RiskLocalTransform, Description: "pattern-based URL/parameter classification"},

		{Name: "dalfox", Binary: "dalfox", Consumes: []Kind{KindParameterizedURL}, Produces: []Kind{KindFinding}, Risk: RiskActiveFuzz, Description: "XSS parameter analysis and verification"},
		{Name: "nuclei", Binary: "nuclei", Consumes: []Kind{KindHTTPTarget, KindURL}, Produces: []Kind{KindFinding}, Risk: RiskActiveFuzz, Description: "template-driven vulnerability scanning"},
		{Name: "corsy", Binary: "corsy", Consumes: []Kind{KindHTTPTarget, KindURL}, Produces: []Kind{KindFinding}, Risk: RiskHTTPProbe, Description: "CORS checks"},
		{Name: "crlfuzz", Binary: "crlfuzz", Consumes: []Kind{KindHTTPTarget, KindURL}, Produces: []Kind{KindFinding}, Risk: RiskActiveFuzz, Description: "CRLF/header injection checks"},
	}

	m := make(map[string]ToolSpec, len(specs))
	for _, spec := range specs {
		m[spec.Name] = spec
	}
	return ToolRegistry{tools: m}
}

func (r ToolRegistry) Get(name string) (ToolSpec, bool) {
	spec, ok := r.tools[strings.ToLower(strings.TrimSpace(name))]
	return spec, ok
}

func (r ToolRegistry) MustGet(name string) (ToolSpec, error) {
	spec, ok := r.Get(name)
	if !ok {
		return ToolSpec{}, fmt.Errorf("unknown tool %q", name)
	}
	return spec, nil
}

func (r ToolRegistry) List() []ToolSpec {
	out := make([]ToolSpec, 0, len(r.tools))
	for _, spec := range r.tools {
		out = append(out, spec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ValidateGraphEdge verifies a direct typed edge between two stages. It is
// useful for plan validation before any process is started.
func ValidateGraphEdge(producer ToolSpec, consumer ToolSpec) error {
	for _, out := range producer.Produces {
		if consumer.Accepts(out) {
			return nil
		}
	}
	return fmt.Errorf("incompatible edge %s -> %s: produces %v, consumer accepts %v",
		producer.Name, consumer.Name, producer.Produces, consumer.Consumes)
}

func containsKind(kinds []Kind, want Kind) bool {
	for _, kind := range kinds {
		if kind == want {
			return true
		}
	}
	return false
}
