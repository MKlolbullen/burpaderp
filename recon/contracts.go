package recon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Kind is the schema carried between pipeline stages. A tool may only receive
// kinds listed in its contract and may only emit kinds declared by that same
// contract.
type Kind string

const (
	KindDomain           Kind = "domain"
	KindHostname         Kind = "hostname"
	KindResolvedHost     Kind = "resolved_host"
	KindIP               Kind = "ip"
	KindCIDR             Kind = "cidr"
	KindService          Kind = "service"
	KindHTTPTarget       Kind = "http_target"
	KindURL              Kind = "url"
	KindParameterizedURL Kind = "parameterized_url"
	KindPayload          Kind = "payload"
	KindFinding          Kind = "finding"
)

// Record is the JSONL wire type used by the Go recon sidecar. It is deliberately
// a tagged union rather than a map[string]any: every boundary can validate the
// fields required by record.Kind before a value reaches another tool.
type Record struct {
	Kind          Kind      `json:"kind"`
	Value         string    `json:"value,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	Addresses     []string  `json:"addresses,omitempty"`
	CNAMEs        []string  `json:"cnames,omitempty"`
	IP            string    `json:"ip,omitempty"`
	CIDR          string    `json:"cidr,omitempty"`
	Port          int       `json:"port,omitempty"`
	Protocol      string    `json:"protocol,omitempty"`
	URL           string    `json:"url,omitempty"`
	Status        int       `json:"status,omitempty"`
	Parameter     string    `json:"parameter,omitempty"`
	PayloadFamily string    `json:"payload_family,omitempty"`
	Tool          string    `json:"tool,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	Evidence      string    `json:"evidence,omitempty"`
	Source        string    `json:"source,omitempty"`
	RunID         string    `json:"run_id,omitempty"`
	CreatedAt     time.Time `json:"created_at,omitempty"`

	// Derived marks an IP/service that came from resolving an in-scope hostname
	// rather than from an explicitly authorised IP/CIDR. Network-probe stages do
	// not accept such records unless AllowDerivedIPs is explicitly enabled.
	Derived bool `json:"derived,omitempty"`
}

// RejectedRecord is the quarantine format. Bad tool output is data, not a log
// line: preserve it with the exact boundary, source and reason so the run can be
// audited and adapters can be fixed without silently losing evidence.
type RejectedRecord struct {
	Tool      string    `json:"tool,omitempty"`
	Direction string    `json:"direction"`
	Reason    string    `json:"reason"`
	Raw       string    `json:"raw,omitempty"`
	Record    *Record   `json:"record,omitempty"`
	Source    string    `json:"source,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Scope is intentionally conservative for network probing. Domain scope allows
// DNS and HTTP work against the hostname, but does not automatically authorise
// port scanning every IP the hostname resolves to (CDNs/shared hosting make that
// assumption unsafe). Explicit CIDRs/IPs are accepted; derived IPs require the
// dedicated opt-in.
type Scope struct {
	domains         []string
	cidrs           []netip.Prefix
	allowDerivedIPs bool
}

func NewScope(domains, cidrs []string, allowDerivedIPs bool) (Scope, error) {
	s := Scope{allowDerivedIPs: allowDerivedIPs}
	seenDomains := map[string]struct{}{}
	for _, raw := range domains {
		d, err := NormalizeFQDN(raw)
		if err != nil {
			return Scope{}, fmt.Errorf("scope domain %q: %w", raw, err)
		}
		if _, ok := seenDomains[d]; !ok {
			seenDomains[d] = struct{}{}
			s.domains = append(s.domains, d)
		}
	}
	seenCIDRs := map[string]struct{}{}
	for _, raw := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return Scope{}, fmt.Errorf("scope CIDR %q: %w", raw, err)
		}
		p = p.Masked()
		key := p.String()
		if _, ok := seenCIDRs[key]; !ok {
			seenCIDRs[key] = struct{}{}
			s.cidrs = append(s.cidrs, p)
		}
	}
	if len(s.domains) == 0 && len(s.cidrs) == 0 {
		return Scope{}, errors.New("scope must contain at least one domain or CIDR")
	}
	return s, nil
}

func (s Scope) Domains() []string { return append([]string(nil), s.domains...) }