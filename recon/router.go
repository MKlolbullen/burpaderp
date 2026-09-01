package recon

import (
	"fmt"
	"sort"
	"strings"
)

type PayloadRole string

const (
	PayloadRolePayload       PayloadRole = "payload"
	PayloadRoleParameterHint PayloadRole = "parameter_hint"
)

type PayloadPolicy struct {
	Family                    string      `json:"family"`
	Role                      PayloadRole `json:"role"`
	Consumers                 []string    `json:"consumers"`
	RequiresDestructiveFilter bool        `json:"requires_destructive_filter,omitempty"`
	RequiresOASTRewrite       bool        `json:"requires_oast_rewrite,omitempty"`
	Notes                     string      `json:"notes,omitempty"`
}

// PayloadRouter turns the payload directory from an untyped bag of text files
// into explicit families. In particular, rce.txt is a parameter-hint corpus and
// must never be treated as an RCE payload list.
type PayloadRouter struct {
	policies map[string]PayloadPolicy
}

func DefaultPayloadRouter() PayloadRouter {
	policies := []PayloadPolicy{
		{Family: "xss", Role: PayloadRolePayload, Consumers: []string{"corpus-fuzz", "xss-specialist"}, Notes: "XSS payload corpus; specialist adapter may use Dalfox's own payload interface rather than passing lines verbatim"},
		{Family: "sqli", Role: PayloadRolePayload, Consumers: []string{"corpus-fuzz", "sqli-specialist"}},
		{Family: "sqli2", Role: PayloadRolePayload, Consumers: []string{"corpus-fuzz", "sqli-specialist"}},
		{Family: "ssti", Role: PayloadRolePayload, Consumers: []string{"corpus-fuzz", "ssti-specialist"}, RequiresOASTRewrite: true},
		{Family: "lfi", Role: PayloadRolePayload, Consumers: []string{"corpus-fuzz", "lfi-specialist"}},
		{Family: "rce_payloads", Role: PayloadRolePayload, Consumers: []string{"corpus-fuzz", "rce-specialist"}, RequiresDestructiveFilter: true, RequiresOASTRewrite: true},
		{Family: "rce", Role: PayloadRoleParameterHint, Consumers: []string{"parameter-profiler"}, Notes: "?name={payload}-shaped parameter hints, not payloads"},
	}
	m := make(map[string]PayloadPolicy, len(policies))
	for _, policy := range policies {
		m[policy.Family] = policy
	}
	return PayloadRouter{policies: m}
}

func (r PayloadRouter) Policy(family string) (PayloadPolicy, bool) {
	policy, ok := r.policies[strings.ToLower(strings.TrimSpace(family))]
	return policy, ok
}

func (r PayloadRouter) List() []PayloadPolicy {
	out := make([]PayloadPolicy, 0, len(r.policies))
	for _, policy := range r.policies {
		out = append(out, policy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

func (r PayloadRouter) Route(payload Record, target Record) (PayloadPolicy, error) {
	if payload.Kind != KindPayload {
		return PayloadPolicy{}, fmt.Errorf("payload router requires %s input, got %s", KindPayload, payload.Kind)
	}
	policy, ok := r.Policy(payload.PayloadFamily)
	if !ok {
		return PayloadPolicy{}, fmt.Errorf("unknown payload family %q", payload.PayloadFamily)
	}
	if policy.Role == PayloadRoleParameterHint {
		return PayloadPolicy{}, fmt.Errorf("payload family %q is role=%s and cannot be fired", policy.Family, policy.Role)
	}
	if target.Kind != KindParameterizedURL {
		return PayloadPolicy{}, fmt.Errorf("payload family %q requires %s target, got %s", policy.Family, KindParameterizedURL, target.Kind)
	}
	return policy, nil
}
