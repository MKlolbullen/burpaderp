package recon

import "fmt"

// RunPolicy is the process-start gate for external tools. Scope validation still
// happens per record; this answers the separate question "may this class of tool
// run at all in the current scan mode?".
type RunPolicy struct {
	AllowPassiveOSINT   bool `json:"allow_passive_osint"`
	AllowLocalTransform bool `json:"allow_local_transform"`
	AllowDNSProbe       bool `json:"allow_dns_probe"`
	AllowHTTPProbe      bool `json:"allow_http_probe"`
	AllowNetworkProbe   bool `json:"allow_network_probe"`
	AllowActiveFuzz     bool `json:"allow_active_fuzz"`
}

// DefaultRunPolicy enables discovery/probing needed for ordinary recon but keeps
// raw network scans and vulnerability/fuzzing stages behind explicit opt-in.
func DefaultRunPolicy() RunPolicy {
	return RunPolicy{
		AllowPassiveOSINT: true,
		AllowLocalTransform: true,
		AllowDNSProbe: true,
		AllowHTTPProbe: true,
		AllowNetworkProbe: false,
		AllowActiveFuzz: false,
	}
}

func (p RunPolicy) Check(spec ToolSpec) error {
	allowed := true
	switch spec.Risk {
	case RiskPassiveOSINT:
		allowed = p.AllowPassiveOSINT
	case RiskLocalTransform:
		allowed = p.AllowLocalTransform
	case RiskDNSProbe:
		allowed = p.AllowDNSProbe
	case RiskHTTPProbe:
		allowed = p.AllowHTTPProbe
	case RiskNetworkProbe:
		allowed = p.AllowNetworkProbe
	case RiskActiveFuzz:
		allowed = p.AllowActiveFuzz
	}
	if !allowed {
		return fmt.Errorf("tool %s risk=%s is disabled by run policy", spec.Name, spec.Risk)
	}
	return nil
}
