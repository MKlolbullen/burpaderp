package recon

import (
	_ "embed"
	"encoding/json"
)

//go:embed chain_catalog.json
var chainCatalog []byte

// ReconChainPlan returns a planning manifest, not an executable command DAG.
// The same catalog is packaged in the Java UI; no process is needed to preview it.
func ReconChainPlan(rawDomain string) (map[string]any, error) {
	domain, err := EnumerationDomain(rawDomain)
	if err != nil {
		return nil, err
	}
	var plan map[string]any
	if err := json.Unmarshal(chainCatalog, &plan); err != nil {
		return nil, err
	}
	plan["domain"] = domain
	return plan, nil
}
