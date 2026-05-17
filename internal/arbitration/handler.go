// arbitration/handler.go — SAL Kernel evaluation engine
// Phase 1: ParameterBoundsSchema validation (SAL-4010)
// Phase 2: Inter-Agent Trust / Delegation Chain (SAL-4011, SAL-4012)
package arbitration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ── Payload types ──────────────────────────────────────────────

type ArbitrateRequest struct {
	RequestID   string        `json:"request_id"`
	ProxyID     string        `json:"proxy_id"`
	IIAACPayload *IIAACPayload `json:"iiaac_payload"`
}

// IIAACPayload — Intent · Identity · Asset · Action · Context
type IIAACPayload struct {
	RequestID    string            `json:"request_id"`
	ProxyID      string            `json:"proxy_id"`
	TimestampUTC string            `json:"timestamp_utc"`
	Identity     Identity          `json:"identity"`
	Intent       Intent            `json:"intent"`
	Asset        Asset             `json:"asset"`
	Action       Action            `json:"action"`
	Context      map[string]interface{} `json:"context"`
	// Phase 1: action parameters to validate against bounds
	ActionParameters map[string]interface{} `json:"action_parameters"`
	// Phase 2: delegation chain
	DelegationChain []DelegationLink `json:"delegation_chain"`
}

// Identity with optional IIAAC capabilities (ParameterBoundsSchema)
type Identity struct {
	AgentID        string       `json:"agent_id"`
	CertFingerprint string      `json:"cert_fingerprint"`
	CertExpiry     string       `json:"cert_expiry"`
	Capabilities   []Capability `json:"capabilities"`
}

// ── Phase 1: ParameterBoundsSchema ───────────────────────────

type Capability struct {
	Name            string                     `json:"name"`
	ParameterBounds map[string]ParameterBound  `json:"parameter_bounds"`
}

// SemanticType constrains how the value is interpreted
type SemanticType string

const (
	SemanticCurrency  SemanticType = "CURRENCY"
	SemanticAccountID SemanticType = "ACCOUNT_ID"
	SemanticDate      SemanticType = "DATE"
	SemanticEmail     SemanticType = "EMAIL"
	SemanticFreetext  SemanticType = "FREETEXT"
)

type ParameterBound struct {
	Min           *float64       `json:"min"`
	Max           *float64       `json:"max"`
	AllowedValues []interface{}  `json:"allowed_values"`
	Pattern       string         `json:"pattern"`
	SemanticType  SemanticType   `json:"semantic_type"`
}

// ── Phase 2: Delegation Chain ─────────────────────────────────

type DelegationLink struct {
	AgentID             string `json:"agent_id"`
	CredentialHash      string `json:"credential_hash"`
	DelegatedCapability string `json:"delegated_capability"`
	DelegatedAt         string `json:"delegated_at"` // ISO8601
}

// ── Remaining payload types ───────────────────────────────────

type Intent struct {
	Declared     string `json:"declared"`
	InferredTool string `json:"inferred_tool"`
}

type Asset struct {
	ResourceURI  string `json:"resource_uri"`
	NormalizedID string `json:"normalized_id"`
}

type Action struct {
	MCPMethod      string `json:"mcp_method"`
	Classification string `json:"classification"`
}

// ── Result ─────────────────────────────────────────────────────

type BrokenLinkInfo struct {
	AgentID string `json:"agent_id"`
	Reason  string `json:"reason"`
}

type ParameterValidationResult struct {
	Checked []string `json:"checked"`
	Passed  []string `json:"passed"`
	Failed  []string `json:"failed"`
}

type EvalResult struct {
	Decision            string                     `json:"decision"` // ALLOW | DENY
	ReasonCode          string                     `json:"reason_code,omitempty"`
	Field               string                     `json:"field,omitempty"`
	BrokenLink          *BrokenLinkInfo            `json:"broken_link,omitempty"`
	ParameterValidation *ParameterValidationResult `json:"parameter_validation"`
	TrustChainDepth     int                        `json:"trust_chain_depth"`
}

// ── Constants ──────────────────────────────────────────────────

const (
	MaxChainDepth    = 5
	DelegationTTLSec = 300
	AISBaseURL       = "https://api.agentidentity.systems"
)

// ── Evaluate — main arbitration entry point ───────────────────

func Evaluate(req *ArbitrateRequest) *EvalResult {
	pv := &ParameterValidationResult{
		Checked: []string{},
		Passed:  []string{},
		Failed:  []string{},
	}

	if req.IIAACPayload == nil {
		return &EvalResult{
			Decision:            "DENY",
			ReasonCode:          "SAL-4000",
			Field:               "iiaac_payload",
			ParameterValidation: pv,
			TrustChainDepth:     0,
		}
	}

	p := req.IIAACPayload

	// ── Phase 2: Delegation chain validation ──────────────────
	chainDepth := len(p.DelegationChain)
	if chainDepth > MaxChainDepth {
		return &EvalResult{
			Decision:            "DENY",
			ReasonCode:          "SAL-4012",
			Field:               "DELEGATION_CHAIN_VIOLATION",
			ParameterValidation: pv,
			TrustChainDepth:     chainDepth,
		}
	}

	for _, link := range p.DelegationChain {
		if err := validateDelegationLink(link); err != nil {
			return &EvalResult{
				Decision:   "DENY",
				ReasonCode: "SAL-4011",
				Field:      "DELEGATION_CHAIN_VIOLATION",
				BrokenLink: &BrokenLinkInfo{AgentID: link.AgentID, Reason: err.Error()},
				ParameterValidation: pv,
				TrustChainDepth: chainDepth,
			}
		}
	}

	// ── Phase 1: Parameter bounds validation ──────────────────
	if len(p.ActionParameters) > 0 && len(p.Identity.Capabilities) > 0 {
		for _, cap := range p.Identity.Capabilities {
			for paramName, bound := range cap.ParameterBounds {
				pv.Checked = append(pv.Checked, paramName)
				val, exists := p.ActionParameters[paramName]
				if !exists {
					pv.Passed = append(pv.Passed, paramName)
					continue
				}
				if err := validateParameter(paramName, val, bound); err != nil {
					pv.Failed = append(pv.Failed, paramName)
					return &EvalResult{
						Decision:            "DENY",
						ReasonCode:          "SAL-4010",
						Field:               "PARAMETER_BOUNDS_VIOLATION",
						ParameterValidation: pv,
						TrustChainDepth:     chainDepth,
					}
				}
				pv.Passed = append(pv.Passed, paramName)
			}
		}
	}

	// ── Base policy: ALLOW if cert not expired ────────────────
	if p.Identity.CertExpiry != "" {
		exp, err := time.Parse(time.RFC3339, p.Identity.CertExpiry)
		if err == nil && exp.Before(time.Now().UTC()) {
			return &EvalResult{
				Decision:            "DENY",
				ReasonCode:          "SAL-4001",
				Field:               "cert_expiry",
				ParameterValidation: pv,
				TrustChainDepth:     chainDepth,
			}
		}
	}

	return &EvalResult{
		Decision:            "ALLOW",
		ParameterValidation: pv,
		TrustChainDepth:     chainDepth,
	}
}

// ── Parameter validation ───────────────────────────────────────

func validateParameter(name string, val interface{}, bound ParameterBound) error {
	// Numeric bounds (CURRENCY, etc.)
	if bound.SemanticType == SemanticCurrency || bound.Min != nil || bound.Max != nil {
		numVal, ok := toFloat(val)
		if !ok {
			return fmt.Errorf("parameter %q: expected numeric value, got %T", name, val)
		}
		if bound.Min != nil && numVal < *bound.Min {
			return fmt.Errorf("parameter %q value %.2f below minimum %.2f", name, numVal, *bound.Min)
		}
		if bound.Max != nil && numVal > *bound.Max {
			return fmt.Errorf("parameter %q value %.2f exceeds maximum %.2f", name, numVal, *bound.Max)
		}
	}

	// Allowed values check
	if len(bound.AllowedValues) > 0 {
		found := false
		for _, av := range bound.AllowedValues {
			if fmt.Sprintf("%v", av) == fmt.Sprintf("%v", val) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("parameter %q value %v not in allowed_values", name, val)
		}
	}

	// Pattern check (EMAIL, ACCOUNT_ID, etc.)
	if bound.Pattern != "" {
		strVal, ok := val.(string)
		if !ok {
			return fmt.Errorf("parameter %q: pattern requires string value", name)
		}
		re, err := regexp.Compile(bound.Pattern)
		if err != nil {
			return fmt.Errorf("parameter %q: invalid pattern: %v", name, err)
		}
		if !re.MatchString(strVal) {
			return fmt.Errorf("parameter %q value %q does not match pattern %q", name, strVal, bound.Pattern)
		}
	}

	return nil
}

func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// ── Delegation chain validation ────────────────────────────────

func validateDelegationLink(link DelegationLink) error {
	if link.AgentID == "" {
		return fmt.Errorf("missing agent_id")
	}
	if link.CredentialHash == "" {
		return fmt.Errorf("missing credential_hash for agent %s", link.AgentID)
	}
	if link.DelegatedCapability == "" {
		return fmt.Errorf("missing delegated_capability for agent %s", link.AgentID)
	}

	// TTL check
	if link.DelegatedAt != "" {
		delegatedAt, err := time.Parse(time.RFC3339, link.DelegatedAt)
		if err == nil {
			age := time.Since(delegatedAt).Seconds()
			if age > DelegationTTLSec {
				return fmt.Errorf("delegation TTL expired for agent %s (age: %.0fs, max: %ds)",
					link.AgentID, age, DelegationTTLSec)
			}
		}
	}

	// AIS credential verification (best-effort — don't fail on network error)
	if err := verifyAgentCredential(link.AgentID, link.CredentialHash); err != nil {
		// Only hard-fail on definitive 404 (agent decommissioned)
		if strings.Contains(err.Error(), "agent not found") {
			return fmt.Errorf("agent %s credential not found in AIS: %v", link.AgentID, err)
		}
		// Timeout / network issues: log and continue (non-blocking)
	}

	return nil
}

// verifyAgentCredential calls AIS to verify an agent's credential is still active.
func verifyAgentCredential(agentID, credHash string) error {
	url := fmt.Sprintf("%s/agents/%s/verify", AISBaseURL, agentID)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("AIS unreachable: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("agent not found in AIS (404)")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AIS returned %d: %s", resp.StatusCode, string(body)[:min(len(body), 100)])
	}

	// Parse response and verify credential hash if present
	var result map[string]interface{}
	if json.Unmarshal(body, &result) == nil {
		// Check revoked status
		if status, _ := result["status"].(string); status == "suspended" || status == "decommissioned" {
			return fmt.Errorf("agent %s is %s in AIS", agentID, status)
		}
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
