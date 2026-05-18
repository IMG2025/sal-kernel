// internal/intent/registry.go — SAL Kernel Intent Schema Registry
//
// Hardcoded registry aligned to Sentinel risk tier task types.
// Schema updates require a kernel redeploy (by design — Git-auditable,
// zero runtime mutation surface, forensically deterministic).
//
// Canonical intent set (aligned to policyEngine.js / riskTiers.js):
//   ANALYZE   — read-only analytics and reporting (TIER_1+)
//   EXECUTE   — data read/write execution (TIER_2+)
//   ESCALATE  — high-impact operations (TIER_3+, may escalate to TIER_4)
//
// Matching strategy:
//   1. Exact match preferred  (e.g., "ANALYZE")
//   2. Prefix match fallback  (e.g., "ANALYZE_v1" matches "ANALYZE")
//
// Unknown intent → caller receives ErrIntentUnknown → SAL-4002 DENY.
// Empty intent   → caller receives ErrIntentMissing → SAL-4003 DENY.
package intent

import (
	"errors"
	"strings"
)

// Sentinel error values — callers use errors.Is() for precise matching.
var (
	ErrIntentMissing = errors.New("intent declaration missing")
	ErrIntentUnknown = errors.New("intent schema not registered")
)

// IntentSchema defines a registered intent schema entry.
type IntentSchema struct {
	// ID is the canonical identifier (uppercase, e.g. "ANALYZE").
	ID string

	// Description is a human-readable summary of the intent scope.
	Description string

	// MinTier is the minimum Sentinel risk tier required for this intent.
	// Informational at kernel level — tier enforcement is Sentinel's responsibility.
	MinTier string

	// EscalatesTo indicates whether this intent can trigger tier escalation.
	// Only ESCALATE triggers dynamic tier promotion in Sentinel.
	EscalatesTo string
}

// registry is the single source of truth for all registered intent schemas.
// Aligned 1:1 with allowed_task_types in riskTiers.js.
var registry = map[string]IntentSchema{
	"ANALYZE": {
		ID:          "ANALYZE",
		Description: "Read-only analytics and reporting operations. No data mutation permitted.",
		MinTier:     "TIER_1",
		EscalatesTo: "",
	},
	"EXECUTE": {
		ID:          "EXECUTE",
		Description: "Standard execution with data read/write capabilities.",
		MinTier:     "TIER_2",
		EscalatesTo: "",
	},
	"ESCALATE": {
		ID:          "ESCALATE",
		Description: "High-impact operations. Triggers TIER_4 enforcement on TIER_3+ agents.",
		MinTier:     "TIER_3",
		EscalatesTo: "TIER_4",
	},
}

// Resolve matches a declared intent string against the registry.
//
// Matching order:
//  1. Exact match (case-insensitive normalized to uppercase)
//  2. Prefix match — declared intent starts with a registered schema ID
//     followed by '_' (e.g., "ANALYZE_v1" matches "ANALYZE")
//
// Returns (IntentSchema, nil) on match.
// Returns (IntentSchema{}, ErrIntentMissing) if declared is empty.
// Returns (IntentSchema{}, ErrIntentUnknown) if no match found.
func Resolve(declared string) (IntentSchema, error) {
	if strings.TrimSpace(declared) == "" {
		return IntentSchema{}, ErrIntentMissing
	}

	normalized := strings.ToUpper(strings.TrimSpace(declared))

	// Pass 1: exact match
	if schema, ok := registry[normalized]; ok {
		return schema, nil
	}

	// Pass 2: prefix match — "ANALYZE_v1" → "ANALYZE"
	for id, schema := range registry {
		if strings.HasPrefix(normalized, id+"_") {
			return schema, nil
		}
	}

	return IntentSchema{}, ErrIntentUnknown
}

// List returns all registered intent schema IDs in deterministic order.
// Used for audit logging and Proof Pack metadata.
func List() []string {
	return []string{"ANALYZE", "EXECUTE", "ESCALATE"}
}

// IsRegistered is a convenience wrapper for callers that only need a boolean.
func IsRegistered(declared string) bool {
	_, err := Resolve(declared)
	return err == nil
}
