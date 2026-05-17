// sal-kernel — CoreIdentity SAL Arbitration Engine
// Phases: parameter-validation + delegation-chain
// Port 8443 (plain HTTP, TLS terminated at GKE ingress)
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/coreidentity/sal-kernel/internal/arbitration"
)

// ── Global counters ────────────────────────────────────────────
var (
	proofPackTotal  atomic.Int64
	policyVersion   = getEnv("SAL_POLICY_VERSION", "v2.1.0-param-validation")
	listenAddr      = ":" + getEnv("PORT", "8443")
)

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ── Health ─────────────────────────────────────────────────────
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           "healthy",
		"service":          "sal-kernel",
		"policy_version":   policyVersion,
		"proof_pack_total": proofPackTotal.Load(),
		"ts":               time.Now().UTC().Format(time.RFC3339),
	})
}

// ── Arbitrate ──────────────────────────────────────────────────
func arbitrateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	t0 := time.Now()

	var req arbitration.ArbitrateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	result := arbitration.Evaluate(&req)

	latency := time.Since(t0)
	proofID := newUUID()
	anchor  := anchorHash(proofID)
	proofPackTotal.Add(1)

	agentID := ""
	intent  := ""
	action  := ""
	asset   := ""
	if p := req.IIAACPayload; p != nil {
		agentID = p.Identity.AgentID
		intent  = p.Intent.Declared
		action  = p.Action.Classification
		asset   = p.Asset.NormalizedID
	}

	log.Printf("[EVAL] %s agent:%s intent:%s action:%s asset:%s latency:%s",
		result.Decision, agentID, intent, action, asset, latency)
	log.Printf("[LEDGER] Anchored proof pack — id: %s anchor: %s...%s",
		proofID, anchor[:8], anchor[len(anchor)-8:])

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"decision":             result.Decision,
		"proof_pack_id":        proofID,
		"proof_pack_anchor":    anchor,
		"policy_version":       policyVersion,
		"request_id":           req.RequestID,
		"agent_id":             agentID,
		"latency_us":           fmt.Sprintf("%.3fµs", float64(latency.Nanoseconds())/1000),
		"reason_code":          result.ReasonCode,
		"field":                result.Field,
		"broken_link":          result.BrokenLink,
		"parameter_validation": result.ParameterValidation,
		"trust_chain_depth":    result.TrustChainDepth,
		"audit_trail":          true,
		"ts":                   time.Now().UTC().Format(time.RFC3339),
	})
}

// ── Helpers ────────────────────────────────────────────────────
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func anchorHash(id string) string {
	h := sha256.Sum256([]byte(id + time.Now().String()))
	return hex.EncodeToString(h[:])
}

// ── Main ───────────────────────────────────────────────────────
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health",    healthHandler)
	mux.HandleFunc("/v1/arbitrate", arbitrateHandler)
	mux.HandleFunc("/health",       healthHandler) // alias

	log.Printf("[BOOT] SAL Kernel %s listening on %s", policyVersion, listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("[BOOT] fatal: %v", err)
	}
}
