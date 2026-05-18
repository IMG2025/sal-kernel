// internal/schema/normalizer.go — SAL Kernel Schema Normalization
//
// SchemaRead resolves a schema by ID from the intent registry.
// Closes the TODO stub — backed by the hardcoded intent registry (v1).
package schema

import (
	"errors"
	"fmt"

	"github.com/coreidentity/sal-kernel/internal/intent"
)

// Schema represents a resolved governance schema.
type Schema struct {
	ID          string
	Version     string
	Description string
	Fields      map[string]interface{}
}

// SchemaRead loads a schema by ID from the intent registry.
func SchemaRead(id string) (*Schema, error) {
	if id == "" {
		return nil, errors.New("schema id cannot be empty")
	}
	intentSchema, err := intent.Resolve(id)
	if err != nil {
		return nil, fmt.Errorf("schema %q not found: %w", id, err)
	}
	return &Schema{
		ID:          intentSchema.ID,
		Version:     "1.0",
		Description: intentSchema.Description,
		Fields:      make(map[string]interface{}),
	}, nil
}

// Normalize applies schema normalization to raw data.
func Normalize(schema *Schema, data map[string]interface{}) (map[string]interface{}, error) {
	// Nil guard (CIDG plat-01)
	if schema == nil {
		return nil, errors.New("cannot normalize: schema is nil — SchemaRead may have failed")
	}
	result := make(map[string]interface{})
	for k, v := range data {
		if _, ok := schema.Fields[k]; ok {
			result[k] = v
		}
	}
	return result, nil
}
