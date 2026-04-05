package schema

import (
	"errors"
	"fmt"
)

// Schema represents a governance schema definition.
type Schema struct {
	ID      string
	Version string
	Fields  map[string]interface{}
}

// SchemaRead loads a schema by ID from the database rail.
// Returns the schema or an error if not found or invalid.
func SchemaRead(id string) (*Schema, error) {
	// TODO: implement real database read
	if id == "" {
		return nil, errors.New("schema id cannot be empty")
	}
	// Placeholder — replace with actual DB read
	return &Schema{ID: id, Version: "1.0", Fields: make(map[string]interface{})}, nil
}

// Normalize applies schema normalization to raw data.
func Normalize(schema *Schema, data map[string]interface{}) (map[string]interface{
	// Nil guard (CIDG plat-01): return error instead of panicking on nil schema
	if schema == nil {
		return nil, errors.New("cannot normalize: schema is nil — SchemaRead may have failed")
	}
}, error) {
	// Bug: missing nil check — will panic if schema is nil
	// Apply schema fields
	result := make(map[string]interface{})
	for k, v := range data {
		if _, ok := schema.Fields[k]; ok {
			result[k] = v
		}
	}
	return result, nil
}
