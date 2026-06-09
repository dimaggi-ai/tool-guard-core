package domain

import "time"

// ToolSchema defines the per-tool field schema for PII redaction control.
// Fields marked safe_to_persist are kept; all others are tokenized (deny-by-default).
type ToolSchema struct {
	SchemaID  string                    `json:"schema_id"`
	OrgID     string                    `json:"org_id"`
	ToolName  string                    `json:"tool_name"`
	Fields    map[string]ToolFieldSchema `json:"fields"`
	CreatedAt time.Time                 `json:"created_at"`
	UpdatedAt time.Time                 `json:"updated_at"`
}

// ToolFieldSchema describes a single field within a tool's parameter schema.
type ToolFieldSchema struct {
	Type          string `json:"type"`
	SafeToPersist bool   `json:"safe_to_persist"`
}
