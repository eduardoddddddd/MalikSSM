package server

import (
	"fmt"
	"net/http"
)

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	spec := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       "MalikSSM Agentic Secrets Manager API",
			"description": "Self-hosted Secrets Manager running on ASUS ROG Ally. Allows AI agents (ChatGPT, Claude, Antigravity) to search, retrieve, store, and generate 2FA TOTP codes seamlessly.",
			"version":     "1.0.0",
		},
		"servers": []map[string]any{
			{"url": baseURL, "description": "MalikSSM Server (ASUS ROG Ally)"},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "MalikToken",
					"description":  "Pass a scoped App Token (mlk_live_...) or Session Token (mlk_sess_...)",
				},
			},
		},
		"security": []map[string]any{
			{"bearerAuth": []string{}},
		},
		"paths": map[string]any{
			"/v1/search": map[string]any{
				"get": map[string]any{
					"operationId": "searchSecrets",
					"summary":     "Search secrets semantically by keyword or tags without exposing secret values",
					"parameters": []map[string]any{
						{
							"name":        "q",
							"in":          "query",
							"required":    false,
							"description": "Search query (e.g. 'ssh hetzner', 'openai', 'postgres')",
							"schema":      map[string]any{"type": "string"},
						},
						{
							"name":        "tags",
							"in":          "query",
							"required":    false,
							"description": "Comma-separated tags filter",
							"schema":      map[string]any{"type": "string"},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Ranked secret metadata and schema_keys"},
					},
				},
			},
			"/v1/secrets/{path}": map[string]any{
				"get": map[string]any{
					"operationId": "getSecretValue",
					"summary":     "Retrieve decrypted secret value or specific field by path",
					"parameters": []map[string]any{
						{
							"name":        "path",
							"in":          "path",
							"required":    true,
							"description": "Hierarchical path of the secret (e.g. 'apis/openai/prod')",
							"schema":      map[string]any{"type": "string"},
						},
						{
							"name":        "field",
							"in":          "query",
							"required":    false,
							"description": "Optional specific key inside a KV secret (e.g. 'password')",
							"schema":      map[string]any{"type": "string"},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Decrypted secret payload"},
					},
				},
			},
			"/v1/secrets": map[string]any{
				"post": map[string]any{
					"operationId": "upsertSecret",
					"summary":     "Create or update a secret in MalikSSM",
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"type":     "object",
									"required": []string{"path"},
									"properties": map[string]any{
										"path":        map[string]any{"type": "string"},
										"type":        map[string]any{"type": "string", "enum": []string{"kv", "string", "env", "ssh_key", "totp"}},
										"description": map[string]any{"type": "string"},
										"tags":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
										"value":       map[string]any{"type": "string"},
										"data":        map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
									},
								},
							},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Updated secret metadata"},
					},
				},
			},
			"/v1/totp/{path}": map[string]any{
				"get": map[string]any{
					"operationId": "getSecretTOTP",
					"summary":     "Generate the current 6-digit 2FA TOTP code for a secret",
					"parameters": []map[string]any{
						{
							"name":     "path",
							"in":       "path",
							"required": true,
							"schema":   map[string]any{"type": "string"},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Current 6-digit TOTP code and remaining validity seconds"},
					},
				},
			},
		},
	}

	writeJSON(w, http.StatusOK, spec)
}
