package mcp

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "secrets_search",
			"description": "Search MalikSSM secrets semantically by keyword, service, host, or tags. ALWAYS call this first before asking the user for any password, API key, token, SSH host, or database credential. Returns secret paths, descriptions, tags, and available field names (schema_keys) without exposing secret values.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Search query keywords (e.g., 'ssh hetzner', 'openai', 'postgres', 'win server'). Leave empty to list all accessible secrets.",
					},
					"tags": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Optional list of tags to filter by.",
					},
				},
			},
		},
		{
			"name":        "secrets_get",
			"description": "Retrieve a decrypted secret or a specific key field from MalikSSM by path (e.g., 'apis/openai/prod' or 'servidores/hetzner/ssh').",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"path"},
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Hierarchical path of the secret discovered via secrets_search.",
					},
					"field": map[string]any{
						"type":        "string",
						"description": "Optional specific key inside a KV secret (e.g., 'password', 'api_key', 'host').",
					},
					"stage": map[string]any{
						"type":        "string",
						"description": "Optional staging label: 'AWSCURRENT' (default) or 'AWSPREVIOUS'.",
					},
				},
			},
		},
		{
			"name":        "secrets_set",
			"description": "Create or update (rotate) a secret in MalikSSM. Use this whenever you generate a new API key, password, token, or database credential so the user and other agents can access it.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"path"},
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Hierarchical secret path (e.g., 'proyectos/erp/postgres').",
					},
					"type": map[string]any{
						"type":        "string",
						"enum":        []string{"kv", "string", "env", "ssh_key", "totp"},
						"description": "Secret type (defaults to 'kv' if data is provided, or 'string').",
					},
					"description": map[string]any{
						"type":        "string",
						"description": "Clear human/agent description of what this secret is used for.",
					},
					"tags": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Tags for discovery (e.g., ['db', 'postgres', 'prod']).",
					},
					"data": map[string]any{
						"type":                 "object",
						"additionalProperties": map[string]any{"type": "string"},
						"description":          "Key-value dictionary of secret fields (e.g., {'host': '10.0.0.5', 'username': 'admin', 'password': '...'}).",
					},
					"value": map[string]any{
						"type":        "string",
						"description": "Plain string secret value (if not using key-value 'data').",
					},
				},
			},
		},
		{
			"name":        "secrets_totp",
			"description": "Generate the live 6-digit 2FA TOTP code (RFC 6238) and remaining validity window for a secret containing a TOTP seed or otpauth:// URI.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"path"},
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Secret path containing the TOTP seed.",
					},
				},
			},
		},
		{
			"name":        "secrets_exec",
			"description": "Blind Secret Injection: Execute a local command with secrets from MalikSSM injected as environment variables (or via {{SECRET:path#field}} placeholders). Automatically redacts secret values (***REDACTED***) from stdout/stderr so raw passwords never leak into chat logs.",
			"inputSchema": map[string]any{
				"type":     "object",
				"required": []string{"command"},
				"properties": map[string]any{
					"secrets": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "List of secret paths to inject as uppercase environment variables into the child process.",
					},
					"command": map[string]any{
						"description": "Command string or array of arguments to execute (supports {{SECRET:path#field}} inline placeholders).",
					},
				},
			},
		},
		{
			"name":        "vault_status",
			"description": "Check MalikSSM server status, lock state, active sessions, and secret count on the Windows Server.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}
