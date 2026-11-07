package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/malikssm/malik/internal/client"
	"github.com/malikssm/malik/internal/injector"
	"github.com/malikssm/malik/internal/remote"
	"github.com/malikssm/malik/internal/vault"
)

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server implements the Model Context Protocol (MCP) over stdio.
type Server struct {
	ServerOverride string
	TokenOverride  string
	CallerAgent    string
	// NoReveal makes secrets_get mask every sensitive value, as if all secrets were blind_only.
	NoReveal bool
}

// isPublicField mirrors the injector's notion of non-sensitive KV fields (host, port, user...),
// which agents may read to know where to connect.
func isPublicField(k string) bool {
	return !injector.IsSensitiveFieldName(k)
}

// NewServer creates a new stdio MCP server instance.
func NewServer(serverOverride, tokenOverride, callerAgent string) *Server {
	if callerAgent == "" {
		callerAgent = "mcp-agent"
	}
	return &Server{
		ServerOverride: serverOverride,
		TokenOverride:  tokenOverride,
		CallerAgent:    callerAgent,
	}
}

// apiClient resolves the freshest DPAPI session.bin or token on every tool call
// so running `malik login` immediately authenticates already-open MCP hosts (Claude/Antigravity).
func (s *Server) apiClient() *client.Client {
	return client.New(s.ServerOverride, s.TokenOverride, s.CallerAgent)
}

// ServeStdio processes JSON-RPC 2.0 MCP messages over stdin/stdout.
func (s *Server) ServeStdio() error {
	reader := bufio.NewReader(os.Stdin)
	writer := os.Stdout

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(strings.ToLower(trimmed), "content-length:") {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal([]byte(trimmed), &req); err != nil {
			continue
		}

		// Notifications (no ID) do not expect a response
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue
		}

		resp := s.handleRequest(&req)
		rawResp, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		_, _ = fmt.Fprintf(writer, "%s\n", string(rawResp))
	}
}

func (s *Server) handleRequest(req *jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]any{
					"tools": map[string]any{"listChanged": false},
				},
				"serverInfo": map[string]any{
					"name":    "malik-ssm-mcp",
					"version": "1.0.0",
				},
				"instructions": "MalikSSM Agentic Secrets Manager. NEVER ask the user for passwords, API keys, tokens, SSH hosts, or database credentials. Call secrets_search first to discover what exists. To act on a machine, call remote_exec (credentials are resolved and used inside MalikSSM, like AWS SSM send-command). To run a local command that needs a secret, call secrets_exec. Use secrets_get only for non-secret metadata (host, port, username); do not try to extract passwords.",
			},
		}

	case "ping":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}

	case "tools/list":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": toolDefinitions(),
			},
		}

	case "tools/call":
		var callParams struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			return jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &jsonRPCError{Code: -32602, Message: "invalid tool call arguments"},
			}
		}
		text, isErr := s.executeTool(callParams.Name, callParams.Arguments)
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": text,
					},
				},
				"isError": isErr,
			},
		}

	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonRPCError{Code: -32601, Message: "Method not found: " + req.Method},
		}
	}
}

func (s *Server) executeTool(name string, args map[string]any) (string, bool) {
	api := s.apiClient()

	switch name {
	case "secrets_search":
		query, _ := args["query"].(string)
		var tags []string
		if rawTags, ok := args["tags"].([]any); ok {
			for _, t := range rawTags {
				if ts, ok := t.(string); ok {
					tags = append(tags, ts)
				}
			}
		}
		hits, err := api.SearchSecrets(query, tags)
		if err != nil {
			return fmt.Sprintf("MalikSSM Error: %v", err), true
		}
		out, _ := json.MarshalIndent(map[string]any{
			"query":   query,
			"count":   len(hits),
			"results": hits,
			"hint":    "Use secrets_get with the exact 'path' (and optional 'field' from schema_keys) to retrieve the credential, or secrets_exec to inject it into a command.",
		}, "", "  ")
		return string(out), false

	case "secrets_get":
		path, _ := args["path"].(string)
		field, _ := args["field"].(string)
		stage, _ := args["stage"].(string)
		if strings.TrimSpace(path) == "" {
			return "Error: 'path' is required", true
		}
		sec, err := api.GetSecret(path, 0, stage)
		if err != nil {
			return fmt.Sprintf("MalikSSM Error retrieving %q: %v", path, err), true
		}
		// Values returned here land in the model's context (and the provider's logs). Blind secrets,
		// or every secret when the server runs with --no-reveal, are only usable through secrets_exec.
		if sec.BlindOnly || s.NoReveal {
			for k := range sec.Data {
				if !isPublicField(k) {
					sec.Data[k] = "***BLIND***"
				}
			}
			sec.Value = ""
			if field != "" && !isPublicField(field) {
				return fmt.Sprintf("Secret %q is blind-only: its values are never returned to the agent. Use secrets_exec with secrets=[%q] (env vars) or the {{SECRET:%s#%s}} placeholder.", sec.Path, sec.Path, sec.Path, field), true
			}
		}
		if field != "" {
			val, ok := sec.Data[field]
			if !ok {
				return fmt.Sprintf("Field %q not found in secret %q. Available fields: %v", field, sec.Path, sec.SchemaKeys), true
			}
			out, _ := json.MarshalIndent(map[string]any{
				"path":    sec.Path,
				"field":   field,
				"value":   val,
				"version": sec.Version,
			}, "", "  ")
			return string(out), false
		}
		out, _ := json.MarshalIndent(sec, "", "  ")
		return string(out), false

	case "secrets_set":
		path, _ := args["path"].(string)
		secType, _ := args["type"].(string)
		desc, _ := args["description"].(string)
		val, _ := args["value"].(string)

		var tags []string
		if rawTags, ok := args["tags"].([]any); ok {
			for _, t := range rawTags {
				if ts, ok := t.(string); ok {
					tags = append(tags, ts)
				}
			}
		}
		dataMap := make(map[string]string)
		if rawData, ok := args["data"].(map[string]any); ok {
			for k, v := range rawData {
				dataMap[k] = fmt.Sprintf("%v", v)
			}
		}

		in := vault.PutSecretInput{
			Path:        path,
			Type:        secType,
			Description: desc,
			Tags:        tags,
			Value:       val,
			Data:        dataMap,
		}
		if blind, ok := args["blind_only"].(bool); ok {
			in.BlindOnly = &blind
		}
		meta, err := api.PutSecret(in)
		if err != nil {
			return fmt.Sprintf("MalikSSM Error saving %q: %v", path, err), true
		}
		out, _ := json.MarshalIndent(meta, "", "  ")
		return string(out), false

	case "secrets_totp":
		path, _ := args["path"].(string)
		res, err := api.GetTOTP(path)
		if err != nil {
			return fmt.Sprintf("MalikSSM TOTP Error for %q: %v", path, err), true
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		return string(out), false

	case "secrets_exec":
		var secPaths []string
		if rawSecs, ok := args["secrets"].([]any); ok {
			for _, s := range rawSecs {
				if str, ok := s.(string); ok {
					secPaths = append(secPaths, str)
				}
			}
		}
		var cmdSlice []string
		if rawCmd, ok := args["command"].([]any); ok {
			for _, c := range rawCmd {
				if str, ok := c.(string); ok {
					cmdSlice = append(cmdSlice, str)
				}
			}
		} else if cmdStr, ok := args["command"].(string); ok && cmdStr != "" {
			if runtime.GOOS == "windows" {
				cmdSlice = []string{"powershell", "-NoProfile", "-Command", cmdStr}
			} else {
				cmdSlice = []string{"sh", "-c", cmdStr}
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		res, err := injector.RunWithSecrets(ctx, api, secPaths, cmdSlice, false)
		if err != nil {
			return fmt.Sprintf("MalikSSM Exec Error: %v", err), true
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		return string(out), res.ExitCode != 0

	case "remote_exec":
		target, _ := args["target"].(string)
		command, _ := args["command"].(string)
		stdin, _ := args["stdin"].(string)
		timeout := 60 * time.Second
		if secs, ok := args["timeout_seconds"].(float64); ok && secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
		t, err := remote.Resolve(api, target)
		if err != nil {
			return fmt.Sprintf("MalikSSM remote_exec: %v", err), true
		}
		res, err := remote.Run(context.Background(), t, remote.Options{
			Command:         command,
			Stdin:           stdin,
			Timeout:         timeout,
			KnownHostsFiles: remote.DefaultKnownHostsFiles(),
			TOFUFile:        filepath.Join(client.ConfigDir(), "known_hosts"),
		})
		if err != nil {
			return fmt.Sprintf("MalikSSM remote_exec on %q: %v", target, err), true
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		return string(out), res.ExitCode != 0

	case "vault_status":
		st, err := api.Status()
		if err != nil {
			return fmt.Sprintf("MalikSSM Status Error: %v", err), true
		}
		out, _ := json.MarshalIndent(st, "", "  ")
		return string(out), false

	default:
		return fmt.Sprintf("Unknown tool: %s", name), true
	}
}
