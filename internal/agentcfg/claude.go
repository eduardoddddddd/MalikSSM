package agentcfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ClaudeDesktopConfigPath returns the default claude_desktop_config.json location for the current OS.
func ClaudeDesktopConfigPath() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "Claude", "claude_desktop_config.json")
		}
		return filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	default:
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	}
}

// RegisterMCPServer adds or replaces a single entry under "mcpServers" in an MCP host config file,
// preserving every other key and server. It never overwrites a file it cannot parse: in that case it
// returns an error and leaves the file untouched. Existing files are backed up before being rewritten.
// It returns the backup path ("" if the file did not exist).
func RegisterMCPServer(cfgPath, name, command string, args []string) (string, error) {
	cfg, err := readConfig(cfgPath)
	if err != nil {
		return "", err
	}
	servers := map[string]any{}
	if existing, ok := cfg["mcpServers"]; ok && existing != nil {
		m, ok := existing.(map[string]any)
		if !ok {
			return "", fmt.Errorf("\"mcpServers\" en %s no es un objeto JSON (no se modifica)", cfgPath)
		}
		servers = m
	}
	entry := map[string]any{
		"command": command,
		"args":    args,
	}
	if current, ok := servers[name]; ok {
		before, _ := json.Marshal(current)
		after, _ := json.Marshal(entry)
		if string(before) == string(after) {
			return "", nil // already registered exactly like this: no rewrite, no new backup
		}
	}
	servers[name] = entry
	cfg["mcpServers"] = servers
	return writeConfig(cfgPath, cfg)
}

// AntigravityConfigPath returns Google Antigravity's MCP config (~/.gemini/config/mcp_config.json,
// the same "mcpServers" format as Claude Desktop) and whether Antigravity appears to be set up
// for this user (~/.gemini exists).
func AntigravityConfigPath() (string, bool) {
	home, _ := os.UserHomeDir()
	gemini := filepath.Join(home, ".gemini")
	_, err := os.Stat(gemini)
	return filepath.Join(gemini, "config", "mcp_config.json"), err == nil
}

// ClaudeCodeSettingsPath returns the user-level Claude Code settings file (~/.claude/settings.json).
func ClaudeCodeSettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "settings.json")
}

// AgentAllowRules are the Claude Code permission rules MalikSSM proposes: discovery, status and
// the two tools that use credentials without returning them (remote_exec / malik ssh and
// secrets_exec). Tools that return secret values (secrets_get, malik get, secrets_totp) are left
// out on purpose, so they keep asking for confirmation.
var AgentAllowRules = []string{
	"mcp__malik__secrets_search",
	"mcp__malik__vault_status",
	"mcp__malik__remote_exec",
	"mcp__malik__secrets_exec",
	"Bash(malik ssh *)",
	"Bash(malik search *)",
	"Bash(malik ls*)",
	"Bash(malik status*)",
	"PowerShell(malik ssh *)",
	"PowerShell(malik search *)",
	"PowerShell(malik ls*)",
	"PowerShell(malik status*)",
}

// AddAllowRules appends the given rules to permissions.allow in a Claude Code settings file,
// keeping every existing key and rule. It returns the rules actually added and the backup path.
func AddAllowRules(settingsPath string, rules []string) ([]string, string, error) {
	cfg, err := readConfig(settingsPath)
	if err != nil {
		return nil, "", err
	}
	perms := map[string]any{}
	if existing, ok := cfg["permissions"]; ok && existing != nil {
		m, ok := existing.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("\"permissions\" en %s no es un objeto JSON (no se modifica)", settingsPath)
		}
		perms = m
	}
	var allow []any
	if existing, ok := perms["allow"]; ok && existing != nil {
		a, ok := existing.([]any)
		if !ok {
			return nil, "", fmt.Errorf("\"permissions.allow\" en %s no es una lista (no se modifica)", settingsPath)
		}
		allow = a
	}
	present := map[string]bool{}
	for _, r := range allow {
		if s, ok := r.(string); ok {
			present[s] = true
		}
	}
	var added []string
	for _, r := range rules {
		if !present[r] {
			allow = append(allow, r)
			present[r] = true
			added = append(added, r)
		}
	}
	if len(added) == 0 {
		return nil, "", nil
	}
	perms["allow"] = allow
	cfg["permissions"] = perms
	backup, err := writeConfig(settingsPath, cfg)
	return added, backup, err
}

// readConfig parses a JSON object file (tolerating a UTF-8 BOM); a missing file is an empty object.
// It refuses files it cannot parse, so callers never overwrite them.
func readConfig(path string) (map[string]any, error) {
	cfg := map[string]any{}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if len(trimmed) == 0 {
		return cfg, nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("no se puede leer %s como JSON (no se modifica): %w", path, err)
	}
	if cfg == nil {
		return nil, fmt.Errorf("%s no contiene un objeto JSON (no se modifica)", path)
	}
	return cfg, nil
}

// writeConfig backs up an existing file, then writes cfg atomically, indented and without BOM.
// It returns the backup path ("" when the file did not exist).
func writeConfig(path string, cfg map[string]any) (string, error) {
	backupPath := ""
	if raw, err := os.ReadFile(path); err == nil {
		backupPath = fmt.Sprintf("%s.bak-malik-%s", path, time.Now().Format("20060102-150405"))
		if err := os.WriteFile(backupPath, raw, 0600); err != nil {
			return "", fmt.Errorf("no se pudo crear la copia de seguridad %s: %w", backupPath, err)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return "", err
		}
	} else {
		return "", err
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	out = append(out, '\n')
	tmp := path + ".tmp-malik"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return backupPath, nil
}

const (
	ruleBegin = "<!-- malik:begin (gestionado por `malik init-agents`) -->"
	ruleEnd   = "<!-- malik:end -->"
	// legacyRuleHeading starts the unmarked block written by earlier versions of init-agents.
	legacyRuleHeading = "# MalikSSM — Protocolo Global de Credenciales y Secretos"
)

// AgentRules is the CLAUDE.md block that tells agents how to use MalikSSM: discover with
// secrets_search, act with remote_exec / secrets_exec, and never pull raw passwords.
const AgentRules = ruleBegin + `
# MalikSSM — credenciales y acceso a equipos
- No pidas al usuario contraseñas, API keys, tokens, usuarios ni IPs: búscalos con ` + "`secrets_search`" + ` (MCP) o ` + "`malik search <término>`" + `.
- Para actuar en una máquina usa ` + "`remote_exec`" + ` (MCP) o ` + "`malik ssh <equipo> -- <comando>`" + `: MalikSSM usa la credencial sin mostrártela (como AWS SSM).
- Para un comando local que necesite un secreto usa ` + "`secrets_exec`" + ` (MCP) o ` + "`malik run -s <ruta> -- <comando>`" + `.
- No extraigas contraseñas con ` + "`secrets_get`" + ` / ` + "`malik get`" + `: úsalos solo para metadatos (host, puerto, usuario).
- Si generas una credencial nueva, guárdala con ` + "`secrets_set`" + ` (o ` + "`malik set <ruta> campo=? --blind`" + `).
` + ruleEnd + "\n"

// UpsertRuleBlock writes AgentRules into a CLAUDE.md file: it replaces a previous managed block
// (or the legacy unmarked one) and appends it otherwise, leaving the rest of the file untouched.
// It reports whether the file changed.
func UpsertRuleBlock(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	content := string(raw)
	updated := content

	if b := strings.Index(content, ruleBegin); b >= 0 {
		if e := strings.Index(content[b:], ruleEnd); e >= 0 {
			end := b + e + len(ruleEnd)
			if end < len(content) && content[end] == '\n' {
				end++
			}
			updated = content[:b] + AgentRules + content[end:]
		}
	} else if h := strings.Index(content, legacyRuleHeading); h >= 0 {
		// Legacy block: the heading line plus the "- " bullet lines that follow it.
		end := h + len(legacyRuleHeading)
		for end < len(content) {
			nl := strings.IndexByte(content[end:], '\n')
			if nl < 0 {
				end = len(content)
				break
			}
			next := end + nl + 1
			if !strings.HasPrefix(content[next:], "- ") {
				end = next
				break
			}
			end = next
		}
		updated = content[:h] + AgentRules + content[end:]
	} else {
		if updated != "" && !strings.HasSuffix(updated, "\n") {
			updated += "\n"
		}
		if updated != "" {
			updated += "\n"
		}
		updated += AgentRules
	}

	if updated == content {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, []byte(updated), 0600)
}
