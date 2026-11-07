package agentcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegisterMCPServerPreservesExistingServers(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	original := "\xEF\xBB\xBF" + `{
  "mcpServers": {
    "tdkop": {"command": "python", "args": ["-m", "tdkop"], "env": {"TIMEOUT": 30}}
  },
  "globalShortcut": "Ctrl+Space"
}`
	if err := os.WriteFile(cfgPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	backup, err := RegisterMCPServer(cfgPath, "malik", `C:\bin\malik.exe`, []string{"mcp", "--caller", "claude-desktop"})
	if err != nil {
		t.Fatalf("RegisterMCPServer failed: %v", err)
	}
	if backup == "" {
		t.Fatalf("expected a backup of the existing config")
	}
	if raw, _ := os.ReadFile(backup); string(raw) != original {
		t.Fatalf("backup does not match the original file")
	}

	raw, _ := os.ReadFile(cfgPath)
	if len(raw) >= 3 && raw[0] == 0xEF {
		t.Fatalf("rewritten config must not start with a UTF-8 BOM")
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("rewritten config is not valid JSON: %v", err)
	}
	servers := cfg["mcpServers"].(map[string]any)
	if _, ok := servers["tdkop"]; !ok {
		t.Fatalf("existing MCP server 'tdkop' was lost: %s", raw)
	}
	if _, ok := servers["malik"]; !ok {
		t.Fatalf("'malik' MCP server was not registered: %s", raw)
	}
	if cfg["globalShortcut"] != "Ctrl+Space" {
		t.Fatalf("unrelated top-level keys were lost: %s", raw)
	}
	if env := servers["tdkop"].(map[string]any)["env"].(map[string]any); env["TIMEOUT"] != float64(30) {
		t.Fatalf("numeric values were altered: %v", env["TIMEOUT"])
	}
}

func TestRegisterMCPServerRefusesUnparseableConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	broken := `{"mcpServers": {"tdkop": `
	if err := os.WriteFile(cfgPath, []byte(broken), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterMCPServer(cfgPath, "malik", "malik", []string{"mcp"}); err == nil {
		t.Fatalf("expected an error for an unparseable config")
	}
	if raw, _ := os.ReadFile(cfgPath); string(raw) != broken {
		t.Fatalf("unparseable config must be left untouched")
	}
}

func TestRegisterMCPServerCreatesMissingConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "Claude", "claude_desktop_config.json")
	backup, err := RegisterMCPServer(cfgPath, "malik", "malik", []string{"mcp"})
	if err != nil || backup != "" {
		t.Fatalf("expected clean creation without backup, got backup=%q err=%v", backup, err)
	}
	raw, _ := os.ReadFile(cfgPath)
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("created config is not valid JSON: %v", err)
	}
}

func TestAddAllowRulesMergesWithoutDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	original := `{"model":"opus","permissions":{"allow":["Bash(git *)","mcp__malik__secrets_search"],"deny":["Bash(rm -rf *)"]}}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	added, backup, err := AddAllowRules(path, AgentAllowRules)
	if err != nil {
		t.Fatal(err)
	}
	if backup == "" || len(added) != len(AgentAllowRules)-1 {
		t.Fatalf("expected %d new rules and a backup, got %d (backup=%q)", len(AgentAllowRules)-1, len(added), backup)
	}

	var cfg map[string]any
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	perms := cfg["permissions"].(map[string]any)
	allow := perms["allow"].([]any)
	if allow[0] != "Bash(git *)" || len(allow) != len(AgentAllowRules)+1 {
		t.Fatalf("existing rules must be kept first and nothing duplicated: %v", allow)
	}
	if cfg["model"] != "opus" || len(perms["deny"].([]any)) != 1 {
		t.Fatalf("unrelated settings were changed: %s", raw)
	}

	added, _, err = AddAllowRules(path, AgentAllowRules)
	if err != nil || len(added) != 0 {
		t.Fatalf("second run must be a no-op, got %v err=%v", added, err)
	}
	for _, r := range AgentAllowRules {
		if r == "mcp__malik__secrets_get" || r == "Bash(malik get *)" {
			t.Fatalf("value-returning tools must not be auto-allowed: %s", r)
		}
	}
}

func TestUpsertRuleBlockReplacesLegacyAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CLAUDE.md")
	legacy := "# Mis reglas\n- usa español\n\n# MalikSSM — Protocolo Global de Credenciales y Secretos\n- NUNCA pidas contraseñas.\n- Para leer un secreto usa `secrets_get`.\n\n# Otra sección\n- se mantiene\n"
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := UpsertRuleBlock(path)
	if err != nil || !changed {
		t.Fatalf("expected the legacy block to be replaced, changed=%v err=%v", changed, err)
	}
	raw, _ := os.ReadFile(path)
	got := string(raw)
	if strings.Contains(got, "Protocolo Global") || strings.Contains(got, "Para leer un secreto usa") {
		t.Fatalf("legacy block must be removed:\n%s", got)
	}
	for _, keep := range []string{"# Mis reglas\n- usa español", "# Otra sección\n- se mantiene", "remote_exec"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("missing %q after upsert:\n%s", keep, got)
		}
	}
	if strings.Count(got, ruleBegin) != 1 {
		t.Fatalf("expected exactly one managed block:\n%s", got)
	}
	if changed, err := UpsertRuleBlock(path); err != nil || changed {
		t.Fatalf("second run must be a no-op, changed=%v err=%v", changed, err)
	}

	fresh := filepath.Join(t.TempDir(), "nuevo", "CLAUDE.md")
	if changed, err := UpsertRuleBlock(fresh); err != nil || !changed {
		t.Fatalf("expected a new file, changed=%v err=%v", changed, err)
	}
}
