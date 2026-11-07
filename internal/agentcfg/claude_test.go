package agentcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
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
