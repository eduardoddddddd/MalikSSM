package agentcfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	cfg := map[string]any{}
	backupPath := ""

	raw, err := os.ReadFile(cfgPath)
	switch {
	case err == nil:
		trimmed := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
		if len(trimmed) > 0 {
			dec := json.NewDecoder(bytes.NewReader(trimmed))
			dec.UseNumber()
			if err := dec.Decode(&cfg); err != nil {
				return "", fmt.Errorf("no se puede leer %s como JSON (no se modifica): %w", cfgPath, err)
			}
			if cfg == nil {
				return "", fmt.Errorf("%s no contiene un objeto JSON (no se modifica)", cfgPath)
			}
		}
		backupPath = fmt.Sprintf("%s.bak-malik-%s", cfgPath, time.Now().Format("20060102-150405"))
		if err := os.WriteFile(backupPath, raw, 0600); err != nil {
			return "", fmt.Errorf("no se pudo crear la copia de seguridad %s: %w", backupPath, err)
		}
	case os.IsNotExist(err):
		if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
			return "", err
		}
	default:
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
	servers[name] = map[string]any{
		"command": command,
		"args":    args,
	}
	cfg["mcpServers"] = servers

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	out = append(out, '\n')

	tmp := cfgPath + ".tmp-malik"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, cfgPath); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return backupPath, nil
}
