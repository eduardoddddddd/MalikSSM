package mcp

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/malikssm/malik/internal/client"
	"github.com/malikssm/malik/internal/server"
	"github.com/malikssm/malik/internal/vault"
)

func TestSecretsGetMasksBlindOnlySecrets(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("MALIK_CONFIG_DIR", tmpDir)
	store, err := vault.OpenStore(filepath.Join(tmpDir, "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.AllowAutoUnseal = false
	ts := httptest.NewServer(server.New(store))
	defer ts.Close()

	sess, err := client.New(ts.URL, "", "test").Login("Mcp-Test-Pass-2026!", 1, 0)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	api := client.New(ts.URL, sess.Token, "test")
	blind, notBlind := true, false
	if _, err := api.PutSecret(vault.PutSecretInput{
		Path:      "servidores/web01/ssh",
		Data:      map[string]string{"host": "10.0.0.21", "username": "edu", "password": "TopSecret-123"},
		BlindOnly: &blind,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.PutSecret(vault.PutSecretInput{Path: "apis/demo", Value: "Visible-Value-456", BlindOnly: &notBlind}); err != nil {
		t.Fatal(err)
	}

	mcpSrv := NewServer(ts.URL, sess.Token, "claude")

	out, isErr := mcpSrv.executeTool("secrets_get", map[string]any{"path": "servidores/web01/ssh"})
	if isErr || strings.Contains(out, "TopSecret-123") || !strings.Contains(out, "10.0.0.21") {
		t.Fatalf("blind secret: password must be masked and host visible, got isErr=%v\n%s", isErr, out)
	}
	out, isErr = mcpSrv.executeTool("secrets_get", map[string]any{"path": "servidores/web01/ssh", "field": "password"})
	if !isErr || strings.Contains(out, "TopSecret-123") || !strings.Contains(out, "secrets_exec") {
		t.Fatalf("blind field request must be refused with a secrets_exec hint, got isErr=%v\n%s", isErr, out)
	}
	out, isErr = mcpSrv.executeTool("secrets_get", map[string]any{"path": "servidores/web01/ssh", "field": "host"})
	if isErr || !strings.Contains(out, "10.0.0.21") {
		t.Fatalf("public field of a blind secret should be readable, got isErr=%v\n%s", isErr, out)
	}

	out, _ = mcpSrv.executeTool("secrets_get", map[string]any{"path": "apis/demo"})
	if !strings.Contains(out, "Visible-Value-456") {
		t.Fatalf("non-blind secret should be returned by default, got\n%s", out)
	}
	mcpSrv.NoReveal = true
	out, _ = mcpSrv.executeTool("secrets_get", map[string]any{"path": "apis/demo"})
	if strings.Contains(out, "Visible-Value-456") {
		t.Fatalf("--no-reveal must mask every secret, got\n%s", out)
	}
}
