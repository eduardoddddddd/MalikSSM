package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/malikssm/malik/internal/client"
	"github.com/malikssm/malik/internal/vault"
)

func TestFullServerRESTAndAWSEmulation(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("MALIK_CONFIG_DIR", tmpDir)

	store, err := vault.OpenStore(filepath.Join(tmpDir, "server_test.db"))
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	srv := New(store)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 1. Test Morning Login (auto-initializes on first login and saves DPAPI session.bin)
	cli := client.New(ts.URL, "", "antigravity")
	sess, err := cli.Login("Master-ROG-Ally-Pass-99!", 12, 0)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if !strings.HasPrefix(sess.Token, "mlk_sess_") {
		t.Fatalf("expected mlk_sess_ token, got %s", sess.Token)
	}

	// 2. New client with NO token argument must automatically load DPAPI session.bin
	autoCli := client.New(ts.URL, "", "claude")
	if autoCli.Token != sess.Token {
		t.Fatalf("expected autoCli to load token from DPAPI session.bin")
	}

	// 3. Create secret via autoCli
	_, err = autoCli.PutSecret(vault.PutSecretInput{
		Path:        "apis/openai/prod",
		Type:        "kv",
		Description: "OpenAI API Key de producción",
		Tags:        []string{"ia", "openai", "llm"},
		Data: map[string]string{
			"api_key": "sk-proj-supersecret123456",
			"org_id":  "org-malik",
		},
	})
	if err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	// 4. Test AWS Secrets Manager Boto3 Emulation (POST / with X-Amz-Target: secretsmanager.GetSecretValue)
	awsBody := []byte(`{"SecretId":"apis/openai/prod"}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/", bytes.NewReader(awsBody))
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+sess.Token+"/20261106/local/secretsmanager/aws4_request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("AWS request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected AWS 200 OK, got %d", resp.StatusCode)
	}
	var awsResp map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&awsResp)
	if !strings.Contains(awsResp["SecretString"].(string), "sk-proj-supersecret123456") {
		t.Fatalf("unexpected AWS SecretString: %+v", awsResp)
	}

	// 5. Verify OpenAPI 3.1 endpoint for ChatGPT Actions
	oaResp, err := http.Get(ts.URL + "/openapi.json")
	if err != nil || oaResp.StatusCode != http.StatusOK {
		t.Fatalf("expected /openapi.json 200 OK, got %v", err)
	}
	_ = oaResp.Body.Close()

	// 6. Verify Embedded Web UI endpoint
	uiResp, err := http.Get(ts.URL + "/ui")
	if err != nil || uiResp.StatusCode != http.StatusOK {
		t.Fatalf("expected /ui 200 OK, got %v", err)
	}
	_ = uiResp.Body.Close()
}
