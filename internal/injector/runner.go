package injector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/malikssm/malik/internal/client"
)

// ExecResult holds the redacted output and exit status of a subprocess execution.
type ExecResult struct {
	ExitCode     int      `json:"exit_code"`
	Stdout       string   `json:"stdout"`
	Stderr       string   `json:"stderr"`
	InjectedVars []string `json:"injected_vars"`
	DurationMs   int64    `json:"duration_ms"`
}

// RunWithSecrets fetches all requested secrets from MalikSSM, injects them as environment variables
// (and resolves any {{SECRET:path#field}} placeholders in args), runs the command, and redacts
// any secret values from stdout/stderr.
func RunWithSecrets(ctx context.Context, api *client.Client, secretPaths []string, command []string, streamToConsole bool) (*ExecResult, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("no command specified to execute")
	}

	envMap := make(map[string]string)
	var sensitiveValues []string
	var injectedKeys []string

	// 1. Load requested secrets
	for _, sp := range secretPaths {
		sec, err := api.GetSecret(sp, 0, "")
		if err != nil {
			return nil, fmt.Errorf("failed to load secret %q: %w", sp, err)
		}
		baseName := sanitizeEnvKey(path.Base(sec.Path))

		if len(sec.Data) > 0 {
			for k, v := range sec.Data {
				if v == "" {
					continue
				}
				if isSensitiveFieldName(k) {
					sensitiveValues = append(sensitiveValues, v)
				}
				cleanKey := sanitizeEnvKey(k)
				if cleanKey == "VALUE" && len(sec.Data) == 1 {
					envMap[baseName] = v
					injectedKeys = append(injectedKeys, baseName)
				} else {
					envMap[cleanKey] = v
					injectedKeys = append(injectedKeys, cleanKey)
					prefixed := baseName + "_" + cleanKey
					if _, exists := envMap[prefixed]; !exists {
						envMap[prefixed] = v
						injectedKeys = append(injectedKeys, prefixed)
					}
				}
			}
		} else if sec.Value != "" {
			sensitiveValues = append(sensitiveValues, sec.Value)
			envMap[baseName] = sec.Value
			injectedKeys = append(injectedKeys, baseName)
		}
	}

	// 2. Resolve inline {{SECRET:path#field}} placeholders in command arguments
	resolvedCmd := make([]string, len(command))
	for i, arg := range command {
		resolved, vals, err := resolveInlinePlaceholders(api, arg)
		if err != nil {
			return nil, err
		}
		resolvedCmd[i] = resolved
		sensitiveValues = append(sensitiveValues, vals...)
	}

	// 3. Build child environment
	childEnv := os.Environ()
	for k, v := range envMap {
		childEnv = append(childEnv, k+"="+v)
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, resolvedCmd[0], resolvedCmd[1:]...)
	cmd.Env = childEnv

	var outBuf, errBuf bytes.Buffer
	redactor := func(text string) string {
		for _, sv := range sensitiveValues {
			if len(sv) >= 4 {
				text = strings.ReplaceAll(text, sv, "***REDACTED***")
			}
		}
		return text
	}

	if streamToConsole {
		cmd.Stdin = os.Stdin
		cmd.Stdout = &redactingWriter{dest: os.Stdout, buf: &outBuf, redact: redactor}
		cmd.Stderr = &redactingWriter{dest: os.Stderr, buf: &errBuf, redact: redactor}
	} else {
		cmd.Stdout = &redactingWriter{dest: nil, buf: &outBuf, redact: redactor}
		cmd.Stderr = &redactingWriter{dest: nil, buf: &errBuf, redact: redactor}
	}

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}

	return &ExecResult{
		ExitCode:     exitCode,
		Stdout:       redactor(outBuf.String()),
		Stderr:       redactor(errBuf.String()),
		InjectedVars: injectedKeys,
		DurationMs:   time.Since(start).Milliseconds(),
	}, nil
}

type redactingWriter struct {
	dest   io.Writer
	buf    *bytes.Buffer
	redact func(string) string
}

func (rw *redactingWriter) Write(p []byte) (int, error) {
	redacted := rw.redact(string(p))
	if rw.buf != nil {
		rw.buf.WriteString(redacted)
	}
	if rw.dest != nil {
		_, _ = rw.dest.Write([]byte(redacted))
	}
	return len(p), nil
}

func resolveInlinePlaceholders(api *client.Client, input string) (string, []string, error) {
	var sensitive []string
	for {
		startIdx := strings.Index(input, "{{SECRET:")
		if startIdx == -1 {
			break
		}
		endIdx := strings.Index(input[startIdx:], "}}")
		if endIdx == -1 {
			break
		}
		endIdx += startIdx
		expr := input[startIdx+9 : endIdx]
		secPath := expr
		field := "value"
		if hashIdx := strings.Index(expr, "#"); hashIdx != -1 {
			secPath = expr[:hashIdx]
			field = expr[hashIdx+1:]
		}
		sec, err := api.GetSecret(secPath, 0, "")
		if err != nil {
			return "", nil, fmt.Errorf("failed to resolve placeholder {{SECRET:%s}}: %w", expr, err)
		}
		val := sec.Value
		if v, ok := sec.Data[field]; ok {
			val = v
		}
		sensitive = append(sensitive, val)
		input = input[:startIdx] + val + input[endIdx+2:]
	}
	return input, sensitive, nil
}

func isSensitiveFieldName(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "host", "hostname", "ip", "port", "user", "username", "region", "database", "db", "env", "environment":
		return false
	default:
		return true
	}
}

func sanitizeEnvKey(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
