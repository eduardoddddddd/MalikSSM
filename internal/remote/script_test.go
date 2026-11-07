package remote

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestBuildScriptCommandPowerShellEncodesUTF16(t *testing.T) {
	script := "foreach ($p in @('a','ñ')) {\n  \"línea $p\"\n}\n"
	cmd, stdin, err := BuildScriptCommand("powershell", script)
	if err != nil {
		t.Fatal(err)
	}
	if stdin != "" || !strings.HasPrefix(cmd, "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ") {
		t.Fatalf("unexpected command %q / stdin %q", cmd, stdin)
	}
	raw, err := base64.StdEncoding.DecodeString(cmd[strings.LastIndex(cmd, " ")+1:])
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("payload is not UTF-16 base64: %v", err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	if got := string(utf16.Decode(units)); got != psPrelude+script {
		t.Fatalf("round trip mismatch:\n%q\n%q", got, script)
	}
}

func TestBuildScriptCommandShellsAndLimits(t *testing.T) {
	cmd, stdin, err := BuildScriptCommand("bash", "echo hola\n")
	if err != nil || cmd != "bash -s" || stdin != "echo hola\n" {
		t.Fatalf("bash: %q %q %v", cmd, stdin, err)
	}
	if _, _, err := BuildScriptCommand("cmd", "dir"); err == nil {
		t.Fatalf("expected an error for an unsupported interpreter")
	}
	if _, _, err := BuildScriptCommand("powershell", strings.Repeat("x", 20000)); err == nil {
		t.Fatalf("expected an error for an oversized PowerShell script")
	}
	if InterpreterForFile("deploy.PS1") != "powershell" || InterpreterForFile("x.sh") != "bash" {
		t.Fatalf("unexpected interpreter guess")
	}
}
