package remote

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// maxEncodedCommand keeps PowerShell -EncodedCommand lines below the Windows command-line limit
// (32767 characters) with room for the interpreter and flags.
const maxEncodedCommand = 30000

const psPrelude = "$ProgressPreference = 'SilentlyContinue'\n"

// BuildScriptCommand turns a multi-line script into a command (and stdin) that runs it reliably:
//   - powershell / pwsh: passed as -EncodedCommand (UTF-16LE base64). Piping a script into
//     "powershell -Command -" is unreliable: multi-line blocks such as foreach { ... } are not run.
//   - bash / sh / zsh: sent on stdin to "<shell> -s".
func BuildScriptCommand(interpreter, script string) (command, stdin string, err error) {
	if strings.TrimSpace(script) == "" {
		return "", "", fmt.Errorf("script is empty")
	}
	switch strings.ToLower(strings.TrimSpace(interpreter)) {
	case "powershell", "pwsh":
		exe := "powershell"
		if strings.EqualFold(interpreter, "pwsh") {
			exe = "pwsh"
		}
		// Without a console, progress records are serialized as CLIXML on stderr: silence them.
		units := utf16.Encode([]rune(psPrelude + script))
		raw := make([]byte, len(units)*2)
		for i, u := range units {
			binary.LittleEndian.PutUint16(raw[i*2:], u)
		}
		command = exe + " -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + base64.StdEncoding.EncodeToString(raw)
		if len(command) > maxEncodedCommand {
			return "", "", fmt.Errorf("PowerShell script too large for -EncodedCommand (%d chars encoded, max %d): split it or copy it to the target first", len(command), maxEncodedCommand)
		}
		return command, "", nil
	case "bash", "sh", "zsh":
		return strings.ToLower(strings.TrimSpace(interpreter)) + " -s", script, nil
	default:
		return "", "", fmt.Errorf("unsupported interpreter %q (use powershell, pwsh, bash, sh or zsh)", interpreter)
	}
}

// InterpreterForFile guesses the interpreter from a script file name.
func InterpreterForFile(name string) string {
	switch {
	case strings.HasSuffix(strings.ToLower(name), ".ps1"):
		return "powershell"
	case strings.HasSuffix(strings.ToLower(name), ".zsh"):
		return "zsh"
	default:
		return "bash"
	}
}
