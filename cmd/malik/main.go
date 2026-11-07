package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/malikssm/malik/internal/agentcfg"
	"github.com/malikssm/malik/internal/client"
	"github.com/malikssm/malik/internal/injector"
	"github.com/malikssm/malik/internal/mcp"
	"github.com/malikssm/malik/internal/remote"
	"github.com/malikssm/malik/internal/security"
	"github.com/malikssm/malik/internal/vault"
	"golang.org/x/term"
)

type sliceFlag []string

func (s *sliceFlag) String() string { return strings.Join(*s, ",") }
func (s *sliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	sub := strings.ToLower(os.Args[1])
	args := os.Args[2:]

	switch sub {
	case "mcp":
		runMCP(args)
	case "login":
		runLogin(args)
	case "logout":
		runLogout()
	case "status":
		runStatus(args)
	case "ls", "list":
		runList(args)
	case "search", "find":
		runSearch(args)
	case "get":
		runGet(args)
	case "set", "put":
		runSet(args)
	case "rm", "del", "delete":
		runDelete(args)
	case "totp", "2fa", "otp":
		runTOTP(args)
	case "run", "exec":
		runExec(args)
	case "ssh", "remote":
		runSSH(args)
	case "token", "tokens":
		runToken(args)
	case "audit", "logs":
		runAudit(args)
	case "lock":
		runLock(args)
	case "unlock":
		runUnlock(args)
	case "session-token":
		runSessionToken()
	case "init-agents":
		runInitAgents(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q.\n\n", sub)
		printUsage()
		os.Exit(1)
	}
}

func runMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	srv := fs.String("server", "", "Optional MalikSSM server URL override")
	tok := fs.String("token", "", "Optional MalikSSM token override")
	caller := fs.String("caller", "mcp-agent", "Agent identifier for audit logs (e.g. claude, antigravity)")
	noReveal := fs.Bool("no-reveal", false, "Never return secret values through secrets_get (agents must use secrets_exec)")
	_ = fs.Parse(args)

	mcpSrv := mcp.NewServer(*srv, *tok, *caller)
	mcpSrv.NoReveal = *noReveal
	if err := mcpSrv.ServeStdio(); err != nil {
		fmt.Fprintf(os.Stderr, "MCP stdio error: %v\n", err)
		os.Exit(1)
	}
}

func runLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	srv := fs.String("server", "", "MalikSSM server URL (e.g. http://192.168.1.50:8443)")
	pass := fs.String("pass", "", "Master passphrase (if omitted, prompts interactively)")
	hours := fs.Int("hours", 12, "Session validity in hours")
	days := fs.Int("days", 0, "Session validity in days (e.g. --days 30 for trusted PC)")
	_ = fs.Parse(args)

	passphrase := *pass
	if passphrase == "" {
		passphrase = readPassphrase("Introduce tu Contraseña Maestra (MalikSSM): ")
	} else {
		warnPassFlag()
	}
	if passphrase == "" {
		fatal("Passphrase cannot be empty")
	}

	api := client.New(*srv, "", "malik-cli")
	sess, err := api.Login(passphrase, *hours, *days)
	if err != nil {
		fatal("Login failed: %v", err)
	}

	fmt.Printf("✔ Sesión iniciada y sellada localmente (%s)\n", security.HardwareProviderName())
	fmt.Printf("  Servidor   : %s\n", sess.ServerURL)
	fmt.Printf("  Ordenador  : %s (ID: %s)\n", sess.ClientHost, sess.SessionID)
	fmt.Printf("  Válida hasta: %s (%s)\n", sess.ExpiresAt.Local().Format("2006-01-02 15:04:05"), time.Until(sess.ExpiresAt).Round(time.Minute))
	fmt.Printf("  Cofre Local: %s\n", client.SessionFilePath())
	fmt.Println("  -> Claude, Antigravity y tus scripts en este PC ya están autenticados automáticamente.")
}

func runLogout() {
	if err := client.ClearLocalSession(); err != nil {
		fatal("Failed to clear local session: %v", err)
	}
	fmt.Println("✔ Sesión local eliminada de este ordenador.")
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	_ = fs.Parse(args)

	api := client.New(*srv, "", "malik-cli")
	st, err := api.Status()
	if err != nil {
		fatal("Error connecting to %s: %v", api.ServerURL, err)
	}

	localSess, _ := client.LoadLocalSession()
	raw, _ := json.MarshalIndent(map[string]any{
		"server_url":          api.ServerURL,
		"vault_status":        st,
		"local_dpapi_session": localSess != nil && time.Now().Before(localSess.ExpiresAt),
	}, "", "  ")
	fmt.Println(string(raw))
}

func runList(args []string) {
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	tok := fs.String("token", "", "Token override")
	jsonOut := fs.Bool("json", false, "Output raw JSON")
	_ = fs.Parse(args)

	prefix := ""
	if fs.NArg() > 0 {
		prefix = fs.Arg(0)
	}
	api := client.New(*srv, *tok, "malik-cli")
	items, err := api.ListSecrets(prefix)
	if err != nil {
		fatal("%v", err)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(string(out))
		return
	}
	if len(items) == 0 {
		fmt.Println("(No hay secretos almacenados)")
		return
	}
	for _, it := range items {
		fmt.Printf("%-32s  [v%d %-6s]  campos:%v  tags:%v  %s\n",
			it.Path, it.CurrentVersion, it.Type, it.SchemaKeys, it.Tags, it.Description)
	}
}

func runSearch(args []string) {
	fs := flag.NewFlagSet("search", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	tok := fs.String("token", "", "Token override")
	tags := fs.String("tags", "", "Comma-separated tags")
	jsonOut := fs.Bool("json", false, "Output JSON")
	_ = fs.Parse(reorderFlagsFirst(args))

	query := strings.Join(fs.Args(), " ")
	var tagList []string
	if *tags != "" {
		tagList = strings.Split(*tags, ",")
	}
	api := client.New(*srv, *tok, "malik-cli")
	hits, err := api.SearchSecrets(query, tagList)
	if err != nil {
		fatal("%v", err)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(hits, "", "  ")
		fmt.Println(string(out))
		return
	}
	if len(hits) == 0 {
		fmt.Printf("Sin coincidencias para %q\n", query)
		return
	}
	for _, h := range hits {
		fmt.Printf("[Score %3d] %-30s  campos:%v  tags:%v  — %s\n",
			h.Score, h.Path, h.SchemaKeys, h.Tags, h.Description)
	}
}

func runGet(args []string) {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	tok := fs.String("token", "", "Token override")
	field := fs.String("field", "", "Extract a specific key from a KV secret")
	ver := fs.Int("version", 0, "Specific version number")
	stage := fs.String("stage", "", "AWSCURRENT or AWSPREVIOUS")
	raw := fs.Bool("raw", false, "Print raw string value without JSON formatting")
	_ = fs.Parse(reorderFlagsFirst(args))

	if fs.NArg() == 0 {
		fatal("Usage: malik get <path> [--field key] [--raw]")
	}
	secPath := fs.Arg(0)
	api := client.New(*srv, *tok, "malik-cli")
	sec, err := api.GetSecret(secPath, *ver, *stage)
	if err != nil {
		fatal("%v", err)
	}

	if *field != "" {
		val, ok := sec.Data[*field]
		if !ok {
			fatal("Field %q not found in %q (available: %v)", *field, sec.Path, sec.SchemaKeys)
		}
		fmt.Println(val)
		return
	}
	if *raw {
		fmt.Println(sec.Value)
		return
	}
	out, _ := json.MarshalIndent(sec, "", "  ")
	fmt.Println(string(out))
}

func runSet(args []string) {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	tok := fs.String("token", "", "Token override")
	secType := fs.String("type", "", "Secret type: kv, string, env, totp, ssh_key")
	desc := fs.String("desc", "", "Semantic description for AI agents")
	tags := fs.String("tags", "", "Comma-separated tags")
	val := fs.String("value", "", "Plain string secret value")
	blind := fs.Bool("blind", false, "Blind-only (default for new secrets): agents use it via remote_exec/secrets_exec but secrets_get never returns its values; --blind=false makes it readable")
	merge := fs.Bool("merge", false, "Keep the current fields and only add/replace the ones given")
	_ = fs.Parse(reorderFlagsFirst(args))

	var blindOnly *bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "blind" {
			blindOnly = blind
		}
	})

	if fs.NArg() == 0 {
		fatal("Usage: malik set <path> [key=val | key=? | key=@file ...] [--merge] [--blind] [--value str] [--desc \"...\"] [--tags \"a,b\"]")
	}
	secPath := fs.Arg(0)
	data, value, err := parseSetArgs(fs.Args()[1:], *val, readPassphrase, os.ReadFile)
	if err != nil {
		fatal("%v", err)
	}

	var tagList []string
	if *tags != "" {
		tagList = strings.Split(*tags, ",")
	}

	api := client.New(*srv, *tok, "malik-cli")
	if *merge {
		current, err := api.GetSecret(secPath, 0, "")
		if err != nil {
			fatal("--merge: no se pudo leer %q: %v", secPath, err)
		}
		merged := make(map[string]string, len(current.Data)+len(data))
		for k, v := range current.Data {
			merged[k] = v
		}
		for k, v := range data {
			merged[k] = v
		}
		data = merged
	}
	if len(data) == 0 && value == "" {
		fatal("Nada que guardar en %q: indica campos (clave=valor, clave=? o clave=@fichero) o --value. Un secreto vacío sobrescribiría la versión actual.", secPath)
	}
	meta, err := api.PutSecret(vault.PutSecretInput{
		Path:        secPath,
		Type:        *secType,
		Description: *desc,
		Tags:        tagList,
		Value:       value,
		Data:        data,
		BlindOnly:   blindOnly,
	})
	if err != nil {
		fatal("%v", err)
	}
	out, _ := json.MarshalIndent(meta, "", "  ")
	fmt.Println(string(out))
}

func runDelete(args []string) {
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	tok := fs.String("token", "", "Token override")
	_ = fs.Parse(reorderFlagsFirst(args))

	if fs.NArg() == 0 {
		fatal("Usage: malik rm <path>")
	}
	api := client.New(*srv, *tok, "malik-cli")
	if err := api.DeleteSecret(fs.Arg(0)); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("✔ Secreto %q eliminado.\n", fs.Arg(0))
}

func runTOTP(args []string) {
	fs := flag.NewFlagSet("totp", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	tok := fs.String("token", "", "Token override")
	raw := fs.Bool("raw", false, "Print only the 6-digit code")
	_ = fs.Parse(reorderFlagsFirst(args))

	if fs.NArg() == 0 {
		fatal("Usage: malik totp <path> [--raw]")
	}
	api := client.New(*srv, *tok, "malik-cli")
	res, err := api.GetTOTP(fs.Arg(0))
	if err != nil {
		fatal("%v", err)
	}
	if *raw {
		fmt.Println(res.Code)
		return
	}
	fmt.Printf("Código 2FA TOTP: %s (válido por %ds)\n", res.Code, res.SecondsRemaining)
}

func runExec(args []string) {
	var secrets sliceFlag
	var srv, tok string
	var cmdArgs []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			cmdArgs = args[i+1:]
			break
		}
		if (a == "-s" || a == "--secret") && i+1 < len(args) {
			secrets = append(secrets, args[i+1])
			i++
			continue
		}
		if a == "--server" && i+1 < len(args) {
			srv = args[i+1]
			i++
			continue
		}
		if a == "--token" && i+1 < len(args) {
			tok = args[i+1]
			i++
			continue
		}
		cmdArgs = args[i:]
		break
	}

	if len(cmdArgs) == 0 {
		fatal("Usage: malik run -s <secret-path> [-s <secret-path2>] -- <command> [args...]")
	}

	api := client.New(srv, tok, "malik-run")
	res, err := injector.RunWithSecrets(context.Background(), api, secrets, cmdArgs, true)
	if err != nil {
		fatal("%v", err)
	}
	os.Exit(res.ExitCode)
}

// runSSH runs a command on a machine stored in the vault (like `aws ssm send-command`): the
// credentials are resolved and used inside this process and never printed.
func runSSH(args []string) {
	fs := flag.NewFlagSet("ssh", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	tok := fs.String("token", "", "Token override")
	timeout := fs.Int("timeout", 60, "Timeout in seconds")
	stdinFile := fs.String("stdin-file", "", "File sent to the remote command's stdin")
	scriptFile := fs.String("script", "", "Multi-line script file to run instead of a command (.ps1 -> PowerShell -EncodedCommand, otherwise bash -s)")
	interpreter := fs.String("interpreter", "", "Interpreter for --script: powershell, pwsh, bash, sh, zsh (default: by file extension)")
	jsonOut := fs.Bool("json", false, "Print the full result as JSON")

	before, cmdParts := args, []string(nil)
	for i, a := range args {
		if a == "--" {
			before, cmdParts = args[:i], args[i+1:]
			break
		}
	}
	_ = fs.Parse(reorderFlagsFirst(before))
	if fs.NArg() == 0 {
		fatal("Uso: malik ssh <equipo|ruta> [--timeout 60] [--script fichero] [--stdin-file f] -- <comando>")
	}
	target := fs.Arg(0)
	if cmdParts == nil {
		cmdParts = fs.Args()[1:]
	}
	command := strings.Join(cmdParts, " ")
	stdin := ""
	if *scriptFile != "" {
		raw, err := os.ReadFile(*scriptFile)
		if err != nil {
			fatal("No se pudo leer %s: %v", *scriptFile, err)
		}
		interp := *interpreter
		if interp == "" {
			interp = remote.InterpreterForFile(*scriptFile)
		}
		if command, stdin, err = remote.BuildScriptCommand(interp, string(raw)); err != nil {
			fatal("%v", err)
		}
	}
	if strings.TrimSpace(command) == "" {
		fatal("Falta el comando: malik ssh %s -- <comando>  (o --script fichero)", target)
	}
	if *stdinFile != "" {
		raw, err := os.ReadFile(*stdinFile)
		if err != nil {
			fatal("No se pudo leer %s: %v", *stdinFile, err)
		}
		stdin = string(raw)
	}

	api := client.New(*srv, *tok, "malik-ssh")
	t, err := remote.Resolve(api, target)
	if err != nil {
		fatal("%v", err)
	}
	res, err := remote.Run(context.Background(), t, remote.Options{
		Command:         command,
		Stdin:           stdin,
		Timeout:         time.Duration(*timeout) * time.Second,
		KnownHostsFiles: remote.DefaultKnownHostsFiles(),
		TOFUFile:        filepath.Join(client.ConfigDir(), "known_hosts"),
	})
	if err != nil {
		fatal("%v", err)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Print(res.Stdout)
		fmt.Fprint(os.Stderr, res.Stderr)
	}
	os.Exit(res.ExitCode)
}

func runToken(args []string) {
	if len(args) == 0 {
		fatal("Usage: malik token [create|ls|revoke]")
	}
	action := args[0]
	rest := args[1:]

	switch action {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ExitOnError)
		srv := fs.String("server", "", "Server URL override")
		name := fs.String("name", "", "Application/bot name")
		allow := fs.String("allow", "*", "Comma-separated allowed path scopes (e.g. apis/openai/*,db/*)")
		perms := fs.String("perms", "read,search,totp", "Comma-separated permissions")
		days := fs.Int("days", 0, "Optional expiration in days (0 = never expires)")
		_ = fs.Parse(reorderFlagsFirst(rest))

		if *name == "" && fs.NArg() > 0 {
			*name = fs.Arg(0)
		}
		if *name == "" {
			fatal("Usage: malik token create --name <app-name> [--allow \"apis/*\"]")
		}
		api := client.New(*srv, "", "malik-cli")
		rawTok, meta, err := api.CreateAppToken(*name, strings.Split(*allow, ","), strings.Split(*perms, ","), *days)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Println("✔ App Token Creado (Guárdalo, no se volverá a mostrar en texto plano):")
		fmt.Printf("  TOKEN  : %s\n", rawTok)
		fmt.Printf("  ID     : %s\n", meta.ID)
		fmt.Printf("  Nombre : %s\n", meta.Name)
		fmt.Printf("  Scopes : %v\n", meta.AllowedScopes)
		fmt.Printf("  Perms  : %v\n", meta.Permissions)

	case "ls", "list":
		api := client.New("", "", "malik-cli")
		list, err := api.ListAppTokens()
		if err != nil {
			fatal("%v", err)
		}
		out, _ := json.MarshalIndent(list, "", "  ")
		fmt.Println(string(out))

	case "revoke", "rm":
		if len(rest) == 0 {
			fatal("Usage: malik token revoke <id>")
		}
		api := client.New("", "", "malik-cli")
		if err := api.RevokeAppToken(rest[0]); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("✔ Token %s revocado.\n", rest[0])
	}
}

func runAudit(args []string) {
	limit := 30
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			limit = n
		}
	}
	api := client.New("", "", "malik-cli")
	entries, err := api.ListAudit(limit)
	if err != nil {
		fatal("%v", err)
	}
	for _, e := range entries {
		fmt.Printf("%s | %-14s | %-13s | %-28s | %-6s | %s\n",
			e.Timestamp.Local().Format("15:04:05"), e.Agent, e.Action, e.Path, e.Status, e.Detail)
	}
}

func runLock(args []string) {
	fs := flag.NewFlagSet("lock", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	keep := fs.Bool("keep-sessions", false, "Do not revoke active sessions")
	_ = fs.Parse(args)

	api := client.New(*srv, "", "malik-cli")
	if _, err := api.Lock(!*keep); err != nil {
		fatal("%v", err)
	}
	fmt.Println("🔒 Bóveda bloqueada en la Windows Server (Master Key borrada de la RAM).")
}

func runUnlock(args []string) {
	fs := flag.NewFlagSet("unlock", flag.ExitOnError)
	srv := fs.String("server", "", "Server URL override")
	pass := fs.String("pass", "", "Master passphrase")
	_ = fs.Parse(args)

	passphrase := *pass
	if passphrase == "" {
		passphrase = readPassphrase("Introduce tu Contraseña Maestra para desbloquear el Servidor Central: ")
	} else {
		warnPassFlag()
	}
	api := client.New(*srv, "", "malik-cli")
	if _, err := api.Unlock(passphrase, true); err != nil {
		fatal("%v", err)
	}
	fmt.Println("🔓 Bóveda desbloqueada en RAM con protección VirtualLock.")
}

func runSessionToken() {
	_, tok := client.ResolveConnection("", "")
	if tok == "" {
		os.Exit(1)
	}
	fmt.Print(tok)
}

func runInitAgents(args []string) {
	fs := flag.NewFlagSet("init-agents", flag.ExitOnError)
	desktopCfg := fs.String("claude-desktop-config", "", "Ruta de claude_desktop_config.json (por defecto la del sistema operativo)")
	skipDesktop := fs.Bool("skip-claude-desktop", false, "No registrar el MCP en Claude Desktop")
	skipCode := fs.Bool("skip-claude-code", false, "No registrar el MCP en Claude Code (claude mcp add)")
	skipAntigravity := fs.Bool("skip-antigravity", false, "No registrar el MCP en Google Antigravity (~/.gemini/config/mcp_config.json)")
	permsYes := fs.Bool("claude-permissions", false, "Añadir sin preguntar los permisos acotados de MalikSSM a ~/.claude/settings.json")
	permsNo := fs.Bool("no-claude-permissions", false, "No tocar los permisos de Claude Code")
	_ = fs.Parse(args)

	exePath, err := os.Executable()
	if err != nil {
		fatal("Cannot determine executable path: %v", err)
	}
	exePath, _ = filepath.Abs(exePath)

	fmt.Println("✔ Configurando agentes para MalikSSM")
	fmt.Printf("  Binario MCP   : %s mcp\n", exePath)

	// 1. Regla para los agentes en ~/.claude/CLAUDE.md (bloque gestionado, se actualiza en cada ejecución)
	home, _ := os.UserHomeDir()
	claudeMD := filepath.Join(home, ".claude", "CLAUDE.md")
	if changed, err := agentcfg.UpsertRuleBlock(claudeMD); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ No se pudo actualizar %s: %v\n", claudeMD, err)
	} else if changed {
		fmt.Printf("  Regla agentes : %s (actualizada)\n", claudeMD)
	} else {
		fmt.Printf("  Regla agentes : %s (ya al día)\n", claudeMD)
	}

	// 2. MCP en Claude Desktop
	if !*skipDesktop {
		cfgPath := *desktopCfg
		if cfgPath == "" {
			cfgPath = agentcfg.ClaudeDesktopConfigPath()
		}
		backup, err := agentcfg.RegisterMCPServer(cfgPath, "malik", exePath, []string{"mcp", "--caller", "claude-desktop"})
		if err != nil {
			fatal("No se registró el MCP en Claude Desktop: %v", err)
		}
		fmt.Printf("  Claude Desktop: %s (resto de servidores MCP conservados)\n", cfgPath)
		if backup != "" {
			fmt.Printf("  Copia previa  : %s\n", backup)
		}
	}

	// 2b. MCP en Google Antigravity (si está instalado para este usuario)
	if !*skipAntigravity {
		if agPath, present := agentcfg.AntigravityConfigPath(); present {
			backup, err := agentcfg.RegisterMCPServer(agPath, "malik", exePath, []string{"mcp", "--caller", "antigravity"})
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ No se registró el MCP en Antigravity: %v\n", err)
			} else {
				fmt.Printf("  Antigravity   : %s (resto de servidores MCP conservados)\n", agPath)
				if backup != "" {
					fmt.Printf("  Copia previa  : %s\n", backup)
				}
			}
			// Reglas globales de Antigravity (y Gemini CLI): ~/.gemini/GEMINI.md
			geminiMD := filepath.Join(filepath.Dir(filepath.Dir(agPath)), "GEMINI.md")
			if changed, err := agentcfg.UpsertRuleBlock(geminiMD); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ No se pudo actualizar %s: %v\n", geminiMD, err)
			} else if changed {
				fmt.Printf("  Regla Gemini  : %s (actualizada)\n", geminiMD)
			}
		}
	}

	// 3. MCP en Claude Code
	if !*skipCode {
		registerClaudeCodeMCP(exePath)
	}

	// 4. Permisos acotados (como autorizar `aws` una vez): solo descubrir, estado y las herramientas
	//    que usan credenciales sin devolverlas. Nunca "omitir permisos".
	settings := agentcfg.ClaudeCodeSettingsPath()
	apply := *permsYes
	if !apply && !*permsNo && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println("\n  Permisos recomendados para que los agentes usen MalikSSM sin preguntarte cada vez:")
		for _, r := range agentcfg.AgentAllowRules {
			fmt.Printf("    + %s\n", r)
		}
		fmt.Println("    (secrets_get, malik get y secrets_totp seguirán pidiendo confirmación)")
		fmt.Printf("  ¿Añadirlos a %s? [s/N]: ", settings)
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		apply = strings.HasPrefix(answer, "s") || strings.HasPrefix(answer, "y")
	}
	if apply {
		added, backup, err := agentcfg.AddAllowRules(settings, agentcfg.AgentAllowRules)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "  ⚠ No se pudieron añadir los permisos: %v\n", err)
		case len(added) == 0:
			fmt.Printf("  Permisos      : %s (ya estaban)\n", settings)
		default:
			fmt.Printf("  Permisos      : %d reglas añadidas a %s\n", len(added), settings)
			if backup != "" {
				fmt.Printf("  Copia previa  : %s\n", backup)
			}
		}
	} else if !*permsNo {
		fmt.Println("  Permisos      : sin cambios (usa --claude-permissions para añadirlos)")
	}
}

// registerClaudeCodeMCP runs `claude mcp add --scope user malik ...` when the Claude Code CLI is installed.
func registerClaudeCodeMCP(exePath string) {
	claudeBin, err := exec.LookPath("claude")
	if err != nil {
		fmt.Printf("  Claude Code   : no encontrado; regístralo con: claude mcp add --scope user malik -- \"%s\" mcp --caller claude-code\n", exePath)
		return
	}
	out, err := exec.Command(claudeBin, "mcp", "add", "--scope", "user", "malik", "--", exePath, "mcp", "--caller", "claude-code").CombinedOutput()
	switch {
	case err == nil:
		fmt.Println("  Claude Code   : MCP 'malik' registrado (scope user)")
	case strings.Contains(strings.ToLower(string(out)), "already exists"):
		fmt.Println("  Claude Code   : MCP 'malik' ya estaba registrado")
	default:
		fmt.Printf("  Claude Code   : ⚠ claude mcp add falló: %s\n", strings.TrimSpace(string(out)))
	}
}

// reorderFlagsFirst moves --flag arguments before positional arguments so Go's flag package parses them in any order.
func reorderFlagsFirst(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && !isBoolFlag(a) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}

// parseSetArgs turns `malik set` positional arguments into KV data and/or a plain value.
// A value of "?" is prompted for without echo (so it never lands in the shell history), "@path"
// reads the value from a file (JSON keys, PEM files...) and "@@text" is a literal starting with "@".
func parseSetArgs(args []string, plainValue string, prompt func(string) string, readFile func(string) ([]byte, error)) (map[string]string, string, error) {
	resolve := func(name, v string) (string, error) {
		switch {
		case v == "?":
			got := prompt(fmt.Sprintf("Valor para %s (no se mostrará): ", name))
			if got == "" {
				return "", fmt.Errorf("valor vacío para %s", name)
			}
			return got, nil
		case strings.HasPrefix(v, "@@"):
			return v[1:], nil
		case strings.HasPrefix(v, "@") && len(v) > 1:
			raw, err := readFile(v[1:])
			if err != nil {
				return "", fmt.Errorf("no se pudo leer %s para %s: %w", v[1:], name, err)
			}
			return strings.TrimRight(string(raw), "\r\n"), nil
		}
		return v, nil
	}

	data := make(map[string]string)
	for _, kv := range args {
		eq := strings.Index(kv, "=")
		if eq <= 0 {
			if plainValue == "" {
				plainValue = kv
			}
			continue
		}
		v, err := resolve(kv[:eq], kv[eq+1:])
		if err != nil {
			return nil, "", err
		}
		data[kv[:eq]] = v
	}
	if plainValue != "" {
		v, err := resolve("value", plainValue)
		if err != nil {
			return nil, "", err
		}
		plainValue = v
	}
	return data, plainValue, nil
}

// readPassphrase prompts without echoing the input when stdin is a terminal, and falls back to a
// plain line read when it is piped (scripts, CI).
func readPassphrase(prompt string) string {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) && capsLockOn() {
		fmt.Fprintln(os.Stderr, "⚠ Bloq Mayús está activado.")
	}
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(fd) {
		raw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal("No se pudo leer la contraseña: %v", err)
		}
		return strings.TrimSpace(string(raw))
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

func warnPassFlag() {
	fmt.Fprintln(os.Stderr, "⚠ --pass deja la contraseña maestra en el historial del shell y en la lista de procesos; omítelo para que se pida sin eco.")
}

func isBoolFlag(a string) bool {
	switch strings.TrimLeft(a, "-") {
	case "raw", "json", "keep-sessions", "blind", "merge":
		return true
	}
	return false
}

func printUsage() {
	fmt.Println(`MalikSSM (malik) — Cliente Universal, Inyector y Servidor MCP (Go Native)

USO DIARIO:
  malik login [--server http://win-server:8443] [--days 30]   Inicia sesión (se sella con Windows DPAPI)
  malik status                                              Estado de la bóveda y de tu sesión local
  malik ls [prefijo]                                        Lista secretos disponibles
  malik search <consulta>                                   Búsqueda semántica por ruta, tags o campos
  malik get <ruta> [--field clave] [--raw]                  Obtiene y desencripta un secreto
  malik set <ruta> [k=v | k=? | k=@fichero ...] [--merge] [--blind] [--desc "..."] [--tags "a,b"]
                                                            Crea o rota un secreto (k=? lo pide sin eco)
  malik totp <ruta> [--raw]                                 Genera el código 2FA TOTP de 6 dígitos
  malik run -s <ruta> -- <comando> [args...]                Inyecta secretos en RAM y censura logs
  malik ssh <equipo> [--script f.ps1|f.sh] -- <comando>     Ejecuta en un equipo de la bóveda sin ver sus credenciales

AGENTES Y ADMINISTRACIÓN:
  malik mcp [--caller claude|antigravity]                   Arranca el servidor MCP nativo por stdio
  malik init-agents [--claude-permissions]                  MCP en Claude Desktop/Code, regla para agentes y permisos acotados
  malik token create --name <app> [--allow "ruta/*"]        Crea un App Token para bots 24/7 o ChatGPT
  malik audit [limite]                                      Muestra el historial de accesos de agentes
  malik lock / malik unlock                                 Bloqueo de pánico / Desbloqueo de la bóveda`)
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "✖ "+format+"\n", a...)
	os.Exit(1)
}
