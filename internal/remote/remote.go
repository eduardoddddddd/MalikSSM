// Package remote runs commands on machines described in the vault, the way `aws ssm send-command`
// does for EC2: the caller (a person or an AI agent) names a target and a command, and the
// credentials are resolved and used inside this process. They never appear in the caller's
// command line, environment or output.
package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/malikssm/malik/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SecretGetter is the subset of the API client needed to resolve targets.
type SecretGetter interface {
	GetSecret(path string, version int, stage string) (*vault.DecryptedSecret, error)
}

// Target is a remote machine assembled from one or more vault entries.
type Target struct {
	Name         string
	Host         string
	Port         int
	Username     string
	Password     string
	IdentityFile string
	PrivateKey   string
	Sources      []string
}

// CandidatePaths lists the vault entries consulted for a short target name, most specific first:
// an SSH entry (usually key-based) and then the machine's admin account (usually a password).
func CandidatePaths(name string) []string {
	return []string{
		"servidores/" + name + "/ssh",
		"equipos/" + name + "/ssh",
		"equipos/" + name + "/admin",
	}
}

// Resolve builds a Target from the vault. A target containing "/" is a single secret path;
// otherwise every CandidatePaths entry that exists contributes the fields it has (first wins).
func Resolve(api SecretGetter, target string) (*Target, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("target is required (a machine name such as 'rogally' or a secret path)")
	}
	paths := []string{target}
	name := target
	if !strings.Contains(target, "/") {
		paths = CandidatePaths(target)
	} else {
		name = vault.NormalizePath(target)
	}

	t := &Target{Name: name}
	for _, p := range paths {
		sec, err := api.GetSecret(p, 0, "")
		if err != nil {
			continue
		}
		t.Sources = append(t.Sources, sec.Path)
		d := sec.Data
		setIfEmpty(&t.Host, first(d, "host", "hostname", "tailscale_ip", "ip", "lan_ip"))
		setIfEmpty(&t.Username, first(d, "username", "user"))
		setIfEmpty(&t.Password, first(d, "password", "pass"))
		setIfEmpty(&t.IdentityFile, first(d, "identity_file", "key_path"))
		setIfEmpty(&t.PrivateKey, first(d, "private_key", "ssh_key"))
		if t.Port == 0 {
			if port, err := strconv.Atoi(first(d, "port", "ssh_port")); err == nil && port > 0 {
				t.Port = port
			}
		}
	}
	if len(t.Sources) == 0 {
		return nil, fmt.Errorf("no vault entry found for target %q (looked for %s)", target, strings.Join(paths, ", "))
	}
	if t.Host == "" || t.Username == "" {
		return nil, fmt.Errorf("target %q needs at least 'host' and 'username' fields (found in %s)", target, strings.Join(t.Sources, ", "))
	}
	if t.Password == "" && t.IdentityFile == "" && t.PrivateKey == "" {
		return nil, fmt.Errorf("target %q has no credential: add 'password', 'identity_file' or 'private_key' (found in %s)", target, strings.Join(t.Sources, ", "))
	}
	if t.Port == 0 {
		t.Port = 22
	}
	return t, nil
}

// Options controls a remote execution.
type Options struct {
	Command string
	Stdin   string
	Timeout time.Duration
	// KnownHostsFiles are checked for the server's host key (e.g. ~/.ssh/known_hosts).
	KnownHostsFiles []string
	// TOFUFile records host keys seen for the first time; a later different key is refused.
	TOFUFile string
}

// Result is what callers (and agents) get back. It carries no credential.
type Result struct {
	Target     string   `json:"target"`
	Host       string   `json:"host"`
	Username   string   `json:"username"`
	Auth       []string `json:"auth"`
	Sources    []string `json:"sources"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	DurationMs int64    `json:"duration_ms"`
	HostKey    string   `json:"host_key,omitempty"`
}

// Run executes opts.Command on the target over SSH and returns its redacted output.
func Run(ctx context.Context, t *Target, opts Options) (*Result, error) {
	if strings.TrimSpace(opts.Command) == "" {
		return nil, errors.New("command is required")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	res := &Result{Target: t.Name, Host: t.Host, Username: t.Username, Sources: t.Sources}
	redact := redactor(t)

	var auths []ssh.AuthMethod
	if signer, err := t.signer(); err != nil {
		return nil, errors.New(redact(err.Error()))
	} else if signer != nil {
		auths = append(auths, ssh.PublicKeys(signer))
		res.Auth = append(res.Auth, "publickey")
	}
	if t.Password != "" {
		pw := t.Password
		auths = append(auths, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = pw
			}
			return answers, nil
		}))
		res.Auth = append(res.Auth, "password")
	}

	hostKeyCallback, known, err := hostKeyChecker(opts.KnownHostsFiles, opts.TOFUFile, &res.HostKey)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	cfg := &ssh.ClientConfig{
		User:            t.Username,
		Auth:            auths,
		HostKeyCallback: hostKeyCallback,
		// Like OpenSSH: when known_hosts already has keys for this host, negotiate only those key
		// types, otherwise a server that also offers e.g. ECDSA looks like a changed host key.
		HostKeyAlgorithms: knownHostKeyAlgorithms(known, addr, t.Host, t.Port),
		Timeout:           10 * time.Second,
	}

	start := time.Now()
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh to %s@%s failed: %s", t.Username, addr, redact(err.Error()))
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session on %s failed: %w", addr, err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if opts.Stdin != "" {
		session.Stdin = strings.NewReader(opts.Stdin)
	}

	done := make(chan error, 1)
	go func() { done <- session.Run(opts.Command) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = client.Close()
		return nil, fmt.Errorf("command on %s timed out after %s", addr, opts.Timeout)
	}

	res.DurationMs = time.Since(start).Milliseconds()
	res.Stdout = redact(stdout.String())
	res.Stderr = redact(stderr.String())
	var exitErr *ssh.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitStatus()
	default:
		var missing *ssh.ExitMissingError
		if !errors.As(err, &missing) {
			return nil, fmt.Errorf("command on %s failed: %s", addr, redact(err.Error()))
		}
		res.ExitCode = -1
	}
	return res, nil
}

func (t *Target) signer() (ssh.Signer, error) {
	var raw []byte
	switch {
	case t.PrivateKey != "":
		raw = []byte(t.PrivateKey)
	case t.IdentityFile != "":
		data, err := os.ReadFile(expandHome(t.IdentityFile))
		if err != nil {
			if t.Password != "" {
				return nil, nil // key not on this machine: fall back to the password
			}
			return nil, fmt.Errorf("cannot read identity_file %s: %w", t.IdentityFile, err)
		}
		raw = data
	default:
		return nil, nil
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		var passErr *ssh.PassphraseMissingError
		if errors.As(err, &passErr) && t.Password != "" {
			return nil, nil // encrypted key: rely on the password instead
		}
		return nil, fmt.Errorf("cannot parse private key for %s: %w", t.Name, err)
	}
	return signer, nil
}

// hostKeyChecker accepts keys listed in knownFiles; an unknown host is trusted on first use and
// recorded in tofuFile; a host whose key changed is always refused.
func hostKeyChecker(knownFiles []string, tofuFile string, seen *string) (ssh.HostKeyCallback, ssh.HostKeyCallback, error) {
	var existing []string
	for _, f := range append(append([]string{}, knownFiles...), tofuFile) {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); err == nil {
			existing = append(existing, f)
		}
	}
	var known ssh.HostKeyCallback
	if len(existing) > 0 {
		cb, err := knownhosts.New(existing...)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot load known_hosts: %w", err)
		}
		known = cb
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		*seen = key.Type() + " " + ssh.FingerprintSHA256(key)
		if known != nil {
			err := known(hostname, remote, key)
			if err == nil {
				return nil
			}
			var keyErr *knownhosts.KeyError
			if !errors.As(err, &keyErr) || len(keyErr.Want) > 0 {
				return fmt.Errorf("host key for %s does not match known_hosts (possible man-in-the-middle); refusing to connect: %w", hostname, err)
			}
		}
		if tofuFile == "" {
			return fmt.Errorf("unknown host key for %s and no TOFU file configured", hostname)
		}
		if err := os.MkdirAll(filepath.Dir(tofuFile), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(tofuFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = fmt.Fprintln(f, knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key))
		return err
	}, known, nil
}

// knownHostKeyAlgorithms asks the known_hosts callback which key types it holds for addr (by
// presenting a throwaway key and reading the KeyError) and returns the matching algorithms.
// nil means "no known keys": the client then offers its defaults and TOFU applies.
func knownHostKeyAlgorithms(known ssh.HostKeyCallback, addr, host string, port int) []string {
	if known == nil {
		return nil
	}
	_, probePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewSignerFromKey(probePriv)
	if err != nil {
		return nil
	}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP(host), Port: port}
	var keyErr *knownhosts.KeyError
	if err := known(addr, remoteAddr, probe.PublicKey()); !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		return nil
	}
	var algos []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			algos = append(algos, a)
		}
	}
	for _, k := range keyErr.Want {
		switch k.Key.Type() {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSASHA256)
			add(ssh.KeyAlgoRSA)
		default:
			add(k.Key.Type())
		}
	}
	return algos
}

func redactor(t *Target) func(string) string {
	var secrets []string
	for _, s := range []string{t.Password, t.PrivateKey} {
		if len(s) >= 4 {
			secrets = append(secrets, s)
		}
	}
	return func(s string) string {
		for _, v := range secrets {
			s = strings.ReplaceAll(s, v, "***REDACTED***")
		}
		return s
	}
}

func first(d map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(d[k]); v != "" {
			return v
		}
	}
	return ""
}

func setIfEmpty(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/"))
		}
	}
	return p
}

// DefaultKnownHostsFiles returns the user's OpenSSH known_hosts, so hosts already trusted by
// `ssh` are verified the same way here.
func DefaultKnownHostsFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, ".ssh", "known_hosts")}
}
