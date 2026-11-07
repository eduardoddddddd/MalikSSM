package remote

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/malikssm/malik/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type fakeVault map[string]map[string]string

func (f fakeVault) GetSecret(path string, _ int, _ string) (*vault.DecryptedSecret, error) {
	d, ok := f[path]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &vault.DecryptedSecret{SecretMetadata: vault.SecretMetadata{Path: path}, Data: d}, nil
}

// startSSHServer runs a minimal SSH server that accepts user "edu" with password "S3cret-pw" or
// the given client public key. "exec" requests print the command, the user and stdin; the command
// "fail" exits with status 3 and "leak" prints the password.
func startSSHServer(t *testing.T, clientKey ssh.PublicKey) (addr string, hostKey ssh.Signer) {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _ = ssh.NewSignerFromKey(hostPriv)

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "edu" && string(pw) == "S3cret-pw" {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if clientKey != nil && c.User() == "edu" && string(k.Marshal()) == string(clientKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	// Like Windows OpenSSH, also offer an ECDSA host key (the Go client would pick it first).
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSigner, _ := ssh.NewSignerFromKey(ecPriv)
	cfg.AddHostKey(ecSigner)
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func(nc net.Conn) {
				sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, chReqs, err := nch.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer ch.Close()
						for req := range chReqs {
							if req.Type != "exec" {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
							cmd := string(req.Payload[4 : 4+cmdLen])
							in, _ := io.ReadAll(ch)
							status := uint32(0)
							switch cmd {
							case "fail":
								status = 3
								fmt.Fprint(ch.Stderr(), "boom")
							case "leak":
								fmt.Fprint(ch, "the password is S3cret-pw")
							default:
								fmt.Fprintf(ch, "cmd=%s user=%s stdin=%s", cmd, sc.User(), in)
							}
							_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
							return
						}
					}()
				}
			}(nc)
		}
	}()
	return ln.Addr().String(), hostKey
}

func splitAddr(t *testing.T, addr string) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func TestResolveMergesKeyEntryAndAdminEntry(t *testing.T) {
	v := fakeVault{
		"servidores/web01/ssh": {"host": "100.64.0.5", "port": "2222", "username": "edu", "identity_file": `C:\keys\id`},
		"equipos/web01/admin":  {"host": "10.0.0.9", "username": "other", "password": "pw-123"},
	}
	tg, err := Resolve(v, "web01")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Host != "100.64.0.5" || tg.Port != 2222 || tg.Username != "edu" || tg.IdentityFile != `C:\keys\id` || tg.Password != "pw-123" {
		t.Fatalf("unexpected merge: %+v", tg)
	}
	if len(tg.Sources) != 2 {
		t.Fatalf("expected two sources, got %v", tg.Sources)
	}
	if _, err := Resolve(v, "missing"); err == nil {
		t.Fatalf("expected an error for an unknown target")
	}
	if _, err := Resolve(fakeVault{"equipos/x/admin": {"host": "h", "username": "u"}}, "x"); err == nil {
		t.Fatalf("expected an error for a target without credentials")
	}
}

func TestRunWithPasswordTOFUAndRedaction(t *testing.T) {
	addr, _ := startSSHServer(t, nil)
	host, port := splitAddr(t, addr)
	tofu := filepath.Join(t.TempDir(), "known_hosts")
	tg := &Target{Name: "lab", Host: host, Port: port, Username: "edu", Password: "S3cret-pw"}

	res, err := Run(context.Background(), tg, Options{Command: "hostname", Stdin: "hola", TOFUFile: tofu})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if res.ExitCode != 0 || res.Stdout != "cmd=hostname user=edu stdin=hola" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if raw, _ := os.ReadFile(tofu); !strings.Contains(string(raw), host) || !strings.Contains(string(raw), strings.Fields(res.HostKey)[0]) {
		t.Fatalf("host key %q should be recorded on first use, got %q", res.HostKey, raw)
	}

	res, err = Run(context.Background(), tg, Options{Command: "leak", TOFUFile: tofu})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout, "S3cret-pw") || !strings.Contains(res.Stdout, "***REDACTED***") {
		t.Fatalf("password must be redacted from output: %q", res.Stdout)
	}

	res, err = Run(context.Background(), tg, Options{Command: "fail", TOFUFile: tofu})
	if err != nil || res.ExitCode != 3 || res.Stderr != "boom" {
		t.Fatalf("expected exit 3 with stderr, got %+v err=%v", res, err)
	}

	bad := *tg
	bad.Password = "wrong-pw"
	if _, err := Run(context.Background(), &bad, Options{Command: "hostname", TOFUFile: tofu}); err == nil || strings.Contains(err.Error(), "wrong-pw") {
		t.Fatalf("wrong password must fail without echoing it, got %v", err)
	}
}

func TestRunWithKeyAndRejectsChangedHostKey(t *testing.T) {
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(clientPub)
	block, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}

	addr, _ := startSSHServer(t, sshPub)
	host, port := splitAddr(t, addr)
	tofu := filepath.Join(t.TempDir(), "known_hosts")
	tg := &Target{Name: "lab", Host: host, Port: port, Username: "edu", IdentityFile: keyFile}

	res, err := Run(context.Background(), tg, Options{Command: "whoami", TOFUFile: tofu, Timeout: 10 * time.Second})
	if err != nil || res.Stdout != "cmd=whoami user=edu stdin=" || res.Auth[0] != "publickey" {
		t.Fatalf("key auth failed: %+v err=%v", res, err)
	}

	// Same address, different host key (another server took the port) -> refused.
	stale := fmt.Sprintf("[%s]:%d ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n", host, port)
	known := filepath.Join(t.TempDir(), "known_hosts_user")
	if err := os.WriteFile(known, []byte(stale), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), tg, Options{Command: "whoami", KnownHostsFiles: []string{known}, TOFUFile: filepath.Join(t.TempDir(), "tofu")}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a changed host key must be refused, got %v", err)
	}
}

// The server offers ECDSA and ed25519 but known_hosts only has its ed25519 key (as when the host
// was first trusted with OpenSSH): the connection must succeed, not be flagged as a changed key.
func TestRunNegotiatesKnownHostKeyType(t *testing.T) {
	addr, hostKey := startSSHServer(t, nil)
	host, port := splitAddr(t, addr)
	known := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, hostKey.PublicKey())
	if err := os.WriteFile(known, []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tg := &Target{Name: "lab", Host: host, Port: port, Username: "edu", Password: "S3cret-pw"}
	res, err := Run(context.Background(), tg, Options{Command: "hostname", KnownHostsFiles: []string{known}, TOFUFile: filepath.Join(t.TempDir(), "tofu")})
	if err != nil {
		t.Fatalf("expected success with the known ed25519 key, got %v", err)
	}
	if !strings.HasPrefix(res.HostKey, "ssh-ed25519 ") {
		t.Fatalf("expected the ed25519 host key to be used, got %q", res.HostKey)
	}
}
