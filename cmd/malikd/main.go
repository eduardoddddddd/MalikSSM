package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/malikssm/malik/internal/server"
	"github.com/malikssm/malik/internal/vault"
)

func main() {
	defaultAddr := os.Getenv("MALIK_ADDR")
	if defaultAddr == "" {
		defaultAddr = "127.0.0.1:8443"
	}
	defaultDB := os.Getenv("MALIK_DB_PATH")
	if defaultDB == "" {
		exePath, err := os.Executable()
		if err == nil {
			defaultDB = filepath.Join(filepath.Dir(exePath), "data", "malik.db")
		} else {
			defaultDB = filepath.Join("data", "malik.db")
		}
	}

	addr := flag.String("addr", defaultAddr, "Listen address (e.g. 0.0.0.0:8443)")
	dbPath := flag.String("db", defaultDB, "Path to encrypted vault database (malik.db)")
	initPass := flag.String("init-pass", os.Getenv("MALIK_INIT_PASS"), "Optional master passphrase to initialize/unlock on startup")
	tlsCert := flag.String("tls-cert", os.Getenv("MALIK_TLS_CERT"), "Optional TLS certificate file")
	tlsKey := flag.String("tls-key", os.Getenv("MALIK_TLS_KEY"), "Optional TLS private key file")
	insecureHTTP := flag.Bool("insecure-http", envBool("MALIK_INSECURE_HTTP"), "Allow plain HTTP on a non-loopback address (only behind an encrypted network such as Tailscale/WireGuard)")
	autoUnseal := flag.Bool("auto-unseal", envBoolDefault("MALIK_AUTO_UNSEAL", runtime.GOOS == "windows"), "Keep an auto-unseal blob next to the DB. Windows: DPAPI. macOS/Linux: host-bound obfuscation only (disk access = vault access)")
	bindSessions := flag.Bool("bind-sessions-to-ip", envBoolDefault("MALIK_BIND_SESSIONS_TO_IP", true), "Reject session tokens used from an IP other than the one that logged in")
	corsOrigin := flag.String("cors-origin", os.Getenv("MALIK_CORS_ORIGIN"), "Optional single origin allowed for cross-origin browser calls (default: none)")
	flag.Parse()

	useTLS := *tlsCert != "" && *tlsKey != ""
	if !useTLS && !isLoopbackAddr(*addr) && !*insecureHTTP {
		log.Fatalf("[MalikSSM] Refusing to serve plain HTTP on %s: the master passphrase and tokens would travel unencrypted.\n"+
			"  Use --tls-cert/--tls-key, bind to 127.0.0.1 or to a Tailscale IP with --insecure-http.", *addr)
	}
	if !useTLS && !isLoopbackAddr(*addr) {
		log.Printf("[MalikSSM] WARNING: plain HTTP on %s (--insecure-http). Make sure this address is only reachable through an encrypted network.", *addr)
	}

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
		log.Fatalf("[MalikSSM] Failed to create data directory: %v", err)
	}

	store, err := vault.OpenStore(*dbPath)
	if err != nil {
		log.Fatalf("[MalikSSM] Failed to open vault database: %v", err)
	}
	defer store.Close()

	store.AllowAutoUnseal = *autoUnseal
	store.BindSessionsToIP = *bindSessions
	if *autoUnseal && runtime.GOOS != "windows" {
		log.Printf("[MalikSSM] WARNING: --auto-unseal on %s only obfuscates the master key (hostname/UID/machine-id); anyone who can read the data directory can decrypt the vault.", runtime.GOOS)
	}
	if *autoUnseal && !store.IsUnlocked() {
		_ = store.TryAutoUnseal()
	}

	if *initPass != "" {
		if !store.IsInitialized() {
			if err := store.InitVault(*initPass, true); err != nil {
				log.Fatalf("[MalikSSM] Failed to initialize vault: %v", err)
			}
			log.Printf("[MalikSSM] Vault initialized with Envelope AES-256-GCM + Windows DPAPI Auto-Unseal")
		} else if !store.IsUnlocked() {
			if err := store.Unlock(*initPass, true, "127.0.0.1"); err != nil {
				log.Fatalf("[MalikSSM] Failed to unlock vault with provided passphrase: %v", err)
			}
			log.Printf("[MalikSSM] Vault unlocked into VirtualLocked RAM")
		}
	}

	st := store.Status()
	srv := server.New(store)
	srv.CORSOrigin = *corsOrigin
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	fmt.Println("=======================================================================")
	fmt.Println("  MalikSSM Server (malikd) — Agent-First Secrets Manager (Go Native)")
	fmt.Println("=======================================================================")
	fmt.Printf("  Listen Address : %s://%s\n", scheme, *addr)
	fmt.Printf("  Web Dashboard  : %s://127.0.0.1%s/ui\n", scheme, portSuffix(*addr))
	fmt.Printf("  ChatGPT OpenAPI: %s://127.0.0.1%s/openapi.json\n", scheme, portSuffix(*addr))
	fmt.Printf("  AWS Boto3 URL  : %s://127.0.0.1%s\n", scheme, portSuffix(*addr))
	fmt.Printf("  Database Path  : %s\n", *dbPath)
	fmt.Printf("  Vault State    : Initialized=%v | Unlocked=%v | AutoUnseal=%v (%s)\n", st.Initialized, st.Unlocked, st.AutoUnsealReady, st.HardwareBacking)
	fmt.Printf("  Sessions       : bound to client IP=%v\n", *bindSessions)
	if !st.Initialized {
		fmt.Println("  First run      : initialize from THIS machine (127.0.0.1); remote init is refused.")
	}
	fmt.Println("=======================================================================")

	go func() {
		var serveErr error
		if useTLS {
			serveErr = httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatalf("[MalikSSM] HTTP server error: %v", serveErr)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("[MalikSSM] Shutting down and wiping Master Key from physical RAM...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envBool(name string) bool {
	return envBoolDefault(name, false)
}

func envBoolDefault(name string, def bool) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return def
	}
	return v
}

func portSuffix(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[i:]
		}
	}
	return ":8443"
}
