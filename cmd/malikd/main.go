package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/malikssm/malik/internal/server"
	"github.com/malikssm/malik/internal/vault"
)

func main() {
	defaultAddr := os.Getenv("MALIK_ADDR")
	if defaultAddr == "" {
		defaultAddr = "0.0.0.0:8443"
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
	flag.Parse()

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0700); err != nil {
		log.Fatalf("[MalikSSM] Failed to create data directory: %v", err)
	}

	store, err := vault.OpenStore(*dbPath)
	if err != nil {
		log.Fatalf("[MalikSSM] Failed to open vault database: %v", err)
	}
	defer store.Close()

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
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Println("=======================================================================")
	fmt.Println("  MalikSSM Server (malikd) — Agent-First Secrets Manager (Go Native)")
	fmt.Println("=======================================================================")
	fmt.Printf("  Listen Address : http://%s\n", *addr)
	fmt.Printf("  Web Dashboard  : http://127.0.0.1%s/ui\n", portSuffix(*addr))
	fmt.Printf("  ChatGPT OpenAPI: http://127.0.0.1%s/openapi.json\n", portSuffix(*addr))
	fmt.Printf("  AWS Boto3 URL  : http://127.0.0.1%s\n", portSuffix(*addr))
	fmt.Printf("  Database Path  : %s\n", *dbPath)
	fmt.Printf("  Vault State    : Initialized=%v | Unlocked=%v | AutoUnseal(DPAPI)=%v\n", st.Initialized, st.Unlocked, st.AutoUnsealReady)
	fmt.Println("=======================================================================")

	go func() {
		var serveErr error
		if *tlsCert != "" && *tlsKey != "" {
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

func portSuffix(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[i:]
		}
	}
	return ":8443"
}
