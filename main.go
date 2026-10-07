package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	path := flag.String("config", "sesame.toml", "path to TOML config file")
	flag.Parse()

	cfg, err := LoadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	if weakSecret(cfg.secretBytes) {
		log.Printf("warning: secret has fewer than 8 distinct bytes; use 32+ bytes of random data")
	}
	if cfg.SMTP.TLS == "none" && !isLocalHost(cfg.SMTP.Host) {
		log.Printf("warning: smtp.tls = \"none\": one-time codes are sent unencrypted to %s", cfg.SMTP.Host)
	}
	srv, err := NewServer(cfg, &SMTPSender{cfg: cfg.SMTP})
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close()
	if cfg.PasskeysEnabled() {
		log.Printf("passkeys enabled (rp_id %s, store %s)", cfg.Passkey.RPID, cfg.Passkey.Store)
	}

	stop := make(chan struct{})
	go srv.Run(stop)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		close(stop)
		sctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		hs.Shutdown(sctx)
	}()

	log.Printf("sesame listening on %s", cfg.Listen)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
