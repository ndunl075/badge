// Command badge-proxy runs the Badge doorman in front of any origin.
//
//	badge-proxy -config badge.yaml
//
// The default policy denies nothing, so putting the proxy in front of a live
// site cannot break it. Turn on dryRun to find out what enforcing would change
// before enforcing it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ndunl075/badge/sidecar/proxy"
)

func main() {
	configPath := flag.String("config", "badge.yaml", "path to the configuration file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "badge-proxy:", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := proxy.LoadConfig(configPath)
	if err != nil {
		return err
	}
	handler, err := cfg.Build(proxy.JSONSink{Out: os.Stdout})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", proxy.Healthz)
	mux.Handle("/", handler)

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	fmt.Fprintf(os.Stderr, "badge-proxy listening on %s, forwarding to %s\n", cfg.Listen, cfg.Upstream)
	if cfg.DryRun {
		fmt.Fprintln(os.Stderr, "dry run: the policy is evaluated and reported, but nothing is refused")
	}

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
