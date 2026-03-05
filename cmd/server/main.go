package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"oss-commands-gateway/internal/app"
	"oss-commands-gateway/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	server, err := app.New(cfg)
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = server.Shutdown()
	}()

	if err := server.Listen(":" + cfg.Port); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}
