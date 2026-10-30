package main

import (
	"Ole/internal/app"
	"Ole/internal/config"
	"Ole/internal/httpapi"
	"Ole/internal/relay"
	"Ole/internal/structuredlog"
	"Ole/internal/stun"
	"Ole/internal/versioninfo"
	"context"
	"net/http"
	"os"
)

func main() {
	logger := structuredlog.New("server.main")
	cfg := config.Load()
	if err := cfg.ValidateServer(); err != nil {
		logger.Error("invalid server configuration", "error", err)
		os.Exit(1)
	}
	trustedProxies, err := httpapi.ParseTrustedProxies(cfg.HTTPTrustedProxies)
	if err != nil {
		logger.Error("invalid HTTP trusted proxy configuration", "error", err)
		os.Exit(1)
	}
	application, err := app.New(context.Background(), cfg)
	if err != nil {
		logger.Error("failed to initialize app", "error", err)
		return
	}
	defer func() {
		if closeErr := application.Close(); closeErr != nil {
			logger.Error("failed to close app", "error", closeErr)
		}
	}()

	stunServer, err := stun.Listen(cfg.STUNListenAddr)
	if err != nil {
		logger.Error("failed to start STUN server", "error", err, "listenAddress", cfg.STUNListenAddr)
		return
	}
	defer func() {
		if closeErr := stunServer.Close(); closeErr != nil {
			logger.Error("failed to close STUN server", "error", closeErr)
		}
	}()

	relayServer, err := relay.ListenWithConfig(cfg.RelayListenAddr, appRelayAuthorizer{application}, relay.Config{
		QuotaWindow:             cfg.RelayQuotaWindow,
		MaxPacketsPerPeerWindow: cfg.RelayQuotaPackets,
		MaxBytesPerPeerWindow:   cfg.RelayQuotaBytes,
		AbuseWindow:             cfg.RelayAbuseWindow,
		AbuseThreshold:          cfg.RelayAbuseThreshold,
		AbuseBlockDuration:      cfg.RelayAbuseBlockDuration,
	})
	if err != nil {
		logger.Error("failed to start relay server", "error", err, "listenAddress", cfg.RelayListenAddr)
		return
	}
	defer func() {
		if closeErr := relayServer.Close(); closeErr != nil {
			logger.Error("failed to close relay server", "error", closeErr)
		}
	}()

	logger.Info("server starting", "httpListenAddress", cfg.HTTPPort, "stunListenAddress", stunServer.LocalAddr().String(), "relayListenAddress", relayServer.LocalAddr().String())
	if snapshot := relayServer.Snapshot(); snapshot.QuotaWindowSeconds > 0 {
		logger.Info("relay quotas enabled", "windowSeconds", snapshot.QuotaWindowSeconds, "maxPacketsPerWindow", snapshot.MaxPacketsPerPeerWindow, "maxBytesPerWindow", snapshot.MaxBytesPerPeerWindow)
	}
	if snapshot := relayServer.Snapshot(); snapshot.AbuseThreshold > 0 && snapshot.AbuseBlockSeconds > 0 {
		logger.Info("relay abuse controls enabled", "windowSeconds", snapshot.AbuseWindowSeconds, "threshold", snapshot.AbuseThreshold, "blockSeconds", snapshot.AbuseBlockSeconds)
	}

	router := httpapi.NewRouterWithRelayStatusAndVersion(application, relayServer, versioninfo.ServerMetadata{
		APIVersion:       "v1",
		ServerVersion:    cfg.ServerVersion,
		MinClientVersion: cfg.MinClientVersion,
	}, trustedProxies...)

	err = http.ListenAndServe(cfg.HTTPPort, router)
	if err != nil {
		logger.Error("http server stopped with error", "error", err, "listenAddress", cfg.HTTPPort)
	}
}
