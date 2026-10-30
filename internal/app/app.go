package app

import (
	"Ole/internal/config"
	"Ole/internal/domain"
	"Ole/internal/store/postgres"
	"Ole/internal/structuredlog"
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"time"
)

type App struct {
	AuthService         *domain.AuthService
	DeviceService       *domain.DeviceService
	NetworkService      *domain.NetworkService
	PeerDirectory       *domain.PeerDirectory
	MessagingService    *domain.MessagingService
	FileTransferService *domain.FileTransferService
	SignalingService    *domain.SignalingService
	TunnelCoordinator   *domain.TunnelCoordinator
	AuditRepo           domain.AuditRepo
	UserRepo            domain.UserRepo
	DeviceRepo          domain.DeviceRepo
	NetworkRepo         domain.NetworkRepo
	PeerRepo            domain.PeerRepo
	MessageRepo         domain.MessageRepo
	FileTransferRepo    domain.FileTransferRepo
	FileTransferPayloadRepo domain.FileTransferPayloadRepo
	TunnelRepo          domain.TunnelRepo
	InviteRepo          domain.InviteRepo
	SignalCandidateRepo domain.SignalCandidateRepo
	SessionRepo         domain.SessionRepo
	DB                  *sql.DB
	ReadinessCheck      func(context.Context) error
	logger              *structuredlog.Logger
	peerHeartbeatTTL    time.Duration
	cleanupCancel       context.CancelFunc
	cleanupWG           sync.WaitGroup
	cleanupSuccessCount atomic.Int64
	cleanupFailureCount atomic.Int64
	lastCleanupUnix     atomic.Int64
}

type CleanupMetricsSnapshot struct {
	SuccessCount    int64
	FailureCount    int64
	LastCleanupUnix int64
}

type ReadinessSnapshot struct {
	Ready             bool
	DatabaseReachable bool
	Error             string
}

func New(ctx context.Context, cfg config.Config) (*App, error) {
	if err := cfg.ValidateServer(); err != nil {
		return nil, err
	}
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := postgres.Ping(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if cfg.AutoMigrate {
		if err := postgres.RunMigrations(ctx, db, cfg.MigrationsDir); err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	userRepo := postgres.NewUserRepo(db)
	deviceRepo := postgres.NewDeviceRepo(db)
	networkRepo := postgres.NewNetworkRepo(db)
	peerRepo := postgres.NewPeerRepo(db)
	messageRepo := postgres.NewMessageRepo(db)
	fileTransferRepo := postgres.NewFileTransferRepo(db)
	fileTransferPayloadRepo := postgres.NewFileTransferPayloadRepo(db)
	tunnelRepo := postgres.NewTunnelRepo(db)
	inviteRepo := postgres.NewInviteRepo(db)
	signalCandidateRepo := postgres.NewSignalCandidateRepo(db)
	sessionRepo := postgres.NewSessionRepo(db)
	auditRepo := postgres.NewAuditRepo(db)
	poolRepo := postgres.NewVirtualIPPoolRepo(db)

	application := &App{
		AuthService:         domain.NewAuthService(userRepo, auditRepo, sessionRepo, cfg.JWTSecret, cfg.JWTIssuer),
		DeviceService:       domain.NewDeviceService(deviceRepo, auditRepo),
		NetworkService:      domain.NewNetworkService(networkRepo, inviteRepo, auditRepo),
		PeerDirectory:       domain.NewPeerDirectory(peerRepo, networkRepo, poolRepo, deviceRepo, auditRepo, userRepo),
		MessagingService:    domain.NewMessagingService(messageRepo, peerRepo, networkRepo, auditRepo),
		FileTransferService: domain.NewFileTransferService(fileTransferRepo, peerRepo, networkRepo, auditRepo, fileTransferPayloadRepo),
		SignalingService:    domain.NewSignalingService(peerRepo, networkRepo, signalCandidateRepo, auditRepo),
		TunnelCoordinator:   domain.NewTunnelCoordinator(tunnelRepo, peerRepo, auditRepo, networkRepo),
		AuditRepo:           auditRepo,
		UserRepo:            userRepo,
		DeviceRepo:          deviceRepo,
		NetworkRepo:         networkRepo,
		PeerRepo:            peerRepo,
		MessageRepo:         messageRepo,
		FileTransferRepo:    fileTransferRepo,
		FileTransferPayloadRepo: fileTransferPayloadRepo,
		TunnelRepo:          tunnelRepo,
		InviteRepo:          inviteRepo,
		SignalCandidateRepo: signalCandidateRepo,
		SessionRepo:         sessionRepo,
		DB:                  db,
		ReadinessCheck:      db.PingContext,
		logger:              structuredlog.New("server.app"),
		peerHeartbeatTTL:    cfg.PeerHeartbeatTTL,
	}

	application.startCleanupLoop(ctx, cfg.CleanupInterval)

	return application, nil
}

func (a *App) Close() error {
	if a.cleanupCancel != nil {
		a.cleanupCancel()
		a.cleanupWG.Wait()
	}
	if a.DB != nil {
		return a.DB.Close()
	}
	return nil
}

func (a *App) RunCleanupCycle(nowUnix int64) error {
	if a.AuthService != nil {
		if err := a.AuthService.CleanupExpiredSessions(nowUnix); err != nil {
			a.recordCleanupResult(nowUnix, false)
			return err
		}
	}
	if a.InviteRepo != nil {
		if err := a.InviteRepo.DeleteStale(nowUnix); err != nil {
			a.recordCleanupResult(nowUnix, false)
			return err
		}
	}
	if a.SignalCandidateRepo != nil {
		if err := a.SignalCandidateRepo.DeleteExpired(nowUnix); err != nil {
			a.recordCleanupResult(nowUnix, false)
			return err
		}
	}
	if a.PeerDirectory != nil && a.peerHeartbeatTTL > 0 {
		if err := a.PeerDirectory.CleanupStalePeers(nowUnix, int64(a.peerHeartbeatTTL/time.Second)); err != nil {
			a.recordCleanupResult(nowUnix, false)
			return err
		}
	}
	a.recordCleanupResult(nowUnix, true)
	return nil
}

func (a *App) CleanupMetricsSnapshot() CleanupMetricsSnapshot {
	if a == nil {
		return CleanupMetricsSnapshot{}
	}
	return CleanupMetricsSnapshot{
		SuccessCount:    a.cleanupSuccessCount.Load(),
		FailureCount:    a.cleanupFailureCount.Load(),
		LastCleanupUnix: a.lastCleanupUnix.Load(),
	}
}

func (a *App) recordCleanupResult(nowUnix int64, success bool) {
	if a == nil {
		return
	}
	a.lastCleanupUnix.Store(nowUnix)
	if success {
		a.cleanupSuccessCount.Add(1)
		return
	}
	a.cleanupFailureCount.Add(1)
}

func (a *App) ReadinessSnapshot(ctx context.Context) ReadinessSnapshot {
	if a == nil {
		return ReadinessSnapshot{Ready: true}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	check := a.ReadinessCheck
	if check == nil && a.DB != nil {
		check = a.DB.PingContext
	}
	if check == nil {
		return ReadinessSnapshot{Ready: true, DatabaseReachable: true}
	}
	if err := check(ctx); err != nil {
		return ReadinessSnapshot{
			Ready:             false,
			DatabaseReachable: false,
			Error:             err.Error(),
		}
	}
	return ReadinessSnapshot{
		Ready:             true,
		DatabaseReachable: true,
	}
}

func (a *App) startCleanupLoop(parent context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	runCtx, cancel := context.WithCancel(parent)
	a.cleanupCancel = cancel
	a.cleanupWG.Add(1)
	go func() {
		defer a.cleanupWG.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if err := a.RunCleanupCycle(time.Now().Unix()); err != nil {
					if a.logger != nil {
						a.logger.Error("cleanup cycle failed", "error", err)
					}
				}
			}
		}
	}()
}
