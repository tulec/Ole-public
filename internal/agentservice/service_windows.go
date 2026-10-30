//go:build windows

package agentservice

import (
	"Ole/internal/clientagent"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	DefaultServiceName        = "OleAgent"
	DefaultServiceDisplayName = "Ole Agent"
	DefaultServiceDescription = "Ole background agent for device identity, session management, and local GUI IPC."
)

type Settings struct {
	ServiceName string
	DisplayName string
	Description string
	ListenAddr  string
	Runtime     clientagent.RuntimeConfig
}

type Action int

const (
	ActionRun Action = iota
	ActionInstall
	ActionUninstall
	ActionStart
	ActionStop
	ActionStatus
	ActionConsole
)

type Logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type stdLogger struct{}

func (stdLogger) Infof(format string, args ...any) {
	log.Printf(format, args...)
}

func (stdLogger) Errorf(format string, args ...any) {
	log.Printf(format, args...)
}

type eventLogger struct {
	log *eventlog.Log
}

func (l *eventLogger) Infof(format string, args ...any) {
	if l == nil || l.log == nil {
		return
	}
	_ = l.log.Info(1, fmt.Sprintf(format, args...))
}

func (l *eventLogger) Errorf(format string, args ...any) {
	if l == nil || l.log == nil {
		return
	}
	_ = l.log.Error(1, fmt.Sprintf(format, args...))
}

func DefaultSettings() Settings {
	addr := strings.TrimSpace(os.Getenv("OLE_AGENT_ADDR"))
	if addr == "" {
		addr = clientagent.DefaultListenAddress
	}
	runtime := clientagent.DefaultRuntimeConfig()
	runtime.OverlayDNSListenAddress = "127.0.0.1:53"
	runtime.OverlayDNSDomain = "ole"
	if stunServerAddress := strings.TrimSpace(os.Getenv("OLE_AGENT_STUN_SERVER_ADDR")); stunServerAddress != "" {
		runtime.STUNServerAddress = stunServerAddress
	}
	if overlayDNSListenAddress := strings.TrimSpace(os.Getenv("OLE_AGENT_DNS_LISTEN_ADDR")); overlayDNSListenAddress != "" {
		runtime.OverlayDNSListenAddress = overlayDNSListenAddress
	}
	if overlayDNSDomain := strings.TrimSpace(os.Getenv("OLE_AGENT_DNS_DOMAIN")); overlayDNSDomain != "" {
		runtime.OverlayDNSDomain = overlayDNSDomain
	}
	if relayServerAddress := strings.TrimSpace(os.Getenv("OLE_AGENT_RELAY_SERVER_ADDR")); relayServerAddress != "" {
		runtime.RelayServerAddress = relayServerAddress
	}
	if relayFailbackPeriod := strings.TrimSpace(os.Getenv("OLE_AGENT_RELAY_FAILBACK_PERIOD")); relayFailbackPeriod != "" {
		if parsed, err := time.ParseDuration(relayFailbackPeriod); err == nil {
			runtime.RelayFailbackPeriod = parsed
		}
	}
	if transportKeepalive := strings.TrimSpace(os.Getenv("OLE_AGENT_TRANSPORT_KEEPALIVE")); transportKeepalive != "" {
		if parsed, err := time.ParseDuration(transportKeepalive); err == nil {
			runtime.TransportKeepalive = parsed
		}
	}
	if transportLossLimit := strings.TrimSpace(os.Getenv("OLE_AGENT_TRANSPORT_LOSS_LIMIT")); transportLossLimit != "" {
		if parsed, err := strconv.Atoi(transportLossLimit); err == nil {
			runtime.TransportLossLimit = parsed
		}
	}
	if reconnectRetryBase := strings.TrimSpace(os.Getenv("OLE_AGENT_RECONNECT_RETRY_BASE")); reconnectRetryBase != "" {
		if parsed, err := time.ParseDuration(reconnectRetryBase); err == nil {
			runtime.ReconnectRetryBase = parsed
		}
	}
	if reconnectRetryMax := strings.TrimSpace(os.Getenv("OLE_AGENT_RECONNECT_RETRY_MAX")); reconnectRetryMax != "" {
		if parsed, err := time.ParseDuration(reconnectRetryMax); err == nil {
			runtime.ReconnectRetryMax = parsed
		}
	}
	if updateManifestURL := strings.TrimSpace(os.Getenv("OLE_UPDATE_MANIFEST_URL")); updateManifestURL != "" {
		runtime.UpdateManifestURL = updateManifestURL
	}
	if updateStableManifestURL := strings.TrimSpace(os.Getenv("OLE_UPDATE_STABLE_MANIFEST_URL")); updateStableManifestURL != "" {
		runtime.UpdateStableManifestURL = updateStableManifestURL
	}
	if updateBetaManifestURL := strings.TrimSpace(os.Getenv("OLE_UPDATE_BETA_MANIFEST_URL")); updateBetaManifestURL != "" {
		runtime.UpdateBetaManifestURL = updateBetaManifestURL
	}
	if updateChannel := strings.TrimSpace(os.Getenv("OLE_UPDATE_CHANNEL")); updateChannel != "" {
		runtime.UpdateChannel = updateChannel
	}
	if updateCheckPeriod := strings.TrimSpace(os.Getenv("OLE_UPDATE_CHECK_PERIOD")); updateCheckPeriod != "" {
		if parsed, err := time.ParseDuration(updateCheckPeriod); err == nil {
			runtime.UpdateCheckPeriod = parsed
		}
	}
	if updateDownloadDir := strings.TrimSpace(os.Getenv("OLE_UPDATE_DOWNLOAD_DIR")); updateDownloadDir != "" {
		runtime.UpdateDownloadDir = updateDownloadDir
	}
	if stunProbePeriod := strings.TrimSpace(os.Getenv("OLE_AGENT_STUN_PROBE_PERIOD")); stunProbePeriod != "" {
		if parsed, err := time.ParseDuration(stunProbePeriod); err == nil {
			runtime.STUNProbePeriod = parsed
		}
	}
	if directProbeTimeout := strings.TrimSpace(os.Getenv("OLE_AGENT_DIRECT_PROBE_TIMEOUT")); directProbeTimeout != "" {
		if parsed, err := time.ParseDuration(directProbeTimeout); err == nil {
			runtime.DirectProbeTimeout = parsed
		}
	}
	if directRetryBase := strings.TrimSpace(os.Getenv("OLE_AGENT_DIRECT_RETRY_BASE")); directRetryBase != "" {
		if parsed, err := time.ParseDuration(directRetryBase); err == nil {
			runtime.DirectRetryBase = parsed
		}
	}
	if directRetryMax := strings.TrimSpace(os.Getenv("OLE_AGENT_DIRECT_RETRY_MAX")); directRetryMax != "" {
		if parsed, err := time.ParseDuration(directRetryMax); err == nil {
			runtime.DirectRetryMax = parsed
		}
	}
	if directMaxAttempts := strings.TrimSpace(os.Getenv("OLE_AGENT_DIRECT_MAX_ATTEMPTS")); directMaxAttempts != "" {
		if parsed, err := strconv.Atoi(directMaxAttempts); err == nil {
			runtime.DirectMaxAttempts = parsed
		}
	}
	return Settings{
		ServiceName: DefaultServiceName,
		DisplayName: DefaultServiceDisplayName,
		Description: DefaultServiceDescription,
		ListenAddr:  addr,
		Runtime:     runtime,
	}
}

func ParseAction(args []string, runningAsService bool) (Action, error) {
	if len(args) == 0 {
		if runningAsService {
			return ActionRun, nil
		}
		return ActionConsole, nil
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "service":
		return ActionRun, nil
	case "install":
		return ActionInstall, nil
	case "uninstall", "remove":
		return ActionUninstall, nil
	case "start":
		return ActionStart, nil
	case "stop":
		return ActionStop, nil
	case "status":
		return ActionStatus, nil
	case "console", "run":
		return ActionConsole, nil
	default:
		return 0, fmt.Errorf("unknown command %q", args[0])
	}
}

func Execute(action Action, settings Settings, exePath string, logger Logger) error {
	if logger == nil {
		logger = stdLogger{}
	}
	switch action {
	case ActionInstall:
		return Install(settings, exePath)
	case ActionUninstall:
		return Uninstall(settings)
	case ActionStart:
		return Start(settings)
	case ActionStop:
		return Stop(settings, 20*time.Second)
	case ActionStatus:
		status, err := QueryStatus(settings)
		if err != nil {
			return err
		}
		logger.Infof("Ole Agent service status: %s", status)
		return nil
	case ActionRun:
		return RunService(settings)
	case ActionConsole:
		return RunConsole(settings, logger)
	default:
		return fmt.Errorf("unsupported action: %d", action)
	}
}

func RunConsole(settings Settings, logger Logger) error {
	if logger == nil {
		logger = stdLogger{}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Infof("Ole agent listening on %s", settings.ListenAddr)
	return runHTTPServer(ctx, settings, logger)
}

func RunService(settings Settings) error {
	elog, err := eventlog.Open(settings.ServiceName)
	if err != nil {
		return svc.Run(settings.ServiceName, &serviceHandler{
			settings: settings,
			logger:   stdLogger{},
		})
	}
	defer elog.Close()
	return svc.Run(settings.ServiceName, &serviceHandler{
		settings: settings,
		logger:   &eventLogger{log: elog},
	})
}

func RunDebug(settings Settings) error {
	consoleLog := debug.New(settings.ServiceName)
	return debug.Run(settings.ServiceName, &serviceHandler{
		settings: settings,
		logger:   &debugLogger{log: consoleLog},
	})
}

type debugLogger struct {
	log debug.Log
}

func (l *debugLogger) Infof(format string, args ...any) {
	if l == nil || l.log == nil {
		return
	}
	_ = l.log.Info(1, fmt.Sprintf(format, args...))
}

func (l *debugLogger) Errorf(format string, args ...any) {
	if l == nil || l.log == nil {
		return
	}
	_ = l.log.Error(1, fmt.Sprintf(format, args...))
}

type serviceHandler struct {
	settings Settings
	logger   Logger
}

func (h *serviceHandler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- runHTTPServer(ctx, h.settings, h.logger)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}
	h.logger.Infof("Ole Agent service running on %s", h.settings.ListenAddr)

	for {
		select {
		case change := <-r:
			switch change.Cmd {
			case svc.Interrogate:
				changes <- change.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				err := <-serverErr
				if err != nil {
					h.logger.Errorf("Ole Agent service stopped with error: %v", err)
					return false, 1
				}
				h.logger.Infof("Ole Agent service stopped")
				return false, 0
			default:
				h.logger.Infof("Ignoring service control command: %d", change.Cmd)
			}
		case err := <-serverErr:
			if err != nil {
				h.logger.Errorf("Ole Agent service runtime error: %v", err)
				return false, 1
			}
			return false, 0
		}
	}
}

func runHTTPServer(ctx context.Context, settings Settings, logger Logger) error {
	agent := clientagent.NewWithClientAndStoreAndRuntime(nil, settings.ListenAddr, nil, settings.Runtime)
	defer agent.Close()
	if err := agent.Restore(); err != nil && logger != nil {
		logger.Errorf("Ole Agent restore failed: %v", err)
	}
	server := &http.Server{
		Addr:    settings.ListenAddr,
		Handler: agent.Handler(),
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	if err != nil {
		return err
	}
	if logger != nil {
		logger.Infof("Ole Agent HTTP server stopped")
	}
	return nil
}

func Install(settings Settings, exePath string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	if existing, err := manager.OpenService(settings.ServiceName); err == nil {
		existing.Close()
		return fmt.Errorf("service %s already exists", settings.ServiceName)
	}

	service, err := manager.CreateService(settings.ServiceName, exePath, buildServiceConfig(settings), serviceArguments()...)
	if err != nil {
		return err
	}
	defer service.Close()

	if err := service.SetRecoveryActions(defaultRecoveryActions(), 24*60*60); err != nil {
		return err
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return err
	}
	_ = eventlog.InstallAsEventCreate(settings.ServiceName, eventlog.Info|eventlog.Warning|eventlog.Error)
	return nil
}

func Uninstall(settings Settings) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	service, err := manager.OpenService(settings.ServiceName)
	if err != nil {
		return err
	}
	defer service.Close()

	_, _ = service.Control(svc.Stop)
	if err := waitForState(service, svc.Stopped, 10*time.Second); err != nil {
		log.Printf("service stop during uninstall did not complete cleanly: %v", err)
	}
	if err := service.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(settings.ServiceName)
	return nil
}

func Start(settings Settings) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	service, err := manager.OpenService(settings.ServiceName)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Start()
}

func Stop(settings Settings, timeout time.Duration) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()

	service, err := manager.OpenService(settings.ServiceName)
	if err != nil {
		return err
	}
	defer service.Close()

	if _, err := service.Control(svc.Stop); err != nil {
		return err
	}
	return waitForState(service, svc.Stopped, timeout)
}

func QueryStatus(settings Settings) (string, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer manager.Disconnect()

	service, err := manager.OpenService(settings.ServiceName)
	if err != nil {
		return "", err
	}
	defer service.Close()

	status, err := service.Query()
	if err != nil {
		return "", err
	}
	return stateString(status.State), nil
}

func waitForState(service *mgr.Service, desired svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == desired {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for service state %s", stateString(desired))
}

func buildServiceConfig(settings Settings) mgr.Config {
	return mgr.Config{
		DisplayName:      settings.DisplayName,
		Description:      settings.Description,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
	}
}

func serviceArguments() []string {
	return []string{"service"}
}

func defaultRecoveryActions() []mgr.RecoveryAction {
	return []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
}

func stateString(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start_pending"
	case svc.StopPending:
		return "stop_pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue_pending"
	case svc.PausePending:
		return "pause_pending"
	case svc.Paused:
		return "paused"
	default:
		return fmt.Sprintf("state_%d", state)
	}
}
