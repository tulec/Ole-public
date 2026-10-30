package httpapi

import (
	"Ole/internal/app"
	"Ole/internal/prommetrics"
	"Ole/internal/relay"
	"Ole/internal/structuredlog"
	"Ole/internal/versioninfo"
	"net/http"
	"net/netip"

	httpSwagger "github.com/swaggo/http-swagger/v2"
)

type API struct {
	app            *app.App
	authLimiter    *authRateLimiter
	authAbuse      *authAbuseMonitor
	relayStatus    relayStatusProvider
	versionInfo    versioninfo.ServerMetadata
	logger         *structuredlog.Logger
	metrics        *prommetrics.Registry
	trustedProxies []netip.Prefix
}

func NewRouter(application *app.App, trustedProxies ...netip.Prefix) http.Handler {
	return NewRouterWithRelayStatusAndVersion(application, nil, versioninfo.ServerMetadata{
		APIVersion:       "v1",
		ServerVersion:    versioninfo.DefaultServerVersion,
		MinClientVersion: versioninfo.DefaultClientVersion,
	}, trustedProxies...)
}

type relayStatusProvider interface {
	Snapshot() relay.StatusSnapshot
}

func NewRouterWithRelayStatus(application *app.App, relayStatus relayStatusProvider, trustedProxies ...netip.Prefix) http.Handler {
	return NewRouterWithRelayStatusAndVersion(application, relayStatus, versioninfo.ServerMetadata{
		APIVersion:       "v1",
		ServerVersion:    versioninfo.DefaultServerVersion,
		MinClientVersion: versioninfo.DefaultClientVersion,
	}, trustedProxies...)
}

func NewRouterWithRelayStatusAndVersion(application *app.App, relayStatus relayStatusProvider, metadata versioninfo.ServerMetadata, trustedProxies ...netip.Prefix) http.Handler {
	logger := structuredlog.New("server.httpapi")
	var limiter *authRateLimiter
	var abuseMonitor *authAbuseMonitor
	if application != nil {
		limiter = newAuthRateLimiterWithDB(application.DB)
		abuseMonitor = newAuthAbuseMonitorWithDB(application.DB)
	} else {
		limiter = newAuthRateLimiter()
		abuseMonitor = newAuthAbuseMonitor()
	}
	if abuseMonitor != nil {
		abuseMonitor.logger = structuredlog.New("server.auth_abuse")
	}
	api := &API{
		app:            application,
		authLimiter:    limiter,
		authAbuse:      abuseMonitor,
		relayStatus:    relayStatus,
		versionInfo:    metadata,
		logger:         logger,
		metrics:        prommetrics.NewRegistry(),
		trustedProxies: append([]netip.Prefix(nil), trustedProxies...),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", api.handleHealth)
	mux.HandleFunc("/livez", api.handleLiveness)
	mux.HandleFunc("/readyz", api.handleReadiness)
	mux.HandleFunc("/metrics", api.handleMetrics)
	mux.HandleFunc("/openapi.yaml", api.handleOpenAPI)
	mux.HandleFunc("/swagger", api.handleSwaggerUI)
	mux.Handle("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("/openapi.yaml"),
		httpSwagger.DocExpansion("list"),
		httpSwagger.DeepLinking(true),
	))
	mux.HandleFunc("/api/v1", api.handleRoot)
	mux.HandleFunc("/api/v1/", api.routeV1)

	return api.withMiddleware(mux)
}

func (api *API) routeV1(w http.ResponseWriter, r *http.Request) {
	segments := splitPath(trimPrefix(r.URL.Path, "/api/v1/"))
	if len(segments) == 0 {
		api.handleRoot(w, r)
		return
	}

	switch segments[0] {
	case "users":
		api.routeUsers(w, r, segments[1:])
	case "devices":
		api.routeDevices(w, r, segments[1:])
	case "sessions":
		api.routeSessions(w, r, segments[1:])
	case "networks":
		api.routeNetworks(w, r, segments[1:])
	case "invites":
		api.routeInvites(w, r, segments[1:])
	case "messages":
		api.routeMessages(w, r, segments[1:])
	case "peers":
		api.routePeers(w, r, segments[1:])
	case "file-transfers":
		api.routeFileTransfers(w, r, segments[1:])
	case "tunnels":
		api.routeTunnels(w, r, segments[1:])
	case "audit-events":
		api.routeAuditEvents(w, r, segments[1:])
	case "incidents":
		api.routeIncidents(w, r, segments[1:])
	default:
		writeNotFound(w)
	}
}

func (api *API) routeIncidents(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 0 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(api.listIncidentReports)).ServeHTTP(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routeDevices(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 0 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(api.listDevices)).ServeHTTP(w, r)
	case len(segments) == 0 && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(api.createDevice)).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.getDevice(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodPatch:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.patchDevice(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodDelete:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.deleteDevice(w, r, segments[0])
		})).ServeHTTP(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routeUsers(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 0 && r.Method == http.MethodPost:
		api.createUser(w, r)
	case len(segments) == 1 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.getUser(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "password" && r.Method == http.MethodPut:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.updateUserPassword(w, r, segments[0])
		})).ServeHTTP(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routeSessions(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 0 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(api.listSessions)).ServeHTTP(w, r)
	case len(segments) == 0 && r.Method == http.MethodPost:
		api.createSession(w, r)
	case len(segments) == 0 && r.Method == http.MethodDelete:
		api.authMiddleware(http.HandlerFunc(api.deleteSession)).ServeHTTP(w, r)
	case len(segments) == 1 && segments[0] == "all" && r.Method == http.MethodDelete:
		api.authMiddleware(http.HandlerFunc(api.deleteAllSessions)).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodDelete:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.deleteSessionByID(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 1 && segments[0] == "refresh" && r.Method == http.MethodPost:
		api.refreshSession(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routeNetworks(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 0 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(api.listNetworks)).ServeHTTP(w, r)
	case len(segments) == 0 && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(api.createNetwork)).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.getNetwork(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodDelete:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.deleteNetwork(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "members" && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.addNetworkMember(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 3 && segments[1] == "members" && r.Method == http.MethodPatch:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.updateNetworkMemberRole(w, r, segments[0], segments[2])
		})).ServeHTTP(w, r)
	case len(segments) == 3 && segments[1] == "members" && r.Method == http.MethodDelete:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.removeNetworkMember(w, r, segments[0], segments[2])
		})).ServeHTTP(w, r)
	case len(segments) == 3 && segments[1] == "device-approvals" && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.approveNetworkDevice(w, r, segments[0], segments[2])
		})).ServeHTTP(w, r)
	case len(segments) == 3 && segments[1] == "device-approvals" && r.Method == http.MethodDelete:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.revokeNetworkDeviceApproval(w, r, segments[0], segments[2])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "routing-policy" && r.Method == http.MethodPatch:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.updateNetworkRoutingPolicy(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "group-traffic" && r.Method == http.MethodPatch:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.updateNetworkGroupTrafficPolicy(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "name-resolution" && r.Method == http.MethodPatch:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.updateNetworkNameResolution(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "file-transfer-policy" && r.Method == http.MethodPatch:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.updateNetworkFileTransferPolicy(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "invites" && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.createNetworkInvite(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "audit-events" && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.listNetworkAuditEvents(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "peers" && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.listNetworkPeers(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "peers" && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.createNetworkPeer(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "messages" && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.listNetworkMessages(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "messages" && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.createNetworkMessage(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "file-transfers" && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.listNetworkFileTransfers(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "file-transfers" && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.createNetworkFileTransfer(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "tunnels" && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.listNetworkTunnels(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "tunnels" && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.createNetworkTunnel(w, r, segments[0])
		})).ServeHTTP(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routeInvites(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 2 && segments[1] == "redemptions" && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.redeemInvite(w, r, segments[0])
		})).ServeHTTP(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routeMessages(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 1 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.getMessage(w, r, segments[0])
		})).ServeHTTP(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routePeers(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 2 && segments[1] == "transport-identities" && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.getTransportIdentities(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.getPeer(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodPatch:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.patchPeer(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "candidates" && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.listPeerCandidates(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "candidates" && r.Method == http.MethodPost:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.createPeerCandidate(w, r, segments[0])
		})).ServeHTTP(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routeFileTransfers(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 1 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.getFileTransfer(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodPatch:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.patchFileTransfer(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "content" && r.Method == http.MethodPut:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.uploadFileTransferContent(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "content" && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.downloadFileTransferContent(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "content-chunks" && r.Method == http.MethodPut:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.uploadFileTransferContentChunk(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 2 && segments[1] == "content-chunks" && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.downloadFileTransferContentChunk(w, r, segments[0])
		})).ServeHTTP(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routeTunnels(w http.ResponseWriter, r *http.Request, segments []string) {
	switch {
	case len(segments) == 1 && r.Method == http.MethodGet:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.getTunnel(w, r, segments[0])
		})).ServeHTTP(w, r)
	case len(segments) == 1 && r.Method == http.MethodPatch:
		api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			api.patchTunnel(w, r, segments[0])
		})).ServeHTTP(w, r)
	default:
		writeMethodOrNotFound(w, segments)
	}
}

func (api *API) routeAuditEvents(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) != 0 {
		writeNotFound(w)
		return
	}
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	api.authMiddleware(http.HandlerFunc(api.listAuditEvents)).ServeHTTP(w, r)
}
