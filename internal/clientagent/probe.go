package clientagent

import "time"

type ProbeResponse struct {
	Status      string                `json:"status"`
	Time        int64                 `json:"time"`
	ServiceName string                `json:"serviceName,omitempty"`
	StatePath   string                `json:"statePath,omitempty"`
	Checks      map[string]ProbeCheck `json:"checks,omitempty"`
}

type ProbeCheck struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func (a *Agent) livenessProbe() ProbeResponse {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ProbeResponse{
		Status:      "alive",
		Time:        time.Now().Unix(),
		ServiceName: "Ole Agent",
		StatePath:   a.statePathLocked(),
		Checks: map[string]ProbeCheck{
			"process": {Status: "ok"},
			"http":    {Status: "ok"},
		},
	}
}

func (a *Agent) readinessProbe() (ProbeResponse, int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	response := ProbeResponse{
		Status:      "ready",
		Time:        time.Now().Unix(),
		ServiceName: "Ole Agent",
		StatePath:   a.statePathLocked(),
		Checks: map[string]ProbeCheck{
			"http": {Status: "ok"},
		},
	}
	if a.stateErr != nil {
		response.Status = "not_ready"
		response.Checks["stateStore"] = ProbeCheck{
			Status: "error",
			Detail: a.stateErr.Error(),
		}
		return response, 503
	}
	response.Checks["stateStore"] = ProbeCheck{Status: "ok"}
	return response, 200
}
