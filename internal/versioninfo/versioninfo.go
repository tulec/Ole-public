package versioninfo

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	DefaultClientVersion   = "0.1.0"
	DefaultServerVersion   = "0.1.0"
	HeaderClientVersion    = "X-Ole-Client-Version"
	HeaderServerVersion    = "X-Ole-Server-Version"
	HeaderMinClientVersion = "X-Ole-Min-Client-Version"
	StatusCompatible       = "COMPATIBLE"
	StatusUpgradeRequired  = "UPGRADE_REQUIRED"
	StatusWarning          = "WARNING"
	StatusUnknown          = "UNKNOWN"
)

type ServerMetadata struct {
	APIVersion       string `json:"apiVersion"`
	ServerVersion    string `json:"serverVersion"`
	MinClientVersion string `json:"minClientVersion"`
}

type Compatibility struct {
	ClientVersion    string `json:"clientVersion"`
	ServerVersion    string `json:"serverVersion"`
	MinClientVersion string `json:"minClientVersion"`
	Status           string `json:"status"`
	Message          string `json:"message"`
	Compatible       bool   `json:"compatible"`
}

func Evaluate(clientVersion string, metadata ServerMetadata) Compatibility {
	result := Compatibility{
		ClientVersion:    strings.TrimSpace(clientVersion),
		ServerVersion:    strings.TrimSpace(metadata.ServerVersion),
		MinClientVersion: strings.TrimSpace(metadata.MinClientVersion),
		Status:           StatusUnknown,
		Message:          "server version metadata is unavailable",
	}
	if result.ClientVersion == "" {
		result.Message = "client version is unavailable"
		return result
	}
	if result.ServerVersion == "" && result.MinClientVersion == "" {
		return result
	}
	if result.MinClientVersion != "" {
		cmp, err := Compare(result.ClientVersion, result.MinClientVersion)
		if err == nil && cmp < 0 {
			result.Status = StatusUpgradeRequired
			result.Message = fmt.Sprintf("client %s is below the minimum supported version %s", result.ClientVersion, result.MinClientVersion)
			result.Compatible = false
			return result
		}
	}
	if result.ServerVersion != "" {
		clientMM, clientErr := majorMinor(result.ClientVersion)
		serverMM, serverErr := majorMinor(result.ServerVersion)
		if clientErr == nil && serverErr == nil && clientMM != serverMM {
			result.Status = StatusWarning
			result.Message = fmt.Sprintf("client %s differs from server %s", result.ClientVersion, result.ServerVersion)
			result.Compatible = true
			return result
		}
	}
	result.Status = StatusCompatible
	result.Message = "client version is compatible with the server"
	result.Compatible = true
	return result
}

func Compare(left, right string) (int, error) {
	lv, err := parseVersion(left)
	if err != nil {
		return 0, err
	}
	rv, err := parseVersion(right)
	if err != nil {
		return 0, err
	}
	for idx := 0; idx < 3; idx++ {
		switch {
		case lv[idx] < rv[idx]:
			return -1, nil
		case lv[idx] > rv[idx]:
			return 1, nil
		}
	}
	return 0, nil
}

func majorMinor(value string) (string, error) {
	parts, err := parseVersion(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d.%d", parts[0], parts[1]), nil
}

func parseVersion(value string) ([3]int, error) {
	var out [3]int
	normalized := strings.TrimSpace(value)
	normalized = strings.TrimPrefix(normalized, "v")
	if cut := strings.IndexAny(normalized, "-+"); cut >= 0 {
		normalized = normalized[:cut]
	}
	if normalized == "" {
		return out, fmt.Errorf("empty version")
	}
	parts := strings.Split(normalized, ".")
	if len(parts) > 3 {
		return out, fmt.Errorf("invalid version %q", value)
	}
	for idx, part := range parts {
		number, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return out, fmt.Errorf("invalid version %q", value)
		}
		out[idx] = number
	}
	return out, nil
}
