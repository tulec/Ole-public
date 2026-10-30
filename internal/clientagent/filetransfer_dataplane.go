package clientagent

import (
	"Ole/internal/controlclient"
	"Ole/internal/transportauth"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	fileTransferDataplaneAttempts  = 3
	fileTransferDataplaneMaxBlocks = 2048
	fileTransferDataplaneDeadline  = 5 * time.Second
)

var errFileTransferInterrupted = errors.New("file transfer interrupted")

// Keep the wire envelope bounded even when local metadata contains JSON escapes.
// A short slice is a partial response, not EOF; callers continue at NextOffsetBytes.
func encodeFileTransferDataplaneResponse(response fileTransferDataplaneResponse) []byte {
	// Bound temporary JSON allocations as well as the final wire envelope.
	if len(response.ContentType) > transportauth.MaxResponseBytes || len(response.SHA256) > transportauth.MaxResponseBytes || len(response.Error) > transportauth.MaxResponseBytes {
		return fileTransferDataplaneEncodingError()
	}
	if len(response.Payload) > fileTransferDataplaneChunkBytes {
		response.Payload = response.Payload[:fileTransferDataplaneChunkBytes]
		response.NextOffsetBytes = response.OffsetBytes + int64(len(response.Payload))
		response.Complete = false
	}
	encoded, err := json.Marshal(response)
	if err == nil && len(encoded) <= transportauth.MaxResponseBytes {
		return encoded
	}
	if response.Error == "" && len(response.Payload) > 0 {
		payload := response.Payload
		low, high := 0, len(payload)-1
		var best []byte
		for low <= high {
			n := low + (high-low)/2
			response.Payload = payload[:n]
			response.NextOffsetBytes = response.OffsetBytes + int64(n)
			response.Complete = false
			candidate, err := json.Marshal(response)
			if err == nil && len(candidate) <= transportauth.MaxResponseBytes {
				if n > 0 {
					best = candidate
				}
				low = n + 1
			} else {
				high = n - 1
			}
		}
		if best != nil {
			return best
		}
	}
	return fileTransferDataplaneEncodingError()
}

func fileTransferDataplaneEncodingError() []byte {
	// Do not send the oversized metadata/error back through a smaller envelope.
	encoded, _ := json.Marshal(fileTransferDataplaneResponse{
		Type:  "file-transfer-chunk-response",
		Error: "file transfer response metadata exceeds transport budget",
	})
	return encoded
}

func (a *Agent) exchangeFileTransferBlock(manager transportManagerForPackets, connection *ConnectionStatus, request fileTransferDataplaneRequest, deadline time.Time) (fileTransferDataplaneResponse, error) {
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) > transportauth.MaxMessageBytes {
		return fileTransferDataplaneResponse{}, errors.New("file transfer request exceeds transport budget")
	}
	var lastErr error
	stages := time.Duration(1)
	if strings.EqualFold(connection.TransportMode, "RELAY") {
		// Relay Exchange can wait once for a bind and again for its data ACK.
		stages = 2
	}
	for attempt := 0; attempt < fileTransferDataplaneAttempts; attempt++ {
		timeout := a.runtime.DirectProbeTimeout
		if timeout <= 0 {
			timeout = 300 * time.Millisecond
		}
		if timeout > time.Second/stages {
			timeout = time.Second / stages
		}
		if remaining := time.Until(deadline) / stages; remaining < timeout {
			timeout = remaining
		}
		if timeout <= 0 {
			return fileTransferDataplaneResponse{}, fmt.Errorf("%w: download deadline exceeded", errFileTransferInterrupted)
		}
		// Each Exchange allocates a fresh transport counter. Reading an offset is
		// idempotent; replaying the previous UDP record would be rejected instead.
		payload, err := manager.Exchange(connection.LocalPeerID, connection.RemotePeerID, encoded, timeout)
		if err != nil {
			if errors.Is(err, transportauth.ErrMessageTooLarge) || errors.Is(err, transportauth.ErrCounterExhausted) || errors.Is(err, transportauth.ErrInvalidRecord) {
				return fileTransferDataplaneResponse{}, err
			}
			lastErr = err
			continue
		}
		if len(payload) > transportauth.MaxResponseBytes {
			return fileTransferDataplaneResponse{}, errors.New("file transfer response exceeds transport budget")
		}
		var response fileTransferDataplaneResponse
		if json.Unmarshal(payload, &response) != nil || response.Type != "file-transfer-chunk-response" {
			return response, errors.New("invalid file transfer dataplane response")
		}
		if response.Error != "" {
			return response, fmt.Errorf("file transfer source: %s", response.Error)
		}
		return response, nil
	}
	return fileTransferDataplaneResponse{}, fmt.Errorf("%w: exchange failed after %d attempts: %w", errFileTransferInterrupted, fileTransferDataplaneAttempts, lastErr)
}

func validateFileTransferBlock(response fileTransferDataplaneResponse, request fileTransferDataplaneRequest, total int64, cache bool) error {
	n := int64(len(response.Payload))
	if request.OffsetBytes < 0 || request.OffsetBytes > total || response.TotalSizeBytes != total ||
		response.OffsetBytes != request.OffsetBytes || n > request.LimitBytes || n > total-request.OffsetBytes ||
		response.NextOffsetBytes != request.OffsetBytes+n {
		return errors.New("file transfer dataplane offset or size mismatch")
	}
	if response.Complete != (response.NextOffsetBytes == total) {
		return errors.New("file transfer dataplane completion mismatch")
	}
	if n == 0 && !response.Complete && !cache {
		return errors.New("file transfer dataplane made no progress")
	}
	return nil
}

func (a *Agent) downloadFileTransferFromConnectionLocked(transfer controlclient.FileTransfer, connection *ConnectionStatus, offsetBytes, limitBytes int64, deadline time.Time, cache bool) (*dataplaneFileTransferChunk, error) {
	if connection == nil {
		return nil, nil
	}
	manager := a.transportManagerForConnectionLocked(*connection)
	if manager == nil {
		return nil, nil
	}
	if offsetBytes < 0 || offsetBytes > transfer.SizeBytes {
		return nil, errors.New("file transfer download offset is invalid")
	}
	if limitBytes <= 0 || limitBytes > fileTransferAgentChunkBytes {
		limitBytes = fileTransferAgentChunkBytes
	}
	limitBytes = minInt64(limitBytes, transfer.SizeBytes-offsetBytes)
	content := &dataplaneFileTransferChunk{
		FileTransferContentChunk: &controlclient.FileTransferContentChunk{
			Transfer:    transfer,
			ContentType: firstNonEmptyString(strings.TrimSpace(transfer.ContentType), "application/octet-stream"),
			SHA256:      strings.TrimSpace(transfer.PayloadSHA256),
			Payload:     make([]byte, 0, limitBytes),
			OffsetBytes: offsetBytes, NextOffsetBytes: offsetBytes, TotalSizeBytes: transfer.SizeBytes,
			UploadedAtUnix: transfer.UploadedAtUnix, DownloadedAtUnix: transfer.DownloadedAtUnix,
		},
		LocalPeerID: connection.LocalPeerID, RemotePeerID: connection.RemotePeerID,
	}
	for block := 0; block < fileTransferDataplaneMaxBlocks; block++ {
		request := fileTransferDataplaneRequest{
			Type: "file-transfer-chunk-request", TransferID: transfer.ID,
			OffsetBytes: content.NextOffsetBytes,
			LimitBytes:  minInt64(fileTransferDataplaneChunkBytes, limitBytes-int64(len(content.Payload))),
		}
		response, err := a.exchangeFileTransferBlock(manager, connection, request, deadline)
		if err != nil {
			if len(content.Payload) > 0 && errors.Is(err, errFileTransferInterrupted) {
				// Preserve verified progress across a lost connection; the next
				// download resumes at exactly this offset.
				return content, nil
			}
			return nil, err
		}
		if err := validateFileTransferBlock(response, request, transfer.SizeBytes, cache); err != nil {
			return nil, err
		}
		if content.SHA256 != "" && response.SHA256 != content.SHA256 {
			return nil, errors.New("file transfer dataplane checksum metadata changed")
		}
		if block > 0 && (response.ContentType != content.ContentType || response.UploadedAtUnix != content.UploadedAtUnix || response.SHA256 != content.SHA256) {
			return nil, errors.New("file transfer dataplane metadata changed")
		}
		content.SHA256 = response.SHA256
		content.ContentType = response.ContentType
		content.UploadedAtUnix = response.UploadedAtUnix
		content.Payload = append(content.Payload, response.Payload...)
		content.NextOffsetBytes = response.NextOffsetBytes
		content.Complete = response.Complete
		if content.Complete || int64(len(content.Payload)) >= limitBytes {
			return content, nil
		}
		if len(response.Payload) == 0 {
			if len(content.Payload) > 0 {
				return content, nil
			}
			return nil, nil
		}
	}
	return content, nil
}
