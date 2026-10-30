//go:build windows

package transportauth

import (
	"errors"
	"golang.org/x/sys/windows"
)

func IsMessageSizeError(err error) bool { return errors.Is(err, windows.WSAEMSGSIZE) }
