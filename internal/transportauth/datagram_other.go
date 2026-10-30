//go:build !windows

package transportauth

import (
	"errors"
	"syscall"
)

func IsMessageSizeError(err error) bool { return errors.Is(err, syscall.EMSGSIZE) }
