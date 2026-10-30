//go:build !windows

package clientgui

import "fmt"

func Run() error {
	return fmt.Errorf("Ole desktop GUI client is available on Windows only")
}
