//go:build windows

package main

import (
	"Ole/internal/agentservice"
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"
)

func main() {
	settings := agentservice.DefaultSettings()

	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Println("detect windows service mode:", err)
		os.Exit(1)
	}
	action, err := agentservice.ParseAction(os.Args[1:], isService)
	if err != nil {
		fmt.Println(err)
		fmt.Println("usage: ole-agent [install|uninstall|start|stop|status|console]")
		os.Exit(1)
	}

	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("resolve executable path:", err)
		os.Exit(1)
	}

	if err := agentservice.Execute(action, settings, exePath, nil); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
