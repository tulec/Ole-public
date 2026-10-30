//go:build !windows

package main

import "log"

func main() {
	log.Fatal("Ole agent is currently supported on Windows builds only")
}
