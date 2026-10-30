//go:build !windows

package main

import "log"

func main() {
	log.Fatal("Ole desktop GUI client is currently supported on Windows builds only")
}
