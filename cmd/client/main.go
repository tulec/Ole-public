//go:build windows

package main

import (
	"Ole/internal/clientgui"
	"log"
)

func main() {
	if err := clientgui.Run(); err != nil {
		log.Fatal(err)
	}
}
