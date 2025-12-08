package main

import (
	"time"
	"github.com/letgo/console-menu"
	"github.com/letgo/cracker"
)

func main() {
	config := cracker.AttackConfig{
		MaxThreads:   10,
		Protocol:     "http",
		Port:         80,
		Timeout:      5 * time.Second,
		ShowAttempts: false,
	}

	menu := consolemenu.New(&config)

	for {
		menu.Display()
		if !menu.Process() {
			break
		}
	}
}
