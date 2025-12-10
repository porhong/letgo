package main

import (
	"fmt"
	"os"
	"time"

	consolemenu "github.com/letgo/console-menu"
	"github.com/letgo/cracker"
)

// List of required .txt files
var requiredTxtFiles = []string{
	"users.txt",
	"passwords.txt",
	"cURL-Bruteforce.txt",
	"valid-url.txt",
	"results.txt",
	"cURL-DDOS.txt",
}

// Ensure all required .txt files exist, create if missing
func ensureTxtFilesExist() {
	for _, file := range requiredTxtFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			f, err := os.Create(file)
			if err != nil {
				fmt.Printf("Error creating %s: %v\n", file, err)
			} else {
				f.Close()
				fmt.Printf("Created missing file: %s\n", file)
			}
		}
	}
}

func main() {
	// Ensure all required .txt files exist
	ensureTxtFilesExist()

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
