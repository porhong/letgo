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

// List of required proxy files
var requiredProxyFiles = []string{
	"proxy/raw-proxy.txt",
	"proxy/proxy.txt",
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

	// Create proxy directory if it doesn't exist
	if _, err := os.Stat("proxy"); os.IsNotExist(err) {
		if err := os.Mkdir("proxy", 0755); err != nil {
			fmt.Printf("Error creating proxy directory: %v\n", err)
		} else {
			fmt.Println("Created proxy directory")
		}
	}

	// Create required proxy files
	for _, file := range requiredProxyFiles {
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
