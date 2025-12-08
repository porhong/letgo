package wordlist

import (
	"os"
	"strings"
)

// Generate creates a file with a predefined list of passwords.
func Generate(filename string) error {
	passwords := []string{
		"123456",
		"12345678",
		"123456789",
		"password",
		"qwerty",
		"111111",
	}

	content := strings.Join(passwords, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}
