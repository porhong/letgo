package userlist

import (
	"os"
	"strings"
)

// Generate creates a file with a predefined list of usernames.
func Generate(filename string) error {
	users := []string{
		"admin",
		"user",
		"test",
		"guest",
		"root",
		"administrator",
		"webmaster",
		"support",
		"info",
		"sales",
		"contact",
		"john.doe",
		"jane.doe",
		"smith",
		"demo",
	}

	content := strings.Join(users, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}
