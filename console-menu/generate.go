package consolemenu

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/letgo/userlist"
	"github.com/letgo/wordlist"
)

// generateUserList generates a user list file
func (m *Menu) generateUserList() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter filename for user list (e.g., users.txt): ")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	fmt.Print("Enter amount to generate (0 for all, default: 0): ")
	countStr, _ := reader.ReadString('\n')
	countStr = strings.TrimSpace(countStr)
	count := 0
	if countStr != "" {
		if c, err := strconv.Atoi(countStr); err == nil && c > 0 {
			count = c
		}
	}

	if err := userlist.Generate(filename, count); err != nil {
		fmt.Printf("Error generating user list: %v\n", err)
		return
	}
	if count > 0 {
		fmt.Printf("User list with %d entries generated and saved to %s\n", count, filename)
	} else {
		fmt.Printf("User list generated and saved to %s\n", filename)
	}
}

// generatePasswordList generates a password list file
func (m *Menu) generatePasswordList() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter filename for password list (e.g., passwords.txt): ")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	fmt.Print("Enter amount to generate (0 for all, default: 0): ")
	countStr, _ := reader.ReadString('\n')
	countStr = strings.TrimSpace(countStr)
	count := 0
	if countStr != "" {
		if c, err := strconv.Atoi(countStr); err == nil && c > 0 {
			count = c
		}
	}

	if err := wordlist.Generate(filename, count); err != nil {
		fmt.Printf("Error generating password list: %v\n", err)
		return
	}
	if count > 0 {
		fmt.Printf("Password list with %d entries generated and saved to %s\n", count, filename)
	} else {
		fmt.Printf("Password list generated and saved to %s\n", filename)
	}
}
