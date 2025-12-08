package consolemenu

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/letgo/cracker"
	"github.com/letgo/userlist"
	"github.com/letgo/wordlist"
)

// Menu represents the console menu
type Menu struct {
	Config *cracker.AttackConfig
}

// New creates a new menu
func New(config *cracker.AttackConfig) *Menu {
	return &Menu{Config: config}
}

// Display shows the main menu
func (m *Menu) Display() {
	fmt.Println("===== Password Cracker Menu ======")
	fmt.Println("1. Configure Attack")
	fmt.Println("2. View Configuration")
	fmt.Println("3. Start Attack")
	fmt.Println("4. Generate User List")
	fmt.Println("5. Generate Password List")
	fmt.Println("6. Exit")
	fmt.Print("Choose an option: ")
}

// Process handles the user's menu choice
func (m *Menu) Process() bool {
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		m.configureAttack()
	case "2":
		m.viewConfiguration()
	case "3":
		m.startAttack()
	case "4":
		m.generateUserList()
	case "5":
		m.generatePasswordList()
	case "6":
		fmt.Println("Exiting...")
		return false
	default:
		fmt.Println("Invalid option. Please try again.")
	}
	return true
}

// configureAttack allows the user to set attack parameters
func (m *Menu) configureAttack() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Target: ")
	m.Config.Target, _ = reader.ReadString('\n')
	m.Config.Target = strings.TrimSpace(m.Config.Target)

	fmt.Print("Enter Username: ")
	m.Config.Username, _ = reader.ReadString('\n')
	m.Config.Username = strings.TrimSpace(m.Config.Username)

	fmt.Print("Enter Wordlist path: ")
	m.Config.Wordlist, _ = reader.ReadString('\n')
	m.Config.Wordlist = strings.TrimSpace(m.Config.Wordlist)

	fmt.Print("Enter Protocol (http, https, ssh, hash): ")
	m.Config.Protocol, _ = reader.ReadString('\n')
	m.Config.Protocol = strings.TrimSpace(m.Config.Protocol)

	fmt.Print("Enter Port: ")
	portStr, _ := reader.ReadString('\n')
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err == nil {
		m.Config.Port = port
	} else {
		fmt.Println("Invalid port, using default.")
	}

	fmt.Print("Enter Max Threads: ")
	threadsStr, _ := reader.ReadString('\n')
	threads, err := strconv.Atoi(strings.TrimSpace(threadsStr))
	if err == nil {
		m.Config.MaxThreads = threads
	} else {
		fmt.Println("Invalid thread count, using default.")
	}
}

// viewConfiguration displays the current attack configuration
func (m *Menu) viewConfiguration() {
	fmt.Println("===== Current Configuration ======")
	fmt.Printf("Target: %s\n", m.Config.Target)
	fmt.Printf("Username: %s\n", m.Config.Username)
	fmt.Printf("Wordlist: %s\n", m.Config.Wordlist)
	fmt.Printf("Protocol: %s\n", m.Config.Protocol)
	fmt.Printf("Port: %d\n", m.Config.Port)
	fmt.Printf("Max Threads: %d\n", m.Config.MaxThreads)
	fmt.Printf("Timeout: %v\n", m.Config.Timeout)
	fmt.Printf("Show Attempts: %v\n", m.Config.ShowAttempts)
}

// startAttack initializes and runs the password cracking attack
func (m *Menu) startAttack() {
	if m.Config.Target == "" || m.Config.Username == "" || m.Config.Wordlist == "" {
		fmt.Println("Error: Target, username, and wordlist must be configured before starting an attack.")
		return
	}

	pc := cracker.New(*m.Config)

	fmt.Printf("Loading wordlist from: %s\n", m.Config.Wordlist)
	if err := pc.LoadWordlist(); err != nil {
		fmt.Printf("Error loading wordlist: %v\n", err)
		return
	}

	fmt.Printf("Starting password cracking attack on %s://%s:%d for user '%s'...",
		m.Config.Protocol, m.Config.Target, m.Config.Port, m.Config.Username)
	fmt.Printf("Threads: %d, Timeout: %v\n", m.Config.MaxThreads, m.Config.Timeout)

	found, password := pc.Start()

	if found {
		fmt.Printf("\n✓ Password found: %s\n", password)
	} else {
		fmt.Println("\n✗ Password not found.")
	}
}

// generateUserList generates a user list file
func (m *Menu) generateUserList() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter filename for user list (e.g., users.txt): ")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	if err := userlist.Generate(filename); err != nil {
		fmt.Printf("Error generating user list: %v\n", err)
		return
	}
	fmt.Printf("User list generated and saved to %s\n", filename)
}

// generatePasswordList generates a password list file
func (m *Menu) generatePasswordList() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter filename for password list (e.g., passwords.txt): ")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	if err := wordlist.Generate(filename); err != nil {
		fmt.Printf("Error generating password list: %v\n", err)
		return
	}
	fmt.Printf("Password list generated and saved to %s\n", filename)
}