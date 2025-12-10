package consolemenu

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/letgo/cracker"
	"github.com/letgo/scanner"
)

// Menu represents the console menu
type Menu struct {
	Config              *cracker.AttackConfig
	DiscoveredEndpoints []scanner.EndpointResult
	resultMutex         sync.Mutex // For thread-safe result writing
}

// New creates a new menu
func New(config *cracker.AttackConfig) *Menu {
	return &Menu{Config: config}
}

// Display shows the main menu
func (m *Menu) Display() {
	fmt.Println("===== Password Cracker Menu ======")
	fmt.Println("[Scan]")
	fmt.Println("  1) Scan for Login Endpoints")
	fmt.Println("  2) Scan for Secrets/Env/Tokens")
	fmt.Println("[Generate]")
	fmt.Println("  3) Generate User List")
	fmt.Println("  4) Generate Password List")
	fmt.Println("[Attack]")
	fmt.Println("  5) Attack Brute force with cURL")
	fmt.Println("  6) DDoS Attack (cURL)")
	fmt.Println("[Proxy]")
	fmt.Println("  7) Scrape Proxies")
	fmt.Println("  8) Validate Proxies")
	fmt.Println("  9) Exit")
	fmt.Print("Choose an option [1-9]: ")
}

// Process handles the user's menu choice
func (m *Menu) Process() bool {
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		m.scanEndpoints()
	case "2":
		m.scanSecrets()
	case "3":
		m.generateUserList()
	case "4":
		m.generatePasswordList()
	case "5":
		m.attackWithCurl()
	case "6":
		m.ddosAttack()
	case "7":
		m.scrapeProxies()
	case "8":
		m.validateProxies()
	case "9":
		fmt.Println("Exiting...")
		return false
	default:
		fmt.Println("Invalid option. Please try again.")
	}
	return true
}
