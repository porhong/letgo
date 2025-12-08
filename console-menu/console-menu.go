package consolemenu

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/letgo/cracker"
	"github.com/letgo/scanner"
	"github.com/letgo/userlist"
	"github.com/letgo/wordlist"
)

// Menu represents the console menu
type Menu struct {
	Config          *cracker.AttackConfig
	DiscoveredEndpoints []scanner.EndpointResult
	resultMutex     sync.Mutex // For thread-safe result writing
}

// New creates a new menu
func New(config *cracker.AttackConfig) *Menu {
	return &Menu{Config: config}
}

// Display shows the main menu
func (m *Menu) Display() {
	fmt.Println("===== Password Cracker Menu ======")
	fmt.Println("1. Start Attack")
	fmt.Println("2. Scan for Login Endpoints")
	fmt.Println("3. Generate User List")
	fmt.Println("4. Generate Password List")
	fmt.Println("5. Exit")
	fmt.Print("Choose an option: ")
}

// Process handles the user's menu choice
func (m *Menu) Process() bool {
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		m.startAttack()
	case "2":
		m.scanEndpoints()
	case "3":
		m.generateUserList()
	case "4":
		m.generatePasswordList()
	case "5":
		fmt.Println("Exiting...")
		return false
	default:
		fmt.Println("Invalid option. Please try again.")
	}
	return true
}


// readValidURLs reads URLs from valid-url.txt file
func (m *Menu) readValidURLs() ([]string, error) {
	file, err := os.Open("valid-url.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to open valid-url.txt: %w", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading valid-url.txt: %w", err)
	}

	return urls, nil
}

// parseURL parses a URL string and extracts protocol, host, port, and path
func parseURL(urlStr string) (protocol, host string, port int, endpoint string, err error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", "", 0, "", fmt.Errorf("invalid URL format: %w", err)
	}

	protocol = parsedURL.Scheme
	if protocol == "" {
		protocol = "https"
	}

	host = parsedURL.Hostname()
	if host == "" {
		return "", "", 0, "", fmt.Errorf("missing host in URL")
	}

	// Extract port
	portStr := parsedURL.Port()
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return "", "", 0, "", fmt.Errorf("invalid port: %w", err)
		}
	} else {
		// Default ports
		if protocol == "https" {
			port = 443
		} else if protocol == "http" {
			port = 80
		} else {
			port = 80
		}
	}

	// Extract endpoint path
	endpoint = parsedURL.Path
	if endpoint == "" {
		endpoint = "/"
	}

	return protocol, host, port, endpoint, nil
}

// writeResult writes successful credentials to results.txt file (thread-safe)
func (m *Menu) writeResult(urlStr, username, password string) error {
	m.resultMutex.Lock()
	defer m.resultMutex.Unlock()

	file, err := os.OpenFile("results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open results.txt: %w", err)
	}
	defer file.Close()

	resultLine := fmt.Sprintf("%s|%s|%s\n", urlStr, username, password)
	if _, err := file.WriteString(resultLine); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}

	return nil
}

// startAttack initializes and runs the password cracking attack
func (m *Menu) startAttack() {
	reader := bufio.NewReader(os.Stdin)

	// Read URLs from valid-url.txt
	urls, err := m.readValidURLs()
	if err != nil {
		fmt.Printf("Error reading valid-url.txt: %v\n", err)
		fmt.Println("Please make sure valid-url.txt exists and contains valid URLs.")
		return
	}

	if len(urls) == 0 {
		fmt.Println("Error: valid-url.txt is empty. Please scan for endpoints first.")
		return
	}

	// Display URLs
	fmt.Println("\n===== Available URLs =====")
	for i, urlStr := range urls {
		fmt.Printf("[%d] %s\n", i+1, urlStr)
	}
	fmt.Println()

	// Ask user to select URL or attack all
	fmt.Print("Choose option:\n")
	fmt.Print("  [1] Select URL to attack\n")
	fmt.Print("  [2] Attack all URLs\n")
	fmt.Print("Enter choice (1 or 2): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var selectedURLs []string
	if choice == "1" {
		// Select single URL
		fmt.Print("Enter URL number: ")
		urlNumStr, _ := reader.ReadString('\n')
		urlNum, err := strconv.Atoi(strings.TrimSpace(urlNumStr))
		if err != nil || urlNum < 1 || urlNum > len(urls) {
			fmt.Println("Invalid URL number.")
			return
		}
		selectedURLs = []string{urls[urlNum-1]}
	} else if choice == "2" {
		// Attack all URLs
		selectedURLs = urls
	} else {
		fmt.Println("Invalid choice.")
		return
	}

	// Get attack configuration
	fmt.Println("\n===== Attack Configuration =====")
	
	fmt.Print("Enter Username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println("Error: Username is required.")
		return
	}

	fmt.Print("Enter Wordlist path: ")
	wordlist, _ := reader.ReadString('\n')
	wordlist = strings.TrimSpace(wordlist)
	if wordlist == "" {
		fmt.Println("Error: Wordlist path is required.")
		return
	}

	fmt.Print("Enter Max Threads (default: 100): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	maxThreads := 100
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			maxThreads = t
		}
	}

	fmt.Print("Enter Timeout in seconds (default: 5): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout := 5 * time.Second
	if timeoutStr != "" {
		if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
			timeout = time.Duration(t) * time.Second
		}
	}

	// Ask for login endpoint configuration
	fmt.Print("\nUse login endpoint (POST form/JSON)? (y/n, default: y): ")
	useLogin, _ := reader.ReadString('\n')
	useLogin = strings.TrimSpace(strings.ToLower(useLogin))
	useLoginEndpoint := useLogin != "n" && useLogin != "no"

	var endpoint, method, usernameField, passwordField, contentType string
	var successCodes []int
	var successKeywords, failureKeywords []string
	var followRedirects bool
	var customHeaders map[string]string

	if useLoginEndpoint {
		fmt.Print("Enter Endpoint path (press Enter to use path from URL): ")
		endpointInput, _ := reader.ReadString('\n')
		endpoint = strings.TrimSpace(endpointInput)
		// Will be set from URL if empty in the loop

		fmt.Print("Enter HTTP Method (GET/POST, default: POST): ")
		methodInput, _ := reader.ReadString('\n')
		method = strings.TrimSpace(strings.ToUpper(methodInput))
		if method == "" {
			method = "POST"
		}

		fmt.Print("Enter Username field name (default: username): ")
		usernameFieldInput, _ := reader.ReadString('\n')
		usernameField = strings.TrimSpace(usernameFieldInput)
		if usernameField == "" {
			usernameField = "username"
		}

		fmt.Print("Enter Password field name (default: password): ")
		passwordFieldInput, _ := reader.ReadString('\n')
		passwordField = strings.TrimSpace(passwordFieldInput)
		if passwordField == "" {
			passwordField = "password"
		}

		fmt.Print("Enter Content-Type (form-urlencoded/json, default: form-urlencoded): ")
		contentTypeInput, _ := reader.ReadString('\n')
		contentTypeInput = strings.TrimSpace(strings.ToLower(contentTypeInput))
		if contentTypeInput == "json" {
			contentType = "application/json"
		} else {
			contentType = "application/x-www-form-urlencoded"
		}

		fmt.Print("Enter Success HTTP codes (comma-separated, e.g., 200,302, or press Enter for auto-detect): ")
		successCodesStr, _ := reader.ReadString('\n')
		successCodesStr = strings.TrimSpace(successCodesStr)
		if successCodesStr != "" {
			codes := strings.Split(successCodesStr, ",")
			for _, codeStr := range codes {
				if code, err := strconv.Atoi(strings.TrimSpace(codeStr)); err == nil {
					successCodes = append(successCodes, code)
				}
			}
		}

		fmt.Print("Enter Success keywords in response (comma-separated, or press Enter to skip): ")
		successKeywordsStr, _ := reader.ReadString('\n')
		successKeywordsStr = strings.TrimSpace(successKeywordsStr)
		if successKeywordsStr != "" {
			successKeywords = strings.Split(successKeywordsStr, ",")
			for i := range successKeywords {
				successKeywords[i] = strings.TrimSpace(successKeywords[i])
			}
		}

		fmt.Print("Enter Failure keywords in response (comma-separated, or press Enter to skip): ")
		failureKeywordsStr, _ := reader.ReadString('\n')
		failureKeywordsStr = strings.TrimSpace(failureKeywordsStr)
		if failureKeywordsStr != "" {
			failureKeywords = strings.Split(failureKeywordsStr, ",")
			for i := range failureKeywords {
				failureKeywords[i] = strings.TrimSpace(failureKeywords[i])
			}
		}

		fmt.Print("Follow redirects? (y/n, default: n): ")
		followRedirectsStr, _ := reader.ReadString('\n')
		followRedirectsStr = strings.TrimSpace(strings.ToLower(followRedirectsStr))
		followRedirects = followRedirectsStr == "y" || followRedirectsStr == "yes"

		customHeaders = make(map[string]string)
		fmt.Print("Add custom headers? (y/n, default: n): ")
		addHeaders, _ := reader.ReadString('\n')
		addHeaders = strings.TrimSpace(strings.ToLower(addHeaders))
		if addHeaders == "y" || addHeaders == "yes" {
			for {
				fmt.Print("Enter header (format: Key:Value, or 'done' to finish): ")
				headerStr, _ := reader.ReadString('\n')
				headerStr = strings.TrimSpace(headerStr)
				if headerStr == "done" || headerStr == "" {
					break
				}
				parts := strings.SplitN(headerStr, ":", 2)
				if len(parts) == 2 {
					customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	// Start attacking URLs
	fmt.Println("\n===== Starting Attacks =====")
	successCount := 0
	totalURLs := len(selectedURLs)

	for i, urlStr := range selectedURLs {
		fmt.Printf("\n[%d/%d] Attacking: %s\n", i+1, totalURLs, urlStr)

		// Parse URL
		protocol, host, port, urlEndpoint, err := parseURL(urlStr)
		if err != nil {
			fmt.Printf("  ✗ Error parsing URL: %v\n", err)
			continue
		}

		// Use endpoint from URL if not specified by user
		actualEndpoint := endpoint
		if actualEndpoint == "" {
			actualEndpoint = urlEndpoint
		}

		// Create attack config
		attackConfig := cracker.AttackConfig{
			Target:          host,
			Username:        username,
			Wordlist:        wordlist,
			MaxThreads:      maxThreads,
			Protocol:        protocol,
			Port:            port,
			Timeout:         timeout,
			ShowAttempts:    false,
			Endpoint:        actualEndpoint,
			Method:          method,
			UsernameField:   usernameField,
			PasswordField:   passwordField,
			ContentType:     contentType,
			SuccessCodes:    successCodes,
			SuccessKeywords: successKeywords,
			FailureKeywords: failureKeywords,
			CustomHeaders:   customHeaders,
			FollowRedirects: followRedirects,
		}

		// Create password cracker
		pc := cracker.New(attackConfig)

		// Load wordlist
		if err := pc.LoadWordlist(); err != nil {
			fmt.Printf("  ✗ Error loading wordlist: %v\n", err)
			continue
		}

		// Start attack
		fmt.Printf("  → Threads: %d, Timeout: %v\n", maxThreads, timeout)
		found, password := pc.Start()

		if found {
			fmt.Printf("  ✓ Password found: %s\n", password)
			// Write result to file
			if err := m.writeResult(urlStr, username, password); err != nil {
				fmt.Printf("  ⚠ Warning: Failed to write result to file: %v\n", err)
			} else {
				fmt.Printf("  ✓ Result saved to results.txt\n")
			}
			successCount++
		} else {
			fmt.Printf("  ✗ Password not found.\n")
		}
	}

	// Summary
	fmt.Println("\n===== Attack Summary =====")
	fmt.Printf("Total URLs attacked: %d\n", totalURLs)
	fmt.Printf("Successful credentials found: %d\n", successCount)
	if successCount > 0 {
		fmt.Printf("Results saved to results.txt\n")
	}
	fmt.Println()
}

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

// scanEndpoints scans for login/auth endpoints on the target
func (m *Menu) scanEndpoints() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Base URL (e.g., https://example.com): ")
	baseURL, _ := reader.ReadString('\n')
	baseURL = strings.TrimSpace(baseURL)

	if baseURL == "" {
		fmt.Println("Error: Base URL is required.")
		return
	}

	// Parse URL to extract protocol, host, and port
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		fmt.Printf("Error: Invalid URL format: %v\n", err)
		return
	}

	// Set default protocol if missing
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
		baseURL = parsedURL.String()
	}

	// Extract port for scanner config (if needed)
	port := parsedURL.Port()
	protocol := parsedURL.Scheme

	// Set default port if not specified
	if port == "" {
		if protocol == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Ask for thread count
	fmt.Print("Enter number of threads for scanning (default: 10): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	threads := 10
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil {
			threads = t
		}
	}

	// Create scanner config
	scannerConfig := scanner.ScannerConfig{
		BaseURL:    baseURL,
		MaxThreads: threads,
		Timeout:    10 * time.Second,
	}

	// Create and run scanner
	fmt.Printf("\nScanning for login endpoints on %s...\n", baseURL)
	fmt.Println("This may take a few moments...\n")

	// Set up progress callback
	scannerConfig.OnProgress = func(scanned, total int, percentage float64) {
		// Use \r to overwrite the same line
		fmt.Printf("\rProgress: [%d/%d] %.1f%% - Scanning endpoints...", scanned, total, percentage)
	}

	scannerInstance := scanner.New(scannerConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := scannerInstance.Scan(ctx)
	
	// Clear the progress line and move to new line
	fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
	if err != nil {
		fmt.Printf("Error scanning endpoints: %v\n", err)
		return
	}

	discovered, validated := scannerInstance.GetStats()
	
	// Clear display with summary
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total Endpoints Scanned: %d\n", discovered)
	fmt.Printf("Endpoints Validated: %d\n", validated)
	fmt.Printf("Valid Login Endpoints Found: %d\n", len(results))
	fmt.Println(strings.Repeat("=", 70))

	if len(results) == 0 {
		fmt.Println("\n✗ No valid login endpoints found.")
		fmt.Println("  Try scanning with different parameters or check the target URL.")
		return
	}

	// Display discovered endpoints in a clean format
	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("VALID LOGIN ENDPOINTS (Ready for Brute Force Attack)")
	fmt.Println(strings.Repeat("-", 70))
	
	// Group endpoints by type
	loginPages := []scanner.EndpointResult{}
	loginForms := []scanner.EndpointResult{}
	otherEndpoints := []scanner.EndpointResult{}
	
	for _, result := range results {
		if result.HasLoginForm {
			loginForms = append(loginForms, result)
		} else if result.IsLoginPage {
			loginPages = append(loginPages, result)
		} else {
			otherEndpoints = append(otherEndpoints, result)
		}
	}
	
	// Display endpoints with login forms first (most useful)
	if len(loginForms) > 0 {
		fmt.Printf("\n[✓] Endpoints with Login Forms (%d):\n", len(loginForms))
		fmt.Println(strings.Repeat("-", 70))
		for i, result := range loginForms {
			statusColor := ""
			if result.StatusCode >= 200 && result.StatusCode < 300 {
				statusColor = "✓"
			} else if result.StatusCode >= 300 && result.StatusCode < 400 {
				statusColor = "→"
			} else {
				statusColor = "✗"
			}
			fmt.Printf("  [%d] %s\n", i+1, result.URL)
			fmt.Printf("      Method: %-6s | Status: %s %-3d | Type: Login Form\n", 
				result.Method, statusColor, result.StatusCode)
			if result.ContentType != "" {
				fmt.Printf("      Content-Type: %s\n", result.ContentType)
			}
			fmt.Println()
		}
	}
	
	// Display login pages
	if len(loginPages) > 0 {
		fmt.Printf("\n[!] Login Pages (%d):\n", len(loginPages))
		fmt.Println(strings.Repeat("-", 70))
		for i, result := range loginPages {
			statusColor := ""
			if result.StatusCode >= 200 && result.StatusCode < 300 {
				statusColor = "✓"
			} else if result.StatusCode >= 300 && result.StatusCode < 400 {
				statusColor = "→"
			} else {
				statusColor = "✗"
			}
			fmt.Printf("  [%d] %s\n", len(loginForms)+i+1, result.URL)
			fmt.Printf("      Method: %-6s | Status: %s %-3d | Type: Login Page\n", 
				result.Method, statusColor, result.StatusCode)
			if result.ContentType != "" {
				fmt.Printf("      Content-Type: %s\n", result.ContentType)
			}
			fmt.Println()
		}
	}
	
	// Display other endpoints
	if len(otherEndpoints) > 0 {
		fmt.Printf("\n[?] Other Potential Endpoints (%d):\n", len(otherEndpoints))
		fmt.Println(strings.Repeat("-", 70))
		for i, result := range otherEndpoints {
			statusColor := ""
			if result.StatusCode >= 200 && result.StatusCode < 300 {
				statusColor = "✓"
			} else if result.StatusCode >= 300 && result.StatusCode < 400 {
				statusColor = "→"
			} else {
				statusColor = "✗"
			}
			fmt.Printf("  [%d] %s\n", len(loginForms)+len(loginPages)+i+1, result.URL)
			fmt.Printf("      Method: %-6s | Status: %s %-3d\n", 
				result.Method, statusColor, result.StatusCode)
			if result.ContentType != "" {
				fmt.Printf("      Content-Type: %s\n", result.ContentType)
			}
			fmt.Println()
		}
	}

	// Store discovered endpoints
	m.DiscoveredEndpoints = results

	// Write valid endpoints to file
	if len(results) > 0 {
		if err := m.writeValidEndpointsToFile(results); err != nil {
			fmt.Printf("Warning: Failed to write valid endpoints to file: %v\n", err)
		} else {
			fmt.Printf("\n✓ Valid endpoints saved to valid-url.txt\n")
		}
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\nScan complete! Returning to main menu...")
	fmt.Println()
}

// writeValidEndpointsToFile writes valid endpoints to valid-url.txt
func (m *Menu) writeValidEndpointsToFile(results []scanner.EndpointResult) error {
	file, err := os.Create("valid-url.txt")
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write each valid endpoint URL to the file
	for _, result := range results {
		if _, err := writer.WriteString(result.URL + "\n"); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	return nil
}