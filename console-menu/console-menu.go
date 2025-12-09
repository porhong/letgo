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
	"github.com/letgo/curlparser"
	"github.com/letgo/scanner"
	"github.com/letgo/secretscanner"
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
	fmt.Println("3. Scan for Secrets/Env/Tokens")
	fmt.Println("4. Generate User List")
	fmt.Println("5. Generate Password List")
	fmt.Println("6. Attack with cURL Config")
	fmt.Println("7. Exit")
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
		m.scanSecrets()
	case "4":
		m.generateUserList()
	case "5":
		m.generatePasswordList()
	case "6":
		m.attackWithCurl()
	case "7":
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
	
	// Ask if using userlist or single username
	fmt.Print("Use userlist file? (y/n, default: n): ")
	useUserlist, _ := reader.ReadString('\n')
	useUserlist = strings.TrimSpace(strings.ToLower(useUserlist))
	
	var username, userlist string
	if useUserlist == "y" || useUserlist == "yes" {
		fmt.Print("Enter Userlist path (default: users.txt): ")
		userlist, _ = reader.ReadString('\n')
		userlist = strings.TrimSpace(userlist)
		if userlist == "" {
			userlist = "users.txt"
		}
	} else {
		fmt.Print("Enter Username: ")
		username, _ = reader.ReadString('\n')
		username = strings.TrimSpace(username)
		if username == "" {
			fmt.Println("Error: Username is required.")
			return
		}
	}

	fmt.Print("Enter Wordlist path (default: passwords.txt): ")
	wordlist, _ := reader.ReadString('\n')
	wordlist = strings.TrimSpace(wordlist)
	if wordlist == "" {
		wordlist = "passwords.txt"
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
			Userlist:        userlist,
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

		// Load userlist
		if err := pc.LoadUserlist(); err != nil {
			fmt.Printf("  ✗ Error loading userlist: %v\n", err)
			continue
		}

		// Load wordlist
		if err := pc.LoadWordlist(); err != nil {
			fmt.Printf("  ✗ Error loading wordlist: %v\n", err)
			continue
		}

		// Calculate total combinations and warn if too large
		totalUsers := len(pc.GetUserlist())
		totalPasswords := len(pc.GetWordlist())
		totalCombinations := totalUsers * totalPasswords
		
		fmt.Printf("  → Threads: %d, Timeout: %v\n", maxThreads, timeout)
		if userlist != "" {
			fmt.Printf("  → Testing %d users with %d passwords (%d total combinations)\n", totalUsers, totalPasswords, totalCombinations)
		} else {
			fmt.Printf("  → Testing 1 user with %d passwords\n", totalPasswords)
		}
		
		// Warn for large attacks
		if totalCombinations > 100000 {
			estimatedTime := float64(totalCombinations) / 1000.0 / 60.0 // Rough estimate at 1000/s
			fmt.Printf("  ⚠ WARNING: Large attack size! Estimated time: %.1f minutes\n", estimatedTime)
			fmt.Print("  Continue? (y/n): ")
			confirm, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
				fmt.Println("  Attack cancelled.")
				continue
			}
		}
		
		// Start attack
		found, credentials := pc.Start()

		if found {
			fmt.Printf("  ✓ Credentials found: %s\n", credentials)
			// Parse username:password
			parts := strings.SplitN(credentials, ":", 2)
			foundUsername := username
			foundPassword := credentials
			if len(parts) == 2 {
				foundUsername = parts[0]
				foundPassword = parts[1]
			}
			// Write result to file
			if err := m.writeResult(urlStr, foundUsername, foundPassword); err != nil {
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

	// Ask for target technology (optional filtering)
	fmt.Print("\nFilter by technology? (php/java/python/node/dotnet or Enter for auto-detect): ")
	techFilter, _ := reader.ReadString('\n')
	techFilter = strings.TrimSpace(strings.ToLower(techFilter))
	
	var targetLanguages []string
	if techFilter != "" {
		targetLanguages = []string{techFilter}
		fmt.Printf("✓ Will filter results for %s technology\n", strings.ToUpper(techFilter))
	} else {
		fmt.Println("✓ Auto-detect mode: will scan all technologies")
	}

	// Create scanner config
	scannerConfig := scanner.ScannerConfig{
		BaseURL:         baseURL,
		MaxThreads:      threads,
		Timeout:         10 * time.Second,
		TargetLanguages: targetLanguages,
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
	
	// Analyze detected technologies
	techStats := make(map[string]int)
	for _, result := range results {
		if result.DetectedLanguage != "" && result.DetectedLanguage != "unknown" {
			techStats[result.DetectedLanguage]++
		}
	}
	
	// Clear display with summary
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total Endpoints Scanned: %d\n", discovered)
	fmt.Printf("Endpoints Validated: %d\n", validated)
	fmt.Printf("Valid Login Endpoints Found: %d\n", len(results))
	
	// Display detected technologies
	if len(techStats) > 0 {
		fmt.Println("\nDetected Technologies:")
		for tech, count := range techStats {
			fmt.Printf("  • %s: %d endpoint(s)\n", strings.ToUpper(tech), count)
			fmt.Printf("    ℹ %s\n", getTechnologyRecommendations(tech))
		}
	}
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
			if result.DetectedLanguage != "" && result.DetectedLanguage != "unknown" {
				techInfo := strings.ToUpper(result.DetectedLanguage)
				if result.IsSSR {
					techInfo += " (SSR)"
				}
				fmt.Printf("      Technology: %s\n", techInfo)
			}
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
			if result.DetectedLanguage != "" && result.DetectedLanguage != "unknown" {
				techInfo := strings.ToUpper(result.DetectedLanguage)
				if result.IsSSR {
					techInfo += " (SSR)"
				}
				fmt.Printf("      Technology: %s\n", techInfo)
			}
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
			if result.DetectedLanguage != "" && result.DetectedLanguage != "unknown" {
				techInfo := strings.ToUpper(result.DetectedLanguage)
				if result.IsSSR {
					techInfo += " (SSR)"
				}
				fmt.Printf("      Technology: %s\n", techInfo)
			}
			if result.ContentType != "" {
				fmt.Printf("      Content-Type: %s\n", result.ContentType)
			}
			fmt.Println()
		}
	}

	// Store discovered endpoints
	m.DiscoveredEndpoints = results

	// Ask user if they want to filter by technology
	if len(techStats) > 1 {
		fmt.Println("\nWould you like to filter endpoints by technology?")
		fmt.Print("Enter technology to filter (or press Enter to keep all): ")
		filterInput, _ := reader.ReadString('\n')
		filterInput = strings.TrimSpace(strings.ToLower(filterInput))
		
		if filterInput != "" {
			filteredResults := []scanner.EndpointResult{}
			for _, result := range results {
				if strings.EqualFold(result.DetectedLanguage, filterInput) {
					filteredResults = append(filteredResults, result)
				}
			}
			if len(filteredResults) > 0 {
				results = filteredResults
				fmt.Printf("✓ Filtered to %d endpoint(s) with %s technology\n", len(results), strings.ToUpper(filterInput))
			} else {
				fmt.Printf("⚠ No endpoints found with %s technology, keeping all results\n", strings.ToUpper(filterInput))
			}
		}
	}

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

// scanSecrets scans for exposed environment variables, tokens, and configuration data
func (m *Menu) scanSecrets() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Base URL (e.g., https://example.com): ")
	baseURL, _ := reader.ReadString('\n')
	baseURL = strings.TrimSpace(baseURL)

	if baseURL == "" {
		fmt.Println("Error: Base URL is required.")
		return
	}

	// Parse URL to validate format
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

	// Ask for thread count
	fmt.Print("Enter number of threads for scanning (default: 10): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	threads := 10
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			threads = t
		}
	}

	// Ask for timeout
	fmt.Print("Enter timeout in seconds (default: 10): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout := 10 * time.Second
	if timeoutStr != "" {
		if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
			timeout = time.Duration(t) * time.Second
		}
	}

	// Ask if should follow redirects
	fmt.Print("Follow redirects? (y/n, default: y): ")
	followRedirectsStr, _ := reader.ReadString('\n')
	followRedirectsStr = strings.TrimSpace(strings.ToLower(followRedirectsStr))
	followRedirects := followRedirectsStr != "n" && followRedirectsStr != "no"

	// Create scanner config
	scannerConfig := secretscanner.ScannerConfig{
		BaseURL:         baseURL,
		MaxThreads:      threads,
		Timeout:          timeout,
		FollowRedirects: followRedirects,
	}

	// Create and run scanner
	fmt.Printf("\nScanning for exposed secrets on %s...\n", baseURL)
	fmt.Println("This may take a few moments...\n")

	scannerInstance := secretscanner.New(scannerConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := scannerInstance.Scan(ctx)
	if err != nil {
		fmt.Printf("Error scanning for secrets: %v\n", err)
		return
	}

	scanned := scannerInstance.GetStats()

	// Display results
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    SECRET SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("URLs Scanned: %d\n", scanned)
	fmt.Printf("Secrets Found: %d\n", len(results))
	fmt.Println(strings.Repeat("=", 70))

	if len(results) == 0 {
		fmt.Println("\n✓ No exposed secrets found.")
		fmt.Println("  The application appears to be properly secured.")
		fmt.Println()
		return
	}

	// Group results by type and severity
	resultsByType := make(map[string][]secretscanner.ScanResult)
	resultsBySeverity := make(map[string][]secretscanner.ScanResult)

	for _, result := range results {
		resultsByType[result.Type] = append(resultsByType[result.Type], result)
		resultsBySeverity[result.Severity] = append(resultsBySeverity[result.Severity], result)
	}

	// Display summary by severity
	fmt.Println("\nSummary by Severity:")
	fmt.Println(strings.Repeat("-", 70))
	if high := resultsBySeverity["high"]; len(high) > 0 {
		fmt.Printf("  [HIGH]   %d finding(s) - Immediate action required!\n", len(high))
	}
	if medium := resultsBySeverity["medium"]; len(medium) > 0 {
		fmt.Printf("  [MEDIUM] %d finding(s) - Review recommended\n", len(medium))
	}
	if low := resultsBySeverity["low"]; len(low) > 0 {
		fmt.Printf("  [LOW]    %d finding(s) - Monitor and review\n", len(low))
	}

	// Display summary by type
	fmt.Println("\nSummary by Type:")
	fmt.Println(strings.Repeat("-", 70))
	for _, resultType := range []string{"env", "token", "api_key", "credential", "config"} {
		if results := resultsByType[resultType]; len(results) > 0 {
			fmt.Printf("  [%s] %d finding(s)\n", strings.ToUpper(resultType), len(results))
		}
	}

	// Display detailed findings
	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("DETAILED FINDINGS")
	fmt.Println(strings.Repeat("-", 70))

	// Display high severity first
	if highResults := resultsBySeverity["high"]; len(highResults) > 0 {
		fmt.Println("\n[!] HIGH SEVERITY FINDINGS:")
		for i, result := range highResults {
			fmt.Printf("\n  [%d] %s\n", i+1, result.URL)
			fmt.Printf("      Type: %s | Severity: %s\n", strings.ToUpper(result.Type), strings.ToUpper(result.Severity))
			fmt.Printf("      Location: %s\n", result.Location)
			if result.FilePath != "" {
				fmt.Printf("      File: %s\n", result.FilePath)
			}
			fmt.Printf("      Pattern: %s\n", result.Pattern)
			if result.Value != "" {
				fmt.Printf("      Value: %s\n", result.Value)
			}
			fmt.Printf("      Description: %s\n", result.Description)
		}
	}

	// Display medium severity
	if mediumResults := resultsBySeverity["medium"]; len(mediumResults) > 0 {
		fmt.Println("\n[!] MEDIUM SEVERITY FINDINGS:")
		for i, result := range mediumResults {
			fmt.Printf("\n  [%d] %s\n", i+1, result.URL)
			fmt.Printf("      Type: %s | Severity: %s\n", strings.ToUpper(result.Type), strings.ToUpper(result.Severity))
			fmt.Printf("      Location: %s\n", result.Location)
			if result.FilePath != "" {
				fmt.Printf("      File: %s\n", result.FilePath)
			}
			fmt.Printf("      Pattern: %s\n", result.Pattern)
			if result.Value != "" {
				fmt.Printf("      Value: %s\n", result.Value)
			}
			fmt.Printf("      Description: %s\n", result.Description)
		}
	}

	// Display low severity
	if lowResults := resultsBySeverity["low"]; len(lowResults) > 0 {
		fmt.Println("\n[!] LOW SEVERITY FINDINGS:")
		for i, result := range lowResults {
			fmt.Printf("\n  [%d] %s\n", i+1, result.URL)
			fmt.Printf("      Type: %s | Severity: %s\n", strings.ToUpper(result.Type), strings.ToUpper(result.Severity))
			fmt.Printf("      Location: %s\n", result.Location)
			if result.FilePath != "" {
				fmt.Printf("      File: %s\n", result.FilePath)
			}
			fmt.Printf("      Pattern: %s\n", result.Pattern)
			if result.Value != "" {
				fmt.Printf("      Value: %s\n", result.Value)
			}
			fmt.Printf("      Description: %s\n", result.Description)
		}
	}

	// Ask if user wants to save results
	fmt.Print("\nSave results to file? (y/n, default: y): ")
	saveStr, _ := reader.ReadString('\n')
	saveStr = strings.TrimSpace(strings.ToLower(saveStr))
	if saveStr != "n" && saveStr != "no" {
		if err := m.writeSecretResultsToFile(results); err != nil {
			fmt.Printf("Warning: Failed to write results to file: %v\n", err)
		} else {
			fmt.Printf("✓ Results saved to secrets-found.txt\n")
		}
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\nScan complete! Returning to main menu...")
	fmt.Println()
}

// writeSecretResultsToFile writes secret scan results to a file
func (m *Menu) writeSecretResultsToFile(results []secretscanner.ScanResult) error {
	file, err := os.Create("secrets-found.txt")
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := fmt.Sprintf("%s\n%s\n%s\n\n",
		strings.Repeat("=", 70),
		"SECRET SCAN RESULTS",
		strings.Repeat("=", 70))
	if _, err := writer.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Group by severity
	resultsBySeverity := make(map[string][]secretscanner.ScanResult)
	for _, result := range results {
		resultsBySeverity[result.Severity] = append(resultsBySeverity[result.Severity], result)
	}

	// Write results grouped by severity
	for _, severity := range []string{"high", "medium", "low"} {
		if severityResults := resultsBySeverity[severity]; len(severityResults) > 0 {
			severityHeader := fmt.Sprintf("\n[%s] SEVERITY FINDINGS (%d):\n%s\n",
				strings.ToUpper(severity), len(severityResults), strings.Repeat("-", 70))
			if _, err := writer.WriteString(severityHeader); err != nil {
				return fmt.Errorf("failed to write severity header: %w", err)
			}

			for i, result := range severityResults {
				resultLine := fmt.Sprintf("\n[%d] %s\n", i+1, result.URL)
				resultLine += fmt.Sprintf("    Type: %s | Severity: %s\n", strings.ToUpper(result.Type), strings.ToUpper(result.Severity))
				resultLine += fmt.Sprintf("    Location: %s\n", result.Location)
				if result.FilePath != "" {
					resultLine += fmt.Sprintf("    File: %s\n", result.FilePath)
				}
				resultLine += fmt.Sprintf("    Pattern: %s\n", result.Pattern)
				if result.Value != "" {
					resultLine += fmt.Sprintf("    Value: %s\n", result.Value)
				}
				resultLine += fmt.Sprintf("    Description: %s\n", result.Description)
				resultLine += "\n"

				if _, err := writer.WriteString(resultLine); err != nil {
					return fmt.Errorf("failed to write result: %w", err)
				}
			}
		}
	}

	return nil
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

// getTechnologyRecommendations returns attack strategy recommendations based on detected technology
func getTechnologyRecommendations(tech string) string {
	recommendations := map[string]string{
		"php":     "Common endpoints: /login.php, /admin.php | Default form fields: username, password",
		"java":    "Common endpoints: /j_security_check, /login.do | Watch for session tokens",
		"python":  "Django/Flask detected | Look for csrfmiddlewaretoken in forms",
		"dotnet":  "ASP.NET detected | Common endpoints: /Account/Login.aspx | Check for ViewState",
		"nextjs":  "Next.js (SSR) detected | API routes at /api/auth/* | May use JSON authentication",
		"nuxtjs":  "Nuxt.js (SSR) detected | API routes at /api/* | May use JSON authentication",
		"angular": "Angular (SPA) detected | Likely uses REST API | Check /api/login endpoints",
		"react":   "React (SPA) detected | Likely uses REST API | Check /api/auth endpoints",
		"vue":     "Vue.js detected | Likely uses REST API | Check /api/login endpoints",
		"node":    "Node.js/Express detected | Check for express session cookies",
		"ruby":    "Ruby on Rails detected | CSRF token required | Check /users/sign_in",
	}
	
	if rec, ok := recommendations[strings.ToLower(tech)]; ok {
		return rec
	}
	return "No specific recommendations available"
}

// attackWithCurl performs an attack using cURL configuration from a file
func (m *Menu) attackWithCurl() {
	reader := bufio.NewReader(os.Stdin)

	// Ask for cURL file path
	fmt.Print("\nEnter cURL config file path (default: cURL.txt): ")
	curlFile, _ := reader.ReadString('\n')
	curlFile = strings.TrimSpace(curlFile)
	if curlFile == "" {
		curlFile = "cURL.txt"
	}

	// Load cURL configurations from file
	curlConfigs, err := curlparser.LoadFromFile(curlFile)
	if err != nil {
		fmt.Printf("Error loading cURL config: %v\n", err)
		fmt.Println("Please make sure the file exists and contains valid cURL commands.")
		fmt.Println("\nExample cURL.txt format:")
		fmt.Println("  curl -X POST https://example.com/login \\")
		fmt.Println("    -H 'Content-Type: application/json' \\")
		fmt.Println("    -d '{\"username\":\"test\",\"password\":\"test\"}'")
		fmt.Println()
		return
	}

	fmt.Printf("\n✓ Found %d cURL configuration(s)\n\n", len(curlConfigs))

	// Display found configurations
	fmt.Println("===== Found cURL Configurations =====")
	for i, config := range curlConfigs {
		fmt.Printf("[%d] %s %s\n", i+1, config.Method, config.URL)
		if config.ContentType != "" {
			fmt.Printf("    Content-Type: %s\n", config.ContentType)
		}
		if len(config.Headers) > 0 {
			fmt.Printf("    Headers: %d custom header(s)\n", len(config.Headers))
		}
		if config.Data != "" {
			// Extract field names
			usernameField, passwordField, fields := curlparser.ExtractFieldsFromData(config.Data, config.ContentType)
			fmt.Printf("    Detected fields: username='%s', password='%s'\n", usernameField, passwordField)
			if len(fields) > 2 {
				fmt.Printf("    Additional fields: %d\n", len(fields)-2)
			}
		}
		fmt.Println()
	}

	// Ask which config to use
	var selectedConfigs []*curlparser.CurlConfig
	if len(curlConfigs) == 1 {
		selectedConfigs = curlConfigs
		fmt.Println("Using the only available cURL configuration.")
	} else {
		fmt.Print("Choose option:\n")
		fmt.Print("  [1] Select specific configuration\n")
		fmt.Print("  [2] Use all configurations\n")
		fmt.Print("Enter choice (1 or 2): ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "1" {
			fmt.Print("Enter configuration number: ")
			numStr, _ := reader.ReadString('\n')
			num, err := strconv.Atoi(strings.TrimSpace(numStr))
			if err != nil || num < 1 || num > len(curlConfigs) {
				fmt.Println("Invalid configuration number.")
				return
			}
			selectedConfigs = []*curlparser.CurlConfig{curlConfigs[num-1]}
		} else if choice == "2" {
			selectedConfigs = curlConfigs
		} else {
			fmt.Println("Invalid choice.")
			return
		}
	}

	// Get common attack parameters
	fmt.Println("\n===== Attack Configuration =====")
	
	// Ask if using userlist or single username
	fmt.Print("Use userlist file? (y/n, default: n): ")
	useUserlist, _ := reader.ReadString('\n')
	useUserlist = strings.TrimSpace(strings.ToLower(useUserlist))
	
	var username, userlist string
	if useUserlist == "y" || useUserlist == "yes" {
		fmt.Print("Enter Userlist path (default: users.txt): ")
		userlist, _ = reader.ReadString('\n')
		userlist = strings.TrimSpace(userlist)
		if userlist == "" {
			userlist = "users.txt"
		}
	} else {
		fmt.Print("Enter Username: ")
		username, _ = reader.ReadString('\n')
		username = strings.TrimSpace(username)
		if username == "" {
			fmt.Println("Error: Username is required.")
			return
		}
	}

	fmt.Print("Enter Wordlist path (default: passwords.txt): ")
	wordlist, _ := reader.ReadString('\n')
	wordlist = strings.TrimSpace(wordlist)
	if wordlist == "" {
		wordlist = "passwords.txt"
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

	// Optional: Override success/failure detection
	fmt.Print("\nEnter Success HTTP codes (comma-separated, or press Enter for auto-detect): ")
	successCodesStr, _ := reader.ReadString('\n')
	successCodesStr = strings.TrimSpace(successCodesStr)
	var successCodes []int
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
	var successKeywords []string
	if successKeywordsStr != "" {
		successKeywords = strings.Split(successKeywordsStr, ",")
		for i := range successKeywords {
			successKeywords[i] = strings.TrimSpace(successKeywords[i])
		}
	}

	fmt.Print("Enter Failure keywords in response (comma-separated, or press Enter to skip): ")
	failureKeywordsStr, _ := reader.ReadString('\n')
	failureKeywordsStr = strings.TrimSpace(failureKeywordsStr)
	var failureKeywords []string
	if failureKeywordsStr != "" {
		failureKeywords = strings.Split(failureKeywordsStr, ",")
		for i := range failureKeywords {
			failureKeywords[i] = strings.TrimSpace(failureKeywords[i])
		}
	}

	// Start attacks
	fmt.Println("\n===== Starting Attacks =====")
	successCount := 0
	totalConfigs := len(selectedConfigs)

	for i, curlConfig := range selectedConfigs {
		fmt.Printf("\n[%d/%d] Attacking: %s %s\n", i+1, totalConfigs, curlConfig.Method, curlConfig.URL)

		// Convert cURL config to attack config
		attackConfig, err := curlConfig.ToAttackConfig()
		if err != nil {
			fmt.Printf("  ✗ Error converting config: %v\n", err)
			continue
		}

		// Apply user-provided parameters
		attackConfig.Username = username
		attackConfig.Userlist = userlist
		attackConfig.Wordlist = wordlist
		attackConfig.MaxThreads = maxThreads
		attackConfig.ShowAttempts = false
		
		if len(successCodes) > 0 {
			attackConfig.SuccessCodes = successCodes
		}
		if len(successKeywords) > 0 {
			attackConfig.SuccessKeywords = successKeywords
		}
		if len(failureKeywords) > 0 {
			attackConfig.FailureKeywords = failureKeywords
		}

		// Display configuration details
		fmt.Printf("  → Endpoint: %s\n", attackConfig.Endpoint)
		fmt.Printf("  → Method: %s\n", attackConfig.Method)
		fmt.Printf("  → Content-Type: %s\n", attackConfig.ContentType)
		fmt.Printf("  → Username field: %s\n", attackConfig.UsernameField)
		fmt.Printf("  → Password field: %s\n", attackConfig.PasswordField)
		fmt.Printf("  → Threads: %d, Timeout: %v\n", maxThreads, attackConfig.Timeout)
		if len(attackConfig.CustomHeaders) > 0 {
			fmt.Printf("  → Custom headers: %d\n", len(attackConfig.CustomHeaders))
		}

		// Create password cracker
		pc := cracker.New(*attackConfig)

		// Load userlist
		if err := pc.LoadUserlist(); err != nil {
			fmt.Printf("  ✗ Error loading userlist: %v\n", err)
			continue
		}

		// Load wordlist
		if err := pc.LoadWordlist(); err != nil {
			fmt.Printf("  ✗ Error loading wordlist: %v\n", err)
			continue
		}

		// Calculate total combinations and warn if too large
		totalUsers := len(pc.GetUserlist())
		totalPasswords := len(pc.GetWordlist())
		totalCombinations := totalUsers * totalPasswords
		
		if userlist != "" {
			fmt.Printf("  → Testing %d users with %d passwords (%d total combinations)\n", totalUsers, totalPasswords, totalCombinations)
		} else {
			fmt.Printf("  → Testing 1 user with %d passwords\n", totalPasswords)
		}
		
		// Warn for large attacks
		if totalCombinations > 100000 {
			estimatedTime := float64(totalCombinations) / 1000.0 / 60.0 // Rough estimate at 1000/s
			fmt.Printf("  ⚠ WARNING: Large attack size! Estimated time: %.1f minutes\n", estimatedTime)
			fmt.Print("  Continue? (y/n): ")
			confirm, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
				fmt.Println("  Attack cancelled.")
				continue
			}
		}

		// Start attack
		found, credentials := pc.Start()

		if found {
			fmt.Printf("  ✓ Credentials found: %s\n", credentials)
			// Parse username:password
			parts := strings.SplitN(credentials, ":", 2)
			foundUsername := username
			foundPassword := credentials
			if len(parts) == 2 {
				foundUsername = parts[0]
				foundPassword = parts[1]
			}
			// Write result to file
			if err := m.writeResult(curlConfig.URL, foundUsername, foundPassword); err != nil {
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
	fmt.Printf("Total configurations attacked: %d\n", totalConfigs)
	fmt.Printf("Successful credentials found: %d\n", successCount)
	if successCount > 0 {
		fmt.Printf("Results saved to results.txt\n")
	}
	fmt.Println()
}