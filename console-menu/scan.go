package consolemenu

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/letgo/scanner"
	"github.com/letgo/secretscanner"
)

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
	fmt.Println("This may take a few moments...")

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
		Timeout:         timeout,
		FollowRedirects: followRedirects,
	}

	// Create and run scanner
	fmt.Printf("\nScanning for exposed secrets on %s...\n", baseURL)
	fmt.Println("This may take a few moments...")

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
