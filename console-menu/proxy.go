package consolemenu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/letgo/proxy"
)

// scrapeProxies handles the proxy scraping menu option
func (m *Menu) scrapeProxies() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n[Proxy Scraper]")
	fmt.Println("This will scrape proxies from multiple free sources.")

	// Get threads configuration
	fmt.Print("Enter Max Threads (default: 50): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	maxThreads := 50
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			maxThreads = t
		}
	}

	// Get timeout configuration
	fmt.Print("Enter Timeout in seconds (default: 15): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout := 15 * time.Second
	if timeoutStr != "" {
		if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
			timeout = time.Duration(t) * time.Second
		}
	}

	// Create scraper config
	config := proxy.ProxyScraperConfig{
		MaxThreads: maxThreads,
		Timeout:    timeout,
		OnProgress: func(scraped, total int, percentage float64) {
			fmt.Printf("\r[Scraping] Progress: [%d/%d] %.1f%% sources scraped", scraped, total, percentage)
		},
	}

	fmt.Printf("\nStarting proxy scraping with %d threads...\n", maxThreads)
	scraper := proxy.New(config)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := scraper.Scrape(ctx)

	// Clear progress line
	fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")

	if err != nil {
		fmt.Printf("Error during scraping: %v\n", err)
		return
	}

	if len(results) == 0 {
		fmt.Println("No proxies found.")
		return
	}

	fmt.Printf("Successfully scraped %d proxies.\n", len(results))

	// Remove duplicates
	fmt.Println("Removing duplicates...")
	uniqueProxies := proxy.RemoveDuplicates(results)
	duplicatesRemoved := len(results) - len(uniqueProxies)
	fmt.Printf("Removed %d duplicates. Total unique proxies: %d\n", duplicatesRemoved, len(uniqueProxies))

	// Display protocol breakdown
	protocolCount := make(map[string]int)
	for _, p := range uniqueProxies {
		protocolCount[p.Protocol]++
	}

	fmt.Println("\nProxy breakdown by protocol:")
	for protocol, count := range protocolCount {
		fmt.Printf("  %s: %d\n", strings.ToUpper(protocol), count)
	}

	// Write to file
	fmt.Println("\nSaving proxies to proxy/raw-proxy.txt...")
	if err := m.writeProxiesToFile(uniqueProxies, "proxy/raw-proxy.txt"); err != nil {
		fmt.Printf("Error: Failed to save proxies: %v\n", err)
		return
	}

	fmt.Println("✓ Proxies saved successfully!")
	fmt.Println("\nNext step: Use 'Validate Proxies' to test which proxies are working.")
}

// validateProxies handles the proxy validation menu option
func (m *Menu) validateProxies() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n[Proxy Validator]")
	fmt.Println("This will test proxies from proxy/raw-proxy.txt and save working ones.")

	// Check if raw-proxy.txt exists
	if _, err := os.Stat("proxy/raw-proxy.txt"); os.IsNotExist(err) {
		fmt.Println("Error: proxy/raw-proxy.txt not found.")
		fmt.Println("Please run 'Scrape Proxies' first.")
		return
	}

	// Load proxies from file
	fmt.Println("\nLoading proxies from proxy/raw-proxy.txt...")
	proxies, err := loadProxiesFromFile("proxy/raw-proxy.txt")
	if err != nil {
		fmt.Printf("Error: Failed to load proxies: %v\n", err)
		return
	}

	if len(proxies) == 0 {
		fmt.Println("No proxies found in proxy/raw-proxy.txt")
		return
	}

	fmt.Printf("Loaded %d proxies to validate.\n", len(proxies))

	// Get threads configuration
	fmt.Print("Enter Max Threads (default: 20): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	maxThreads := 20
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			maxThreads = t
		}
	}

	// Get timeout configuration
	fmt.Print("Enter Timeout in seconds (default: 10): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout := 10 * time.Second
	if timeoutStr != "" {
		if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
			timeout = time.Duration(t) * time.Second
		}
	}

	// Clear proxy.txt before validation starts
	fmt.Println("\nPreparing proxy/proxy.txt for incremental writing...")
	if err := m.clearProxyFile("proxy/proxy.txt"); err != nil {
		fmt.Printf("Error: Failed to prepare file: %v\n", err)
		return
	}

	// Track valid proxy count and remaining count
	var validCount int32
	var remainingCount = int32(len(proxies))

	// Create validator config with incremental writing and real-time removal
	config := proxy.ProxyScraperConfig{
		MaxThreads: maxThreads,
		Timeout:    timeout,
		OnProgress: func(validated, total int, percentage float64) {
			fmt.Printf("\r[Validating] Progress: [%d/%d] %.1f%% | Valid: %d | Remaining in raw-proxy.txt: %d",
				validated, total, percentage, atomic.LoadInt32(&validCount), atomic.LoadInt32(&remainingCount))
		},
		OnValidProxy: func(p proxy.ProxyResult) {
			// Write valid proxy immediately
			if err := m.appendProxyToFile(p, "proxy/proxy.txt"); err == nil {
				atomic.AddInt32(&validCount, 1)
			}
		},
		OnProxyValidated: func(p proxy.ProxyResult) {
			// Remove validated proxy from raw-proxy.txt immediately (whether valid or not)
			if err := m.removeProxyFromRawFile(p); err == nil {
				atomic.AddInt32(&remainingCount, -1)
			}
		},
	}

	fmt.Printf("\nStarting proxy validation with %d threads...\n", maxThreads)
	fmt.Println("Valid proxies will be saved to proxy/proxy.txt in real-time.")
	fmt.Println("Validated proxies will be removed from proxy/raw-proxy.txt in real-time.")
	fmt.Println("This may take a while depending on the number of proxies...")

	validator := proxy.NewValidator(config)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	validProxies, err := validator.ValidateProxies(ctx, proxies)

	// Clear progress line
	fmt.Print("\r" + strings.Repeat(" ", 120) + "\r")

	if err != nil {
		fmt.Printf("Error during validation: %v\n", err)
		fmt.Printf("Note: %d valid proxies were already saved to proxy/proxy.txt\n", atomic.LoadInt32(&validCount))
		return
	}

	successRate := 0.0
	if len(proxies) > 0 {
		successRate = float64(len(validProxies)) / float64(len(proxies)) * 100
	}

	fmt.Printf("\nValidation complete!\n")
	fmt.Printf("  Total tested: %d\n", len(proxies))
	fmt.Printf("  Working: %d\n", len(validProxies))
	fmt.Printf("  Failed: %d\n", len(proxies)-len(validProxies))
	fmt.Printf("  Success rate: %.1f%%\n", successRate)

	if len(validProxies) == 0 {
		fmt.Println("\nNo working proxies found.")
		return
	}

	// Display protocol breakdown
	protocolCount := make(map[string]int)
	for _, p := range validProxies {
		protocolCount[p.Protocol]++
	}

	fmt.Println("\nWorking proxies by protocol:")
	for protocol, count := range protocolCount {
		fmt.Printf("  %s: %d\n", strings.ToUpper(protocol), count)
	}

	fmt.Printf("\n✓ All %d working proxies have been saved to proxy/proxy.txt\n", len(validProxies))
	fmt.Printf("✓ All validated proxies have been removed from proxy/raw-proxy.txt\n")
	fmt.Println("You can now use these proxies for attacks (future feature).")
}

// loadProxiesFromFile loads proxies from a file
func loadProxiesFromFile(filename string) ([]proxy.ProxyResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []proxy.ProxyResult
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse format: protocol://host:port
		parts := strings.SplitN(line, "://", 2)
		if len(parts) != 2 {
			continue
		}

		protocol := parts[0]
		hostPort := parts[1]

		hostPortParts := strings.Split(hostPort, ":")
		if len(hostPortParts) != 2 {
			continue
		}

		proxies = append(proxies, proxy.ProxyResult{
			Protocol: protocol,
			Host:     hostPortParts[0],
			Port:     hostPortParts[1],
			IsValid:  false,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return proxies, nil
}

// clearProxyFile initializes the proxy file with header if it doesn't exist or is empty
func (m *Menu) clearProxyFile(filename string) error {
	m.resultMutex.Lock()
	defer m.resultMutex.Unlock()

	// Check if file exists and has content
	fileInfo, err := os.Stat(filename)
	if err == nil && fileInfo.Size() > 0 {
		// File exists with content, check if it has the header
		file, err := os.Open(filename)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		hasHeader := false
		if scanner.Scan() {
			firstLine := scanner.Text()
			if strings.HasPrefix(firstLine, "# Proxy List") {
				hasHeader = true
			}
		}

		// If file has header and content, just continue appending
		if hasHeader {
			return nil
		}
	}

	// Create new file or overwrite if no valid header
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write header
	header := "# Proxy List - Validated Working Proxies\n"
	header += "# Format: protocol://host:port\n"
	header += "# Proxies are written in real-time as they are validated\n\n"
	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// appendProxyToFile appends a single proxy to the file (thread-safe)
func (m *Menu) appendProxyToFile(p proxy.ProxyResult, filename string) error {
	m.resultMutex.Lock()
	defer m.resultMutex.Unlock()

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(p.FormatProxy() + "\n"); err != nil {
		return fmt.Errorf("failed to write proxy: %w", err)
	}

	return nil
}

// removeProxyFromRawFile removes a validated proxy from raw-proxy.txt (thread-safe)
func (m *Menu) removeProxyFromRawFile(p proxy.ProxyResult) error {
	m.resultMutex.Lock()
	defer m.resultMutex.Unlock()

	// Read all proxies from raw-proxy.txt
	file, err := os.Open("proxy/raw-proxy.txt")
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	var remainingProxies []string
	scanner := bufio.NewScanner(file)
	proxyToRemove := p.FormatProxy()

	for scanner.Scan() {
		line := scanner.Text()
		// Keep all lines except the validated proxy and preserve comments/headers
		if strings.TrimSpace(line) != proxyToRemove {
			remainingProxies = append(remainingProxies, line)
		}
	}
	file.Close()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Write back remaining proxies
	outFile, err := os.Create("proxy/raw-proxy.txt")
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	for _, line := range remainingProxies {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("failed to write line: %w", err)
		}
	}

	return nil
}

// clearRawProxyFile clears the raw-proxy.txt file
func (m *Menu) clearRawProxyFile() error {
	m.resultMutex.Lock()
	defer m.resultMutex.Unlock()

	file, err := os.Create("proxy/raw-proxy.txt")
	if err != nil {
		return fmt.Errorf("failed to clear file: %w", err)
	}
	defer file.Close()

	// Write header to indicate it's empty
	header := "# Raw Proxy List - Scraped Proxies (Before Validation)\n"
	header += "# Format: protocol://host:port\n"
	header += "# This file is cleared after validation is complete\n\n"
	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// loadValidProxies loads validated proxies from proxy/proxy.txt
func (m *Menu) loadValidProxies() ([]string, error) {
	file, err := os.Open("proxy/proxy.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proxies = append(proxies, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return proxies, nil
}
