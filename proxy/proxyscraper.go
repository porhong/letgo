package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyScraperConfig holds configuration for the proxy scraper
type ProxyScraperConfig struct {
	MaxThreads       int
	Timeout          time.Duration
	OnProgress       func(scraped, total int, percentage float64)
	OnValidProxy     func(proxy ProxyResult) // Called immediately when a valid proxy is found
	OnProxyValidated func(proxy ProxyResult) // Called after any proxy is validated (valid or not)
}

// ProxyResult represents a scraped proxy
type ProxyResult struct {
	Protocol string
	Host     string
	Port     string
	IsValid  bool
	Error    string
}

// ProxyScraper handles proxy scraping operations
type ProxyScraper struct {
	config  ProxyScraperConfig
	results []ProxyResult
	mu      sync.Mutex
	scraped int32
	total   int32
}

// ProxyValidator handles proxy validation operations
type ProxyValidator struct {
	config    ProxyScraperConfig
	validated int32
	total     int32
}

// New creates a new ProxyScraper instance
func New(config ProxyScraperConfig) *ProxyScraper {
	if config.MaxThreads <= 0 {
		config.MaxThreads = 50
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}

	return &ProxyScraper{
		config:  config,
		results: make([]ProxyResult, 0),
	}
}

// NewValidator creates a new ProxyValidator instance
func NewValidator(config ProxyScraperConfig) *ProxyValidator {
	if config.MaxThreads <= 0 {
		config.MaxThreads = 20
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}

	return &ProxyValidator{
		config: config,
	}
}

type proxySource struct {
	URL      string
	Protocol string
	Format   string
}

// proxySources returns a list of free proxy sources to scrape
func proxySources() []proxySource {
	return []proxySource{
		{"https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all", "http", "text"},
		{"https://api.proxyscrape.com/v2/?request=get&protocol=socks4&timeout=10000&country=all", "socks4", "text"},
		{"https://api.proxyscrape.com/v2/?request=get&protocol=socks5&timeout=10000&country=all", "socks5", "text"},
		{"https://www.proxy-list.download/api/v1/get?type=http", "http", "text"},
		{"https://www.proxy-list.download/api/v1/get?type=https", "https", "text"},
		{"https://www.proxy-list.download/api/v1/get?type=socks4", "socks4", "text"},
		{"https://www.proxy-list.download/api/v1/get?type=socks5", "socks5", "text"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http", "text"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4", "text"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5", "text"},
		{"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", "http", "text"},
		{"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt", "https", "text"},
		{"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt", "socks4", "text"},
		{"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt", "socks5", "text"},
		{"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "http", "text"},
		{"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "socks4", "text"},
		{"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "socks5", "text"},
	}
}

// Scrape fetches proxies from multiple sources
func (ps *ProxyScraper) Scrape(ctx context.Context) ([]ProxyResult, error) {
	sources := proxySources()
	atomic.StoreInt32(&ps.total, int32(len(sources)))
	atomic.StoreInt32(&ps.scraped, 0)

	if ps.config.OnProgress != nil {
		go ps.trackProgress(ctx)
	}

	jobs := make(chan proxySource, len(sources))
	var wg sync.WaitGroup

	for i := 0; i < ps.config.MaxThreads; i++ {
		wg.Add(1)
		go ps.scrapeWorker(ctx, jobs, &wg)
	}

	go func() {
		defer close(jobs)
		for _, source := range sources {
			select {
			case <-ctx.Done():
				return
			case jobs <- source:
			}
		}
	}()

	wg.Wait()

	return ps.GetResults(), nil
}

// scrapeWorker processes scraping jobs
func (ps *ProxyScraper) scrapeWorker(ctx context.Context, jobs <-chan proxySource, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: ps.config.Timeout,
	}

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			proxies := ps.scrapeSource(client, job.URL, job.Protocol, job.Format)
			ps.addResults(proxies)
			atomic.AddInt32(&ps.scraped, 1)
		}
	}
}

// scrapeSource fetches and parses proxies from a single source
func (ps *ProxyScraper) scrapeSource(client *http.Client, sourceURL, protocol, format string) []ProxyResult {
	resp, err := client.Get(sourceURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	return ps.parseProxies(string(body), protocol, format)
}

// parseProxies extracts proxy addresses from response body
func (ps *ProxyScraper) parseProxies(body, protocol, format string) []ProxyResult {
	var results []ProxyResult

	switch format {
	case "text":
		scanner := bufio.NewScanner(strings.NewReader(body))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				host := strings.TrimSpace(parts[0])
				port := strings.TrimSpace(parts[1])

				if net.ParseIP(host) != nil && isValidPort(port) {
					results = append(results, ProxyResult{
						Protocol: protocol,
						Host:     host,
						Port:     port,
						IsValid:  false,
					})
				}
			}
		}

	case "json":
		var jsonData []map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
			for _, item := range jsonData {
				if host, ok := item["ip"].(string); ok {
					if port, ok := item["port"].(string); ok {
						results = append(results, ProxyResult{
							Protocol: protocol,
							Host:     host,
							Port:     port,
							IsValid:  false,
						})
					}
				}
			}
		}

	case "html":
		re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})`)
		matches := re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) == 3 {
				host := match[1]
				port := match[2]
				if net.ParseIP(host) != nil && isValidPort(port) {
					results = append(results, ProxyResult{
						Protocol: protocol,
						Host:     host,
						Port:     port,
						IsValid:  false,
					})
				}
			}
		}
	}

	return results
}

// isValidPort checks if a port number is valid
func isValidPort(port string) bool {
	var portNum int
	_, err := fmt.Sscanf(port, "%d", &portNum)
	return err == nil && portNum > 0 && portNum <= 65535
}

// addResults adds proxy results to the collection
func (ps *ProxyScraper) addResults(results []ProxyResult) {
	if len(results) == 0 {
		return
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.results = append(ps.results, results...)
}

// GetResults returns all scraped proxy results
func (ps *ProxyScraper) GetResults() []ProxyResult {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return append([]ProxyResult{}, ps.results...)
}

// trackProgress displays scraping progress
func (ps *ProxyScraper) trackProgress(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := atomic.LoadInt32(&ps.scraped)
			total := atomic.LoadInt32(&ps.total)
			if total == 0 {
				continue
			}
			percentage := float64(current) / float64(total) * 100
			if ps.config.OnProgress != nil {
				ps.config.OnProgress(int(current), int(total), percentage)
			}
		}
	}
}

// ValidateProxies tests if proxies are working
func (pv *ProxyValidator) ValidateProxies(ctx context.Context, proxies []ProxyResult) ([]ProxyResult, error) {
	atomic.StoreInt32(&pv.total, int32(len(proxies)))
	atomic.StoreInt32(&pv.validated, 0)

	if pv.config.OnProgress != nil {
		go pv.trackValidationProgress(ctx)
	}

	jobs := make(chan ProxyResult, len(proxies))
	results := make(chan ProxyResult, len(proxies))
	var wg sync.WaitGroup

	for i := 0; i < pv.config.MaxThreads; i++ {
		wg.Add(1)
		go pv.validationWorker(ctx, jobs, results, &wg)
	}

	go func() {
		defer close(jobs)
		for _, proxy := range proxies {
			select {
			case <-ctx.Done():
				return
			case jobs <- proxy:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var validProxies []ProxyResult
	for result := range results {
		// Call callback for every validated proxy (both valid and invalid)
		if pv.config.OnProxyValidated != nil {
			pv.config.OnProxyValidated(result)
		}

		if result.IsValid {
			validProxies = append(validProxies, result)
			// Call callback immediately for incremental writing
			if pv.config.OnValidProxy != nil {
				pv.config.OnValidProxy(result)
			}
		}
	}

	return validProxies, nil
}

// validationWorker validates proxy functionality
func (pv *ProxyValidator) validationWorker(ctx context.Context, jobs <-chan ProxyResult, results chan<- ProxyResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for proxy := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			validatedProxy := pv.testProxy(proxy)
			results <- validatedProxy
			atomic.AddInt32(&pv.validated, 1)
		}
	}
}

// testProxy tests if a proxy is working
func (pv *ProxyValidator) testProxy(proxy ProxyResult) ProxyResult {
	proxyURL := fmt.Sprintf("%s://%s:%s", proxy.Protocol, proxy.Host, proxy.Port)

	parsedProxyURL, err := url.Parse(proxyURL)
	if err != nil {
		proxy.Error = fmt.Sprintf("invalid proxy URL: %v", err)
		return proxy
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedProxyURL),
		DialContext: (&net.Dialer{
			Timeout:   pv.config.Timeout,
			KeepAlive: 0,
		}).DialContext,
		TLSHandshakeTimeout:   pv.config.Timeout,
		ResponseHeaderTimeout: pv.config.Timeout,
		DisableKeepAlives:     true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   pv.config.Timeout,
	}

	testURL := "http://httpbin.org/ip"
	resp, err := client.Get(testURL)
	if err != nil {
		proxy.Error = fmt.Sprintf("connection failed: %v", err)
		return proxy
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		proxy.IsValid = true
		proxy.Error = ""
	} else {
		proxy.Error = fmt.Sprintf("unexpected status: %d", resp.StatusCode)
	}

	return proxy
}

// trackValidationProgress displays validation progress
func (pv *ProxyValidator) trackValidationProgress(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := atomic.LoadInt32(&pv.validated)
			total := atomic.LoadInt32(&pv.total)
			if total == 0 {
				continue
			}
			percentage := float64(current) / float64(total) * 100
			if pv.config.OnProgress != nil {
				pv.config.OnProgress(int(current), int(total), percentage)
			}
		}
	}
}

// RemoveDuplicates removes duplicate proxies from a slice
func RemoveDuplicates(proxies []ProxyResult) []ProxyResult {
	seen := make(map[string]bool)
	var unique []ProxyResult

	for _, proxy := range proxies {
		key := fmt.Sprintf("%s://%s:%s", proxy.Protocol, proxy.Host, proxy.Port)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, proxy)
		}
	}

	return unique
}

// FormatProxy returns the proxy in standard format
func (pr *ProxyResult) FormatProxy() string {
	return fmt.Sprintf("%s://%s:%s", pr.Protocol, pr.Host, pr.Port)
}
