# Proxy Scraper Module

## Overview
The Proxy Scraper module provides functionality to scrape free proxies from multiple online sources and validate them for use in attacks.

## Features

### 1. Proxy Scraping (Menu Option 7)
- Scrapes proxies from 17+ free proxy sources
- Supports multiple protocols: HTTP, HTTPS, SOCKS4, SOCKS5
- Concurrent scraping with configurable thread count (default: 50)
- Automatic duplicate removal
- Progress tracking with real-time updates
- Results saved to `proxy/raw-proxy.txt`

### 2. Proxy Validation (Menu Option 8)
- Tests scraped proxies to verify they are working
- Concurrent validation with configurable thread count (default: 20)
- Tests each proxy by connecting to http://httpbin.org/ip
- Configurable timeout (default: 10 seconds)
- Progress tracking with real-time updates
- Success rate statistics
- Working proxies saved to `proxy/proxy.txt`

## File Structure

```
proxy/
├── proxyscraper.go    # Main proxy scraping and validation logic
├── raw-proxy.txt      # All scraped proxies (with duplicates removed)
└── proxy.txt          # Validated working proxies only
```

## Proxy Format
All proxies are stored in the format: `protocol://host:port`

Examples:
- `http://192.168.1.1:8080`
- `https://10.0.0.1:3128`
- `socks4://172.16.0.1:1080`
- `socks5://203.0.113.5:9050`

## Usage

### Scraping Proxies
1. Run the application: `./letgo`
2. Select option `7) Scrape Proxies`
3. Configure settings:
   - Max Threads (default: 50)
   - Timeout in seconds (default: 15)
4. Wait for scraping to complete
5. Review statistics and proxy breakdown by protocol
6. Proxies are saved to `proxy/raw-proxy.txt`

### Validating Proxies
1. Ensure you have scraped proxies first (option 7)
2. Select option `8) Validate Proxies`
3. Configure settings:
   - Max Threads (default: 20)
   - Timeout in seconds (default: 10)
4. Wait for validation to complete
5. Review validation statistics and success rate
6. Working proxies are saved to `proxy/proxy.txt`

## Free Proxy Sources

The module scrapes from the following sources:

1. **ProxyScrape API**
   - HTTP, SOCKS4, SOCKS5 proxies
   - Reliable API with good uptime

2. **Proxy-List.download**
   - HTTP, HTTPS, SOCKS4, SOCKS5 proxies
   - Multiple endpoints for different protocols

3. **TheSpeedX/PROXY-List (GitHub)**
   - Community-maintained proxy lists
   - Updated regularly

4. **ShiftyTR/Proxy-List (GitHub)**
   - HTTP, HTTPS, SOCKS4, SOCKS5 proxies
   - Well-maintained repository

5. **monosans/proxy-list (GitHub)**
   - HTTP, SOCKS4, SOCKS5 proxies
   - Frequently updated

## Configuration Options

### Proxy Scraper Config
- **MaxThreads**: Number of concurrent workers for scraping (1-100)
- **Timeout**: Request timeout in seconds (5-60)
- **OnProgress**: Callback for progress updates

### Proxy Validator Config
- **MaxThreads**: Number of concurrent workers for validation (1-50)
- **Timeout**: Proxy test timeout in seconds (5-30)
- **OnProgress**: Callback for progress updates

## Technical Details

### Scraping Process
1. Fetch proxy lists from multiple sources concurrently
2. Parse responses (supports text, JSON, HTML formats)
3. Validate IP address and port format
4. Store results with protocol information
5. Remove duplicates based on protocol://host:port combination
6. Write to `proxy/raw-proxy.txt`

### Validation Process
1. Load proxies from `proxy/raw-proxy.txt`
2. Create HTTP client with proxy configuration
3. Test connection to http://httpbin.org/ip
4. Check for successful response (HTTP 200)
5. Mark proxy as valid or invalid
6. Write working proxies to `proxy/proxy.txt`

## Future Integration

The proxy module is designed to be integrated with:
- **Attack Brute force with cURL** (Menu Option 5)
- **DDoS Attack with cURL** (Menu Option 6)

Integration will allow rotating through validated proxies during attacks to:
- Avoid IP blocking
- Distribute attack traffic
- Bypass rate limiting
- Improve attack stealth

## Error Handling

The module handles:
- Network timeouts
- Invalid proxy formats
- Unreachable proxy sources
- Connection failures
- Invalid responses

All errors are logged and displayed to the user without crashing the application.

## Performance Tips

1. **For Scraping**:
   - Use 30-50 threads for optimal speed
   - Increase timeout to 20-30s if sources are slow
   - Run during off-peak hours for better source availability

2. **For Validation**:
   - Use 15-25 threads to avoid overwhelming test endpoints
   - Set timeout to 10-15s for reliable results
   - Lower thread count if you experience network issues

## Limitations

- Free proxy sources may have limited availability
- Proxy quality varies (speed, uptime, anonymity)
- Validation is done against a single test URL
- Some proxies may work for specific sites only
- Geographic distribution depends on sources

## Troubleshooting

**No proxies found during scraping:**
- Check internet connection
- Try increasing timeout value
- Some sources may be temporarily unavailable
- Run at different times of day

**All proxies fail validation:**
- Increase validation timeout
- Free proxies have low success rates (5-15% is normal)
- Try scraping again to get fresh proxies
- Network restrictions may block proxy testing

**Slow performance:**
- Reduce thread count
- Increase timeout values
- Check available bandwidth
- Some proxy sources may be rate-limited

## Code Architecture

### Packages
- `proxy/proxyscraper.go` - Core scraping and validation logic
- `console-menu/proxy.go` - Menu integration and user interaction
- `console-menu/utils.go` - File I/O utilities for proxy storage

### Key Types
- `ProxyScraperConfig` - Configuration for scraper/validator
- `ProxyResult` - Represents a single proxy with metadata
- `ProxyScraper` - Main scraper implementation
- `ProxyValidator` - Proxy validation implementation

### Design Patterns
- Worker pool pattern for concurrent processing
- Atomic counters for thread-safe statistics
- Context-based cancellation support
- Progress callback for real-time updates
- Mutex-protected file I/O

## License
Part of the letgo project. Use responsibly and ethically.
