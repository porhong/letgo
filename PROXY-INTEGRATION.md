# Proxy Integration for Brute Force and DDoS Attacks

## Overview
The letgo tool now supports proxy integration for both brute force (cURL-based) and DDoS attacks. This allows you to route your attack traffic through proxy servers for anonymity and distributed load.

## Features

### 1. Proxy Support for Brute Force Attacks
- Use validated proxies from `proxy/proxy.txt`
- Option to enable/disable proxy usage
- Proxy rotation for each request
- Single proxy mode available

### 2. Proxy Support for DDoS Attacks
- Same proxy integration as brute force
- Supports HTTP Flood, Slowloris, and Mixed attack modes
- Proxy rotation distributes load across multiple proxies

## How to Use

### Step 1: Scrape and Validate Proxies
Before using proxies in attacks, you need to collect and validate them:

```bash
./letgo
# Select option: 3) Scrape Proxies
# Select option: 4) Validate Proxies
```

This will:
1. Scrape proxies from multiple free sources
2. Save raw proxies to `proxy/raw-proxy.txt`
3. Validate proxies and save working ones to `proxy/proxy.txt`

### Step 2: Use Proxies in Brute Force Attack

```bash
./letgo
# Select option: 5) Attack Brute force with cURL
# When prompted: "Use proxy for attacks? (y/n, default: n):" type "y"
# Choose whether to rotate proxies: "Rotate through proxies for each request? (y/n, default: y):" type "y"
```

Configuration options:
- **Use proxy**: Enable/disable proxy usage
- **Rotate proxies**: If enabled, each request uses a different proxy from the pool
- **Single proxy**: If rotation is disabled, uses only the first proxy

### Step 3: Use Proxies in DDoS Attack

```bash
./letgo
# Select option: 6) DDoS Attack (cURL)
# When prompted: "Use proxy for attacks? (y/n, default: n):" type "y"
# Choose whether to rotate proxies: "Rotate through proxies for each request? (y/n, default: y):" type "y"
```

## Technical Details

### Proxy File Format
Proxies in `proxy/proxy.txt` should be in the format:
```
http://1.2.3.4:8080
https://5.6.7.8:3128
socks4://9.10.11.12:1080
socks5://13.14.15.16:1080
```

### Implementation Details

#### Brute Force Attack
- Proxies are loaded from `proxy/proxy.txt`
- HTTP client is created with proxy transport
- For rotation mode: Each request cycles through the proxy list
- For single mode: All requests use the first proxy

#### DDoS Attack
- Supports all attack modes (Flood, Slowloris, Mixed)
- Proxy rotation in Flood mode: Each worker request uses a different proxy
- Proxy in Slowloris mode: All connections use proxies if enabled
- Proxy distribution is atomic to prevent race conditions

### Code Changes

1. **cracker/cracker.go**
   - Added `UseProxy`, `ProxyList`, `RotateProxy` fields to `AttackConfig`
   - Added `proxyIndex` counter for rotation
   - Implemented `createHTTPClient()` method with proxy support
   - Updated all HTTP test methods to use proxy-enabled client

2. **ddos/ddos.go**
   - Added `UseProxy`, `ProxyList`, `RotateProxy` fields to `DDoSConfig`
   - Added `proxyIndex` counter to `DDoSAttack`
   - Updated `startFloodWorkers()` to configure proxy
   - Updated `sendRequest()` to rotate proxies per request

3. **console-menu/attack.go**
   - Added proxy configuration prompts for both attacks
   - Loads proxies using `loadValidProxies()` method
   - Applies proxy settings to attack configurations
   - Displays proxy status in configuration summary

4. **console-menu/proxy.go**
   - Added `loadValidProxies()` method to load validated proxies

## Benefits

1. **Anonymity**: Hide your real IP address
2. **Distributed Load**: Spread requests across multiple IPs
3. **Rate Limit Bypass**: Avoid rate limiting on single IP
4. **Geographic Distribution**: Use proxies from different locations

## Best Practices

1. **Always validate proxies** before using them in attacks
2. **Use proxy rotation** for better distribution and anonymity
3. **Monitor proxy performance** - some may be slower than direct connection
4. **Keep proxy list updated** - free proxies often become unavailable
5. **Test with small attacks first** to verify proxy functionality

## Example Workflow

```bash
# 1. Scrape proxies
./letgo → Select 3 (Scrape Proxies)
# Output: Scraped 500 proxies → proxy/raw-proxy.txt

# 2. Validate proxies
./letgo → Select 4 (Validate Proxies)
# Output: 50 working proxies → proxy/proxy.txt

# 3. Run brute force attack with proxies
./letgo → Select 5 (Attack Brute force with cURL)
# Enable proxy: y
# Rotate proxies: y
# Configure attack parameters...
# Attack runs with proxy rotation

# 4. Run DDoS attack with proxies
./letgo → Select 6 (DDoS Attack)
# Enable proxy: y
# Rotate proxies: y
# Configure attack parameters...
# Attack runs with proxy distribution
```

## Troubleshooting

### No proxies found
```
Warning: No valid proxies found in proxy/proxy.txt
```
**Solution**: Run "Scrape Proxies" and "Validate Proxies" first.

### Slow attack speed
**Cause**: Proxies may be slower than direct connection
**Solution**: 
- Use fewer, faster proxies
- Increase timeout values
- Disable proxy rotation to use only the fastest proxy

### Connection failures
**Cause**: Proxies may go offline
**Solution**:
- Re-validate proxies periodically
- Use proxy rotation to skip bad proxies automatically

## Security Notice

⚠️ **Important**: This tool is for educational and authorized security testing only. Always ensure you have proper authorization before conducting any security tests. Misuse of this tool may violate laws and regulations.
