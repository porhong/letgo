# Letgo - Password Cracking Tool

A powerful, multi-threaded password cracking tool with support for HTTP/HTTPS login endpoints, SSH, and hash cracking.

## Features

- ✅ **Multi-user attacks** - Test multiple usernames from a file
- ✅ **cURL configuration import** - Import attack configs from cURL commands
- ✅ **Real-time progress tracking** - See live progress, rate, and ETA
- ✅ **Endpoint scanning** - Automatically discover login endpoints
- ✅ **Multiple protocols** - HTTP Basic Auth, POST forms, JSON APIs, SSH
- ✅ **Smart detection** - Auto-detect success/failure conditions
- ✅ **High performance** - Multi-threaded with configurable concurrency

## Quick Start

```bash
# Build
go build -o letgo cmd/letgo/main.go

# Run
./letgo
# or
go run cmd/letgo/main.go
```

## Usage

### 1. Standard Attack

Attack with a single username and password list:
- Choose option `1` from menu
- Provide target URL from `valid-url.txt`
- Enter username and wordlist path
- Configure attack parameters

### 2. Multi-User Attack

Attack with multiple usernames:
- Choose option `1` from menu
- When asked "Use userlist file?", answer `y`
- Provide userlist path (default: `users.txt`)
- Provide password list (default: `passwords.txt`)

### 3. cURL Config Attack

Import configuration from cURL commands:
- Create `cURL.txt` with your cURL commands
- Choose option `5` from menu
- Tool automatically extracts headers, endpoints, and field names

### 4. Endpoint Scanning

Discover login endpoints:
- Choose option `2` from menu
- Enter base URL
- Tool scans for common login endpoints
- Results saved to `valid-url.txt`

## File Structure

- `users.txt` - List of usernames (one per line)
- `passwords.txt` - List of passwords (one per line)
- `cURL.txt` - cURL commands for attack configuration
- `valid-url.txt` - Valid login endpoints (from scanning)
- `results.txt` - Successful credentials (format: `URL|username|password`)

## Tips for Effective Use

### ⚠️ Managing Large Attacks

Your attack of **727 users × 100,394 passwords = 72,986,438 combinations** would take ~12 hours!

**Recommendations:**

1. **Reduce scope** - Start small and increase if needed
   ```bash
   # Use top 1000 most common passwords first
   head -1000 passwords.txt > passwords-top1k.txt
   ```

2. **Targeted userlist** - Focus on likely usernames
   ```bash
   # Test specific users first
   echo "admin" > priority-users.txt
   echo "administrator" >> priority-users.txt
   ```

3. **Increase threads** - Use more threads for faster execution
   - Default: 100 threads
   - Try: 500-1000 threads (monitor your system)

4. **Use the warning** - Tool now warns when combinations > 100,000

### Example Workflow

```bash
# 1. Scan for endpoints
# Choose option 2, enter target domain

# 2. Start with small wordlist
head -100 passwords.txt > test-passwords.txt

# 3. Test single user first
# Choose option 1, use single username

# 4. If unsuccessful, expand to multi-user
# Choose option 1, use userlist with top users

# 5. Gradually increase password list size
# head -1000, then -10000, etc.
```

## Progress Tracking

The tool now shows real-time progress:
```
Progress: [████████░░░░░░░░░░░░] 25.3% | 18450/72986 | Rate: 1658/s | ETA: 8m32s
```

- **Progress bar** - Visual representation
- **Percentage** - Completion percentage
- **Attempts** - Current/total attempts
- **Rate** - Attempts per second
- **ETA** - Estimated time remaining

## Advanced Features

### Custom Headers

Add custom headers for authentication, tokens, etc.:
```
Add custom headers? (y)
Enter header (format: Key:Value): Authorization:Bearer token123
Enter header (format: Key:Value): X-Custom-Header:value
```

### Success/Failure Detection

Configure how to detect successful login:
- **Success codes**: HTTP status codes (e.g., `200,302`)
- **Success keywords**: Text in response (e.g., `welcome,dashboard`)
- **Failure keywords**: Text indicating failure (e.g., `invalid,incorrect`)

### cURL.txt Format

```bash
# Example 1: JSON POST
curl -X POST https://example.com/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"test","password":"test"}'

# Example 2: Form POST
curl -X POST https://example.com/login \
  -d 'username=admin&password=test'
```

## Building from Source

```bash
go build -o letgo cmd/letgo/main.go
```

## License

Use responsibly and only on systems you own or have permission to test.
