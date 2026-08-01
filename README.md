# cert

**cert** is a zero-dependency CLI tool for checking SSL/TLS certificate expiry dates on domains. It connects to one or more domains, retrieves the certificate, and reports days remaining until expiry. Certificates that are expired or within the warning threshold produce non-zero exit codes, making cert suitable for monitoring scripts and cron jobs.

## Install

```bash
pip install git+https://github.com/jrbobbyhansen-pixel/cert.git
```

Or download `cert.py` and run it directly:

```bash
python3 cert.py example.com
```

## Usage

```bash
# Check a single domain
cert example.com

# Check multiple domains
cert example.com google.com github.com

# Custom port and warning threshold
cert example.com --port 8443 --warn 14

# Verbose output with issuer and subject details
cert example.com --verbose

# Connection timeout
cert example.com --timeout 5
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | All certificates OK |
| 1    | Error (DNS failure, connection refused, etc.) |
| 2    | At least one certificate is expired |
| 3    | At least one certificate is within the warning threshold |

## Requirements

- Python 3.8+
- No external dependencies (stdlib only: `ssl`, `socket`, `datetime`, `argparse`)
- Portable: macOS, Linux, WSL
