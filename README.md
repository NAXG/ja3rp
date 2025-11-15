# JA3RP (JA3 Reverse Proxy)

[![English](https://img.shields.io/badge/Language-English-blue.svg)](README.md) [![中文](https://img.shields.io/badge/Language-中文-red.svg)](README_CN.md)

Ja3RP is a basic reverse proxy server that filters traffic based on [JA3](https://github.com/salesforce/ja3) fingerprints.
It can also operate as a regular HTTP server for testing purposes.

Inspired by this [ja3-server](https://github.com/CapacitorSet/ja3-server) POC.

## Architecture

This project implements JA3 fingerprint-based traffic filtering through several key components:

### Core Components

1. **Modified Go Standard Library**: Custom implementations of `crypto/tls` and `net/http` packages to extract JA3 fingerprints during TLS handshakes
2. **JA3 Fingerprint Extraction**: JA3 fingerprints are extracted in `crypto/tls/common.go:JA3()` method
3. **Server Architecture**: The main server (`ja3rp.go`) operates in two modes:
   - **Reverse Proxy Mode**: Forwards traffic to destination servers when JA3 matches criteria
   - **HTTP Server Mode**: Standalone HTTP server for testing
4. **Traffic Filtering**: Uses MD5 hashes of JA3 strings for whitelist/blacklist filtering
5. **Early TLS Detection**: Performs IP and JA3 fingerprint detection during TLS handshake phase for immediate blocking

### Key Files

- `ja3rp.go`: Core server implementation and main server logic
- `mux.go`: Custom HTTP request multiplexer (modified from Go standard library)
- `crypto/tls/`: Modified TLS implementation with JA3 fingerprint extraction
- `net/http/`: Modified HTTP server that includes JA3 support
- `cmd/main.go`: CLI entry point for running the server

## Documentation

- **English** - This document
- **中文** - [README_CN.md](README_CN.md) - 中文文档

## Installation
```
# Clone the repository
git clone https://github.com/naxg/ja3rp.git
cd ja3rp

# Install dependencies
go mod download

# Build the binary
go build ./cmd/main.go

# Or install globally
go install ./cmd/main.go
```

## Usage
### Preparation
A JA3 hash is constructed from a TLS ClientHello packet.
For this reason the JA3RP server will need an SSL certificate in order to work.

You can generate a self-signed certificate using the following commands:
```
$ openssl req -new -subj "/C=US/ST=Utah/CN=localhost" -newkey rsa:2048 -nodes -keyout localhost.key -out localhost.csr
$ openssl x509 -req -days 365 -in localhost.csr -signkey localhost.key -out localhost.crt
```

**Note**: The project includes test certificates in `internal/tests/data/` for testing purposes.

### Package
The following example starts an HTTPS server and filters incoming traffic based on a JA3 hash.
If the hash is found in the whitelist the traffic is forwarded to the configured destination server.
Otherwise or if blacklisted the request is blocked.

```go
package main

import (
	"fmt"
	"github.com/naxg/ja3rp"
	"github.com/naxg/ja3rp/net/http"
	"log"
	"net/url"
)

func main() {
	address := "localhost:1337"
	d, _ := url.Parse("https://example.com")

	server := ja3rp.NewServer(address, ja3rp.ServerOptions{
		Destination: d,
		Whitelist: []string{
			"bd50e49d418ed1777b9a410d614440c4", // firefox
			"b32309a26951912be7dba376398abc3b", // chrome
		},
		Blacklist: []string{
			"3b5074b1b5d032e5620f69f9f700ff0e", // CURL
		},
		OnBlocked: func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("Sorry, you are not in our whitelist :(")
		},
	})

	err := server.ListenAndServeTLS("certificate.crt", "certificate.key")
	
	log.Fatal(err)
}
```

### CLI

#### Basic Usage
```
$ ja3rp -h
Usage: ja3rp -a <address> [-d <destination URL> -c <cert file> -k <cert key> -w <whitelist file> -b <blacklist file>]
Example: $ ja3rp -a localhost:1337 -d https://example.com -c certificate.crt -k certificate.key -w whitelist.txt -b blacklist.txt
```

#### Examples

**Whitelist mode** (only allow specific clients):
```bash
$ ja3rp -a localhost:1337 -d https://example.com -c cert.crt -k cert.key -w whitelist.txt
```

**Blacklist mode** (block specific clients):
```bash
$ ja3rp -a localhost:1337 -d https://example.com -c cert.crt -k cert.key -b blacklist.txt
```

**HTTP server mode** (for testing, no proxy):
```bash
$ ja3rp -a localhost:1337 -c cert.crt -k cert.key
```

**TLS Stage Detection Example** (programmatic usage):
```go
package main

import (
    "github.com/naxg/ja3rp"
    "net/url"
)

func main() {
    destination, _ := url.Parse("https://api.example.com")

    server := ja3rp.NewServer("0.0.0.0:443", ja3rp.ServerOptions{
        Destination: destination,
    })

    server.TLSConfig.IPBlacklist = []string{
        "192.168.1.100",
        "10.0.0.50",
    }
    server.TLSConfig.JA3Blacklist = []string{
        "bd50e49d418ed1777b9a410d614440c4",
        "suspicious_bot_fingerprint",
    }

    server.ListenAndServeTLS("cert.crt", "cert.key")
}
```

Hashes should be stored in .txt files, each separated by a new line.

### TLS Stage Detection

JA3RP implements **early detection** at the TLS handshake level, providing immediate blocking of unwanted connections before they reach the HTTP layer.

#### IP Address Detection
- **Location**: [`crypto/tls/handshake_server.go:48-55`](crypto/tls/handshake_server.go:48-55)
- **Mechanism**: Checks client IP against blacklist during TLS handshake
- **Implementation**:
  ```go
  if len(c.config.IPBlacklist) > 0 {
      remoteAddr := c.conn.RemoteAddr().String()
      if isIPBlacklisted(remoteAddr, c.config.IPBlacklist) {
          c.sendAlert(alertHandshakeFailure)
          return fmt.Errorf("tls: IP address %s is blacklisted", remoteAddr)
      }
  }
  ```

#### JA3 Fingerprint Detection
- **Location**: [`crypto/tls/handshake_server.go:65-69`](crypto/tls/handshake_server.go:65-69) (TLS 1.3) and [`crypto/tls/handshake_server.go:81-85`](crypto/tls/handshake_server.go:81-85) (TLS 1.2/1.1)
- **Mechanism**: Extracts JA3 fingerprint from ClientHello and checks against blacklist
- **Implementation**:
  ```go
  if len(c.config.JA3Blacklist) > 0 && isJA3Blacklisted(c.JA3, c.config.JA3Blacklist) {
      c.sendAlert(alertHandshakeFailure)
      return fmt.Errorf("tls: JA3 fingerprint %s is blacklisted", c.JA3)
  }
  ```

#### Detection Flow
1. **TCP Connection Established** → Client IP checked immediately
2. **TLS Handshake Begins** → JA3 fingerprint extracted from ClientHello
3. **Early Decision Made** → Connection terminated if either check fails
4. **HTTP Layer Bypassed** → No HTTP processing for blocked connections

#### Configuration Options
- **IP Blacklist**: `IPBlacklist []string` in TLS Config
- **JA3 Blacklist**: `JA3Blacklist []string` in TLS Config
- **Detection Timing**: Occurs before any HTTP headers are processed

This early detection mechanism provides:
- **Performance**: Unwanted connections are rejected at the TLS level
- **Security**: Malicious clients never reach the application layer
- **Efficiency**: Reduced resource usage by filtering before HTTP processing

#### Performance Benefits

| Detection Method | Processing Stage | Resource Usage | Response Time |
|------------------|------------------|----------------|---------------|
| **TLS Stage Detection** | Handshake Level | Minimal (pre-HTTP) | Immediate |
| Traditional Detection | HTTP Layer | Full HTTP processing | Delayed |

**Key Advantages:**
- **Zero HTTP Overhead**: Blocked connections never consume HTTP processing resources
- **Immediate Response**: TLS handshake failure alerts provide instant feedback
- **Memory Efficient**: No HTTP request/response objects created for blocked connections
- **CPU Optimized**: Minimal cryptographic operations for blacklisted connections

### Development

#### Building and Testing
```bash
# Run tests
go test -v

# Run specific test
go test -v -run TestReverseProxy

# Build the project
go build ./cmd/main.go

# Update dependencies
go mod tidy
```

#### Testing with Certificates
The project includes self-signed certificates for testing in `internal/tests/data/`. Tests automatically use these certificates for TLS connections.

#### JA3 Fingerprint Format
JA3 fingerprints are constructed as: `SSLVersion,AcceptedCiphers,Extensions,EllipticCurves,EllipticCurvePointFormats`

## Licenses
This project is licensed with the [MIT License](LICENSE).

The included (and then modified) `net/http`, `internal/profile` and `crypto` packages fall under the [go source code license](./LICENSE_GO.txt).
