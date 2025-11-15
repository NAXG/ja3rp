# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JA3RP (JA3 Reverse Proxy) is a Go-based reverse proxy server that filters traffic based on JA3 fingerprints. This is a proof-of-concept project that is **no longer maintained** - the README recommends using [guardgress](https://github.com/h3adex/guardgress) for production use.

## Development Commands

### Build and Run
```bash
# Build the CLI tool
go build ./cmd/main.go

# Run tests
go test -v

# Run a single test
go test -v -run TestReverseProxy

# Install dependencies
go mod download

# Update dependencies
go mod tidy
```

### Testing with Certificates
The project includes self-signed certificates for testing in `internal/tests/data/`. Tests automatically use these certificates for TLS connections.

## Architecture Overview

### Core Components

1. **Modified Go Standard Library**: The project includes custom implementations of `crypto/tls` and `net/http` packages to extract JA3 fingerprints during TLS handshakes. These modifications are essential for the JA3 functionality.

2. **JA3 Fingerprint Extraction**: JA3 fingerprints are extracted in `crypto/tls/common.go:JA3()` method. The JA3 string format is: `SSLVersion,AcceptedCiphers,Extensions,EllipticCurves,EllipticCurvePointFormats`.

3. **Server Architecture**: The main server (`ja3rp.go`) can operate in two modes:
   - **Reverse Proxy Mode**: Forwards traffic to destination servers when JA3 matches criteria
   - **HTTP Server Mode**: Standalone HTTP server for testing

4. **Traffic Filtering**: Uses MD5 hashes of JA3 strings for whitelist/blacklist filtering. The JA3 fingerprint is attached to HTTP requests via the `Request.JA3` field.

### Key Files and Their Roles

- `ja3rp.go`: Core server implementation, JA3 digest functionality, and main server logic
- `mux.go`: Custom HTTP request multiplexer (modified from Go standard library)
- `crypto/tls/`: Modified TLS implementation with JA3 fingerprint extraction
  - `common.go:JA3()`: Constructs JA3 fingerprint string from ClientHello
  - `handshake_server.go`: Performs early blacklist checks during TLS handshake
- `net/http/`: Modified HTTP server that includes JA3 support
- `cmd/main.go`: CLI entry point for running the server

### Important Implementation Details

- JA3 fingerprints are extracted during the TLS handshake before the HTTP request is processed
- The server can filter based on either whitelist (only allow specified hashes) or blacklist (block specified hashes)
- Custom blocked request handlers can be configured via the `OnBlocked` option
- TLS blacklist filtering occurs early in `handshake_server.go` before HTTP request processing
- The project uses Go 1.21 and has minimal external dependencies

## Security Considerations

This codebase implements TLS fingerprint-based traffic filtering. The JA3 fingerprint extraction and early blacklist enforcement provide a mechanism for rejecting connections based on TLS client characteristics. When working with this code:

- Be aware that this is security-related code that filters network traffic
- The modifications to standard library packages are extensive and affect TLS handshake behavior
- Test thoroughly when making changes to the TLS or HTTP implementations