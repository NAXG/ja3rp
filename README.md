# JA3RP (JA3 Reverse Proxy)
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

### Key Files

- `ja3rp.go`: Core server implementation and main server logic
- `mux.go`: Custom HTTP request multiplexer (modified from Go standard library)
- `crypto/tls/`: Modified TLS implementation with JA3 fingerprint extraction
- `net/http/`: Modified HTTP server that includes JA3 support
- `cmd/main.go`: CLI entry point for running the server

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

Hashes should be stored in .txt files, each separated by a new line.

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
