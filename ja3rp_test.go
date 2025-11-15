package ja3rp

import (
    "fmt"
    "io"
    "strings"
    "net/url"
    "os"
    "path"
    "strconv"
    "testing"

	"github.com/naxg/ja3rp/crypto/tls"
	"github.com/naxg/ja3rp/net/http"
	"github.com/naxg/ja3rp/net/http/httptest"
)

const testPort = 1337

type destinationServerMock struct {
	reached bool
}

// newInsecureClient creates a new HTTP client that can work with self-signed SSL certificates.
func newInsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

func listenAndServe(s *http.Server) {
	dir := path.Join("internal", "tests", "data")
	s.ListenAndServeTLS(path.Join(dir, "localhost.crt"), path.Join(dir, "localhost.key"))
}

// captureCurrentJA3 starts a temporary TLS server that echoes Request.JA3 and returns the digest observed from a local client.
func captureCurrentJA3(addr string) (string, error) {
    dir := path.Join("internal", "tests", "data")
    srv := &http.Server{
        Addr: addr,
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            fmt.Fprint(w, r.JA3)
        }),
    }
    go srv.ListenAndServeTLS(path.Join(dir, "localhost.crt"), path.Join(dir, "localhost.key"))
    client := newInsecureClient()
    res, err := client.Get("https://" + addr)
    if err != nil {
        srv.Close()
        return "", err
    }
    body, _ := io.ReadAll(res.Body)
    srv.Close()
    return string(body), nil
}

// getPort gets an available port by environment variable or uses the given fallback value if it's not set.
func getPort(defaultValue int) string {
	if v, ok := os.LookupEnv("TEST_SERVER_PORT"); ok {
		return v
	}

	return strconv.Itoa(defaultValue)
}

func (dsm *destinationServerMock) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	dsm.reached = true
	fmt.Fprint(w, "ok")
}

func TestReverseProxyServer(t *testing.T) {
	dsm := &destinationServerMock{}

	// mock destination server
	ds := httptest.NewServer(dsm)
	defer ds.Close()

	addr := "localhost:" + getPort(testPort)

	// setup reverse proxy server
	u, err := url.Parse(ds.URL)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(addr, ServerOptions{
		Destination: u,
	})
	defer s.Close()

	// start listening in the background
	go (func() {
		s.ListenAndServe()
	})()

	// send HTTP request
	res, err := http.Get("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}

	// verify HTTP response
	if res.StatusCode != http.StatusOK {
		t.Fail()
	}
	if !dsm.reached {
		t.Errorf("destination server was not reached")
	}
}

func TestServer(t *testing.T) {
	expected := "ok"
	addr := "localhost:" + getPort(testPort)

	mux := NewMux()

	s := NewServer(addr, ServerOptions{
		Mux: mux,
	})
	defer s.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, expected)
	})

	go (func() {
		s.ListenAndServe()
	})()

	res, err := http.Get("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fail()
	}

	body, _ := io.ReadAll(res.Body)
	if bodyStr := string(body); bodyStr != expected {
		t.Errorf("Invalid body. Expected '%s' but got '%s'", expected, bodyStr)
	}
}

func TestWhitelist(t *testing.T) {
	addr := "localhost:" + getPort(testPort)

	s := NewServer(addr, ServerOptions{
		Whitelist: []string{"a", "b", "c"},
	})

	go listenAndServe(s)

	client := newInsecureClient()

	res, err := client.Get("https://" + addr)
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusForbidden {
		t.Fail()
	}

	s.Close()

    ja3, err := captureCurrentJA3(addr)
    if err != nil {
        t.Fatal(err)
    }
    s = NewServer(addr, ServerOptions{
        Whitelist: []string{ja3},
    })
	defer s.Close()

	go listenAndServe(s)

	res, err = client.Get("https://" + addr)
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fail()
	}
}

func TestBlacklist(t *testing.T) {
	addr := "localhost:" + getPort(testPort)

	s := NewServer(addr, ServerOptions{
		Blacklist: []string{"a", "b", "c"},
	})

	go listenAndServe(s)

	client := newInsecureClient()

	res, err := client.Get("https://" + addr)
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fail()
	}

	s.Close()

    ja3, err := captureCurrentJA3(addr)
    if err != nil {
        t.Fatal(err)
    }
    s = NewServer(addr, ServerOptions{
        Blacklist: []string{ja3},
    })
	defer s.Close()

	go listenAndServe(s)

    _, err = client.Get("https://" + addr)
    if err == nil {
        t.Fatalf("expected TLS handshake to fail due to JA3 blacklist, got no error")
    }
    if !strings.Contains(err.Error(), "handshake") {
        t.Fatalf("unexpected error, want handshake failure, got %v", err)
    }
}

func TestTLSHandshakeJA3Blacklist(t *testing.T) {
    addr := "localhost:" + getPort(testPort)

    // First: start a TLS server that echoes the JA3 digest from handshake via Request.JA3
    dir := path.Join("internal", "tests", "data")

    srv1 := &http.Server{
        Addr: addr,
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            fmt.Fprint(w, r.JA3)
        }),
    }
    go srv1.ListenAndServeTLS(path.Join(dir, "localhost.crt"), path.Join(dir, "localhost.key"))

    client := newInsecureClient()
    res, err := client.Get("https://" + addr)
    if err != nil {
        t.Fatal(err)
    }
    body, _ := io.ReadAll(res.Body)
    ja3 := string(body)
    srv1.Close()

    // Second: start a TLS server with JA3 blacklist equal to captured JA3 digest
    srv2 := &http.Server{
        Addr: addr,
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            fmt.Fprint(w, "ok")
        }),
        TLSConfig: &tls.Config{
            JA3Blacklist: []string{ja3},
        },
    }
    go srv2.ListenAndServeTLS(path.Join(dir, "localhost.crt"), path.Join(dir, "localhost.key"))

    _, err = client.Get("https://" + addr)
    if err == nil {
        t.Fatalf("expected TLS handshake to fail due to JA3 blacklist, got no error")
    }
    if !strings.Contains(err.Error(), "handshake") {
        t.Fatalf("unexpected error, want handshake failure, got %v", err)
    }
    srv2.Close()
}

func TestTLSHandshakeIPBlacklist(t *testing.T) {
    addr := "localhost:" + getPort(testPort)
    dir := path.Join("internal", "tests", "data")

    srv := &http.Server{
        Addr: addr,
        Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            fmt.Fprint(w, "ok")
        }),
        TLSConfig: &tls.Config{
            IPBlacklist: []string{"127.0.0.1"},
        },
    }
    go srv.ListenAndServeTLS(path.Join(dir, "localhost.crt"), path.Join(dir, "localhost.key"))

    client := newInsecureClient()
    _, err := client.Get("https://" + addr)
    if err == nil {
        t.Fatalf("expected TLS handshake to fail due to IP blacklist, got no error")
    }
    if !strings.Contains(err.Error(), "handshake") {
        t.Fatalf("unexpected error, want handshake failure, got %v", err)
    }
    srv.Close()
}
