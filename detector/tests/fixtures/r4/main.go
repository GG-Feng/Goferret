package main

import (
	"bufio"
	"compress/gzip"
	"io"
	"net/http"
	"os"
)

type Object interface{ GetAnnotations() map[string]string }

type ClientConfig struct{ Address string }

// R4: decompression without a bound (a limited compressed body still expands)
func FetchGzip(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

// R4 negative: bounded body
func ReadBounded(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	b, _ := io.ReadAll(r.Body)
	_ = b
}

// R4 negative: local stdin is not network input
func ReadStdin() {
	data, _ := io.ReadAll(bufio.NewReader(os.Stdin))
	_ = data
}

// return summary + annotation source + destination field (SSRF)
func addrFromObject(obj Object) string {
	a := obj.GetAnnotations()
	return a["example.com/addr"]
}

func NewClient(obj Object) *ClientConfig {
	cfg := &ClientConfig{}
	cfg.Address = addrFromObject(obj)
	return cfg
}

// SSRF in a handler (direct): query value as outbound URL
func Proxy(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("u")
	resp, err := http.Get(target)
	if err == nil {
		resp.Body.Close()
	}
}

// negative: stdin line as a file path is local operator input
func SaveFromStdin() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	name := sc.Text()
	f, _ := os.Create(name)
	f.Close()
}

// negative (v3.3): a client built from the request; its response is the remote
// server's data, and response headers are not request input
func clientFor(r *http.Request) *http.Client { return http.DefaultClient }

func UserInfo(w http.ResponseWriter, r *http.Request) {
	client := clientFor(r)
	resp, err := client.Get("https://idp.example/userinfo")
	if err != nil {
		return
	}
	n := resp.Header.Get("X-Count")
	_ = n
	data, _ := io.ReadAll(resp.Body)
	_ = data
}
