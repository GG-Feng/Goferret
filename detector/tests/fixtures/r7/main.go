package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"

	"example.com/r7fx/api"
)

type Store interface{ Query(q string) error }

// tagged struct parameter: its fields are decoded data; api.Pick passes the value through
func Invoke(call api.ToolCall, cfg api.Config) {
	p := api.Pick(call.Path, cfg.Root)
	http.Get(fmt.Sprintf("http://backend:8080/%s", p))
}

// map[string]any parameter (dynamic decoded data) handed to a helper
func Dispatch(args map[string]any) {
	buildURL("svc", args)
}

var registry = map[string]any{} // filled by a decoder elsewhere

func buildURL(host string, params map[string]any) {
	id, _ := registry["id"].(string) // pulled out of an untyped container of unknown provenance
	u := fmt.Sprintf("https://%s/api/%s", host, id)
	http.Get(u)
}

// value asserted out of an interface is decoded data
func checkPassword(db Store, arg any) {
	pw := arg.(string)
	db.Query("{ check(pwd: \"" + pw + "\") }")
}

type Parser struct{ repoDir string }

// method value stored in a FuncMap literal: the template engine calls it with
// template-controlled arguments
func (p *Parser) funcs() template.FuncMap {
	return template.FuncMap{"readFile": p.readFile}
}

func (p *Parser) readFile(path string) string {
	b, _ := os.ReadFile(p.repoDir + "/" + path)
	return string(b)
}

// a path taken from the content of a file the program was handed
func loadSpec(specFile string) {
	f, _ := os.Open(specFile)
	sc := bufio.NewScanner(f)
	sc.Scan()
	target := strings.TrimSpace(sc.Text())
	os.ReadFile(target)
}

// negative: the operator's console is not data the program was handed
func fromStdin() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	os.ReadFile(sc.Text())
}

// negative: plain internal helper with an untagged struct
func helper(cfg api.Config) {
	os.ReadFile(cfg.Root)
}

// external data rendered by a template into the path of a URL object
func resolvePath(base *url.URL, tmpl *template.Template, params map[string]any) string {
	id, _ := registry["id"].(string)
	var buf bytes.Buffer
	tmpl.Execute(&buf, id)
	rel, _ := url.Parse(buf.String())
	return base.ResolveReference(rel).String()
}
