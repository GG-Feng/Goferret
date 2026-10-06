package main

import (
	"fmt"
	"net/http"

	"example.com/r6fx/proto"
)

type DB interface{ Query(q string) error }

// cross-package return + second result: msg.Path lands in the URL path
func Loop(c proto.Conn, host string) {
	msg, _, err := proto.Read(c)
	if err != nil {
		return
	}
	forward(msg, host)
}

func forward(m proto.Msg, host string) {
	u := fmt.Sprintf("http://%s:%d%s", host, 8080, m.Path)
	http.Get(u)
}

// string-built query in a non-SQL query language
func Lookup(db DB, r *http.Request) {
	name := r.FormValue("name")
	db.Query("{ user(func: eq(name, \"" + name + "\")) { uid } }")
}

// reflected into an HTML-capable response
func Echo(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello %s", r.FormValue("n"))
}

// negative: text/plain response
func EchoPlain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "hello %s", r.FormValue("n"))
}
