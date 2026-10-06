package main

import (
	"context"
	"net/http"
	"os/exec"

	"example.com/r2fx/store"
)

type Finder interface {
	Lookup(user string, attrs []string) (string, error)
}

type Server struct {
	db  Finder
	req *http.Request
}

// 1 hop through a package call: query value -> store.Run -> exec.Command
func HandleRun(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("n")
	store.Run(name)
}

// interface call (name dispatch): request accessor on a stored request
func (s *Server) Auth() {
	r := s.req
	user, _, ok := r.BasicAuth()
	if !ok {
		return
	}
	s.db.Lookup(user, nil)
}

// closure registered as a handler: 2 hops (validate -> openIt)
func RegisterRoutes(api *API) {
	Register(api, "op", func(ctx context.Context, in *Input) error {
		return validate(&in.Body)
	})
	api.Register("/msg", onMsg)
}

func validate(b *Body) error {
	return openIt(b.Path)
}

// registered by reference
func onMsg(msg string) {
	exec.Command("sh", "-c", msg).Run()
}

// only constants reach it
func internalOnly() {
	store.Run("ls")
}

// 5 hops: beyond the limit
func HandleDeep(w http.ResponseWriter, r *http.Request) {
	d1(r.FormValue("x"))
}
func d1(a string) { d2(a) }
func d2(a string) { d3(a) }
func d3(a string) { d4(a) }
func d4(a string) { d5(a) }
func d5(a string) { exec.Command(a).Run() }

func HandleRepo(w http.ResponseWriter, r *http.Request) {
	repo := &store.Repo{}
	repo.Delete(r.FormValue("id"))
	repo.Rename(r.FormValue("n"))
	repo.Find(r.FormValue("q"))
}
