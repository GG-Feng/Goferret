package main

import (
	"context"
	"net/http"
)

type Router struct{}

func (r *Router) GET(path string, h func(w http.ResponseWriter, req *http.Request)) {}

// three handlers registered inline; two check the caller, one does not
func Routes(r *Router, store Store) {
	r.GET("/items/get", func(w http.ResponseWriter, req *http.Request) {
		it, _ := store.GetItem(context.Background(), req.URL.Query().Get("id"))
		if MustHaveUser(req.Context()).Name != it.Owner {
			return
		}
	})
	r.GET("/items/url", func(w http.ResponseWriter, req *http.Request) {
		id := req.URL.Query().Get("id")
		store.GetItemURL(context.Background(), id)
	})
	r.GET("/items/delete", func(w http.ResponseWriter, req *http.Request) {
		it, _ := store.GetItem(context.Background(), req.URL.Query().Get("id"))
		if MustHaveUser(req.Context()).Name == it.Owner {
			store.DeleteItem(context.Background(), req.URL.Query().Get("id"))
		}
	})
}
