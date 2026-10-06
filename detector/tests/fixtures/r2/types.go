package main

import "os"

type API struct{}
type Body struct{ Path string }
type Input struct{ Body Body }

func Register(api *API, op string, h interface{})  {}
func (a *API) Register(path string, h interface{}) {}

func openIt(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	return f.Close()
}
