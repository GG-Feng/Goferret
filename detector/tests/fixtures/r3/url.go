package main

import (
	"errors"
	"net/url"
	"strings"
)

type Record struct{ Homepage, Site string }

// weak for a URL that is later rendered: parse + scheme only
func validateHomepageURL(homepageURL string) error {
	u, err := url.Parse(homepageURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return errors.New("https only")
	}
	return nil
}

// strong: rejects quotes, angle brackets and whitespace
func validateStrictURL(siteURL string) error {
	if strings.ContainsAny(siteURL, "\"'<> \t\n") {
		return errors.New("bad characters")
	}
	_, err := url.Parse(siteURL)
	return err
}

func HandleSave(rec *Record) error {
	if err := validateHomepageURL(rec.Homepage); err != nil {
		return err
	}
	return validateStrictURL(rec.Site)
}

func Routes(mux *Mux) {
	mux.HandleFunc("/save", HandleSave)
}

type Mux struct{}

func (m *Mux) HandleFunc(p string, h interface{}) {}
