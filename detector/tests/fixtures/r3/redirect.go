package main

import (
	"net/http"
	"strings"
)

// weak: a leading "/" also accepts "//evil.example"
func validateRedirectTarget(next string) (string, bool) {
	if !strings.HasPrefix(next, "/") {
		return "", false
	}
	return next, true
}

// strong: rejects protocol-relative targets
func validateStrictRedirect(next string) (string, bool) {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "", false
	}
	return next, true
}

func checkNotEmpty(s string) string { return s }

func validateInternal(s string) error {
	if s == "" {
		return nil
	}
	return nil
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	if target, ok := validateRedirectTarget(r.FormValue("next")); ok {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	if target, ok := validateStrictRedirect(r.FormValue("next2")); ok {
		http.Redirect(w, r, target, http.StatusFound)
	}
	t := checkNotEmpty(r.FormValue("x"))
	http.Redirect(w, r, t, http.StatusFound)
}

func internalJob() {
	_ = validateInternal("constant")
}
