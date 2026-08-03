package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireHTTPMethod(t *testing.T) {
	t.Run("accepts expected method", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		if !requireHTTPMethod(recorder, request, http.MethodGet) {
			t.Fatal("expected GET to be accepted")
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d, want untouched 200 recorder default", recorder.Code)
		}
	})

	t.Run("rejects and advertises expected method", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/healthz", nil)
		if requireHTTPMethod(recorder, request, http.MethodGet) {
			t.Fatal("expected POST to be rejected")
		}
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status=%d, want 405", recorder.Code)
		}
		if got := recorder.Header().Get("Allow"); got != http.MethodGet {
			t.Fatalf("Allow=%q, want GET", got)
		}
		if !strings.Contains(recorder.Body.String(), `"error":"GET only"`) {
			t.Fatalf("unexpected JSON error: %s", recorder.Body.String())
		}
	})
}
