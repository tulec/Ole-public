package controlclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportIdentitiesRejectInsecureAuthorityAndRedirects(t *testing.T) {
	for _, address := range []string{"http://192.0.2.1:8080", "http://remote.example", "ftp://127.0.0.1", "https://user:password@example.com"} {
		if _, err := New(address).TransportIdentities("peer-a"); err == nil {
			t.Fatal("unsafe authority accepted")
		}
	}
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.Write([]byte(`{"data":{}}`)) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if _, err := New(redirect.URL).TransportIdentities("peer-a"); err == nil {
		t.Fatal("identity redirect accepted")
	}
	if hits != 0 {
		t.Fatal("identity request followed redirect")
	}
}
