package cache

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGrantReleaseCapabilityAndServiceUpperBound(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, requested := range []bool{false, true} {
			name := map[bool]string{false: "service-off", true: "service-on"}[enabled] + "/" + map[bool]string{false: "archive-only", true: "release-requested"}[requested]
			t.Run(name, func(t *testing.T) {
				var upstreams atomic.Int32
				upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					upstreams.Add(1)
					w.Header().Set("ETag", `"grant-fixture"`)
					w.Header().Set("Content-Length", "7")
					if r.Method == http.MethodGet {
						_, _ = io.WriteString(w, "payload")
					}
				}))
				defer upstream.Close()
				service, _, client := testService(t, upstream)
				defer client.CloseIdleConnections()
				if enabled {
					service.EnableReleaseProxy()
				}
				data, err := service.Issue("guest", GrantCapabilities{ReleaseProxy: requested})
				if err != nil {
					t.Fatal(err)
				}
				defer clear(data)
				var bootstrap Bootstrap
				if json.Unmarshal(data, &bootstrap) != nil {
					t.Fatal("invalid bootstrap")
				}
				if bootstrap.ReleaseProxy != (enabled && requested) {
					t.Fatal("service upper bound missing from issued capability")
				}
				// Ordinary archive traffic works for every grant, including archive-only.
				lease := makeLease(t, bootstrap, client, upstream.URL)
				response, err := client.Get(lease)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || string(payload) != "payload" {
					t.Fatal("archive capability lost", err)
				}
				calls := upstreams.Load()
				for _, method := range []string{http.MethodConnect, http.MethodGet} {
					request := httptest.NewRequest(method, "https://github.com:444/", nil)
					request.Header.Set("Proxy-Authorization", "Bearer "+bootstrap.Token)
					recorder := httptest.NewRecorder()
					service.ServeHTTP(recorder, request)
					want := http.StatusNotFound
					if enabled {
						want = http.StatusProxyAuthRequired
						if requested {
							want = http.StatusForbidden
						}
					}
					if recorder.Code != want {
						t.Fatal("host release capability not enforced", method, recorder.Code)
					}
				}
				if calls != upstreams.Load() {
					t.Fatal("release refusal reached an upstream")
				}
				if !enabled {
					// Enabling a service feature later cannot upgrade already issued tokens.
					service.EnableReleaseProxy()
					request := httptest.NewRequest(http.MethodConnect, "https://github.com:443/", nil)
					request.Header.Set("Proxy-Authorization", "Bearer "+bootstrap.Token)
					recorder := httptest.NewRecorder()
					service.ServeHTTP(recorder, request)
					if recorder.Code != http.StatusProxyAuthRequired {
						t.Fatal("issued grant gained unrequested authority")
					}
				}
				service.Revoke("guest")
				request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
				request.Header.Set("Authorization", "Bearer "+bootstrap.Token)
				recorder := httptest.NewRecorder()
				service.ServeHTTP(recorder, request)
				if recorder.Code == http.StatusOK || strings.Contains(recorder.Body.String(), bootstrap.Token) {
					t.Fatal("revocation or private error response")
				}
			})
		}
	}
}
