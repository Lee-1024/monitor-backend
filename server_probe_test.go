package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateServerProbeTargetRequiresTCPHostAndPort(t *testing.T) {
	target := &ServerProbeTarget{Name: "db", Type: "tcp", IntervalSeconds: 10, TimeoutSeconds: 1}

	err := validateServerProbeTarget(target)

	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestRunServerProbeTCPSucceedsAgainstListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	target := ServerProbeTarget{
		Name:           "tcp-ok",
		Type:           "tcp",
		Host:           "127.0.0.1",
		Port:           listener.Addr().(*net.TCPAddr).Port,
		TimeoutSeconds: 1,
	}

	result := runServerProbe(target)

	if result.Status != serverProbeStatusUp {
		t.Fatalf("status = %q, want up, error=%s", result.Status, result.Error)
	}
}

func TestRunServerProbeTCPFailsForUnusedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	target := ServerProbeTarget{
		Name:           "tcp-down",
		Type:           "tcp",
		Host:           "127.0.0.1",
		Port:           port,
		TimeoutSeconds: 1,
	}

	result := runServerProbe(target)

	if result.Status != serverProbeStatusDown {
		t.Fatalf("status = %q, want down", result.Status)
	}
	if result.Error == "" {
		t.Fatal("expected failure reason")
	}
}

func TestRunServerProbeHTTPSucceedsFor2xxAnd3xx(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			result := runServerProbe(ServerProbeTarget{Name: "http-ok", Type: "http", URL: server.URL, TimeoutSeconds: 1})

			if result.Status != serverProbeStatusUp {
				t.Fatalf("status = %q, want up, error=%s", result.Status, result.Error)
			}
			if result.HTTPStatus != status {
				t.Fatalf("HTTPStatus = %d, want %d", result.HTTPStatus, status)
			}
		})
	}
}

func TestRunServerProbeHTTPFailsFor4xxAnd5xx(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			result := runServerProbe(ServerProbeTarget{Name: "http-down", Type: "http", URL: server.URL, TimeoutSeconds: 1})

			if result.Status != serverProbeStatusDown {
				t.Fatalf("status = %q, want down", result.Status)
			}
			if result.HTTPStatus != status {
				t.Fatalf("HTTPStatus = %d, want %d", result.HTTPStatus, status)
			}
		})
	}
}
