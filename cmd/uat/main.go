/* 本地 UAT 入口：只在 synthetic 回环或精确私网 HTTPS 配置下复用完整 API，并从已构建目录提供同源 Vue SPA。 */
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/confidence-huang/careerpathdesk-backend/internal/application"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"
)

const uatAddress = "127.0.0.1:9692"
const uatOrigin = "http://localhost:9692"

func main() {
	if startError := start(); startError != nil {
		log.Printf("careerpathdesk-uat status=failed reason=%v", startError)
		os.Exit(1)
	}
}

func start() error {
	configuration, loadError := config.Load(os.Getenv)
	if loadError != nil {
		return loadError
	}
	if configuration.RuntimeMode != "synthetic" || validateUATNetworkBoundary(configuration.HTTPAddr, configuration.PublicOrigin) != nil {
		return errors.New("UAT runtime boundary is invalid")
	}
	staticDirectory, directoryError := resolveStaticDirectory(os.Getenv("CAREERPATH_UAT_STATIC_DIR"))
	if directoryError != nil {
		return directoryError
	}
	assembled, openError := application.Open(context.Background(), configuration, "uat")
	if openError != nil {
		return openError
	}
	defer assembled.Close()

	handler := sameOriginHandler(assembled.Handler, staticDirectory)
	server := &http.Server{Addr: configuration.HTTPAddr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	stopContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	serveResult := make(chan error, 1)
	go func() {
		if configuration.PublicOrigin == uatOrigin {
			serveResult <- server.ListenAndServe()
			return
		}
		serveResult <- server.ListenAndServeTLS(os.Getenv("CAREERPATH_UAT_TLS_CERT_FILE"), os.Getenv("CAREERPATH_UAT_TLS_KEY_FILE"))
	}()
	select {
	case serveError := <-serveResult:
		if errors.Is(serveError, http.ErrServerClosed) {
			return nil
		}
		return serveError
	case <-stopContext.Done():
	}
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	return server.Shutdown(shutdownContext)
}

// validateUATNetworkBoundary 保留本机回环，同时只允许精确 RFC1918 地址通过 HTTPS 给宿主 Edge 验收。
func validateUATNetworkBoundary(httpAddress string, publicOrigin string) error {
	if httpAddress == uatAddress && publicOrigin == uatOrigin {
		return nil
	}
	host, port, splitError := net.SplitHostPort(httpAddress)
	if splitError != nil || port != "9692" {
		return errors.New("UAT address is invalid")
	}
	address, parseError := netip.ParseAddr(host)
	if parseError != nil || !address.Is4() || !address.IsPrivate() || address.IsLoopback() || address.IsUnspecified() {
		return errors.New("UAT host is not an exact private IPv4 address")
	}
	expectedOrigin := "https://" + net.JoinHostPort(host, port)
	if publicOrigin != expectedOrigin {
		return errors.New("UAT private origin must use matching HTTPS")
	}
	return nil
}

func resolveStaticDirectory(raw string) (string, error) {
	if raw == "" || !filepath.IsAbs(raw) {
		return "", errors.New("UAT static directory is invalid")
	}
	resolved, resolveError := filepath.EvalSymlinks(raw)
	if resolveError != nil {
		return "", errors.New("UAT static directory is unavailable")
	}
	info, statError := os.Stat(filepath.Join(resolved, "index.html"))
	if statError != nil || info.IsDir() {
		return "", errors.New("UAT frontend build is unavailable")
	}
	return resolved, nil
}

func sameOriginHandler(api http.Handler, staticDirectory string) http.Handler {
	files := http.FileServer(http.Dir(staticDirectory))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Frame-Options", "DENY")
		if strings.HasPrefix(request.URL.Path, "/api/") {
			api.ServeHTTP(writer, request)
			return
		}
		cleanPath := filepath.Clean("/" + request.URL.Path)
		candidate := filepath.Join(staticDirectory, strings.TrimPrefix(cleanPath, "/"))
		if info, statError := os.Stat(candidate); statError == nil && !info.IsDir() {
			files.ServeHTTP(writer, request)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		http.ServeFile(writer, request, filepath.Join(staticDirectory, "index.html"))
	})
}
