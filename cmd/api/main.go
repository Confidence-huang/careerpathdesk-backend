/* CareerPathDesk API 进程入口：加载配置，复用唯一应用组合，并管理 Linux 信号与 HTTP 生命周期。 */
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/confidence-huang/careerpathdesk-backend/internal/application"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"
)

var version = "development"

func main() {
	if startError := startApplication(); startError != nil {
		log.Printf("careerpathdesk-api status=failed reason=%v", startError)
		os.Exit(1)
	}
}

func startApplication() error {
	configuration, loadError := config.Load(os.Getenv)
	if loadError != nil {
		return loadError
	}
	assembled, openError := application.Open(context.Background(), configuration, version)
	if openError != nil {
		return openError
	}
	defer assembled.Close()

	stopContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	server := &http.Server{
		Addr: configuration.HTTPAddr, Handler: assembled.Handler,
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second,
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.ListenAndServe() }()
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
