/* 显式 synthetic 重置入口：只接受固定 seed 文件并在一个事务恢复确定性基线。 */
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/postgres"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/secret"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/seed"
)

func main() {
	if resetError := run(); resetError != nil {
		fmt.Fprintln(os.Stderr, "FAIL: synthetic reset was not completed")
		os.Exit(1)
	}
	fmt.Println("PASS: synthetic baseline reset")
}

func run() error {
	arguments := flag.NewFlagSet("reset-synthetic", flag.ContinueOnError)
	seedFile := arguments.String("seed-file", "", "reviewed synthetic seed SQL")
	if parseError := arguments.Parse(os.Args[1:]); parseError != nil || *seedFile == "" || arguments.NArg() != 0 {
		return errors.New("invalid reset arguments")
	}
	configuration, configurationError := config.LoadSyntheticSeed(os.Getenv)
	if configurationError != nil {
		return configurationError
	}
	seedSQL, readError := os.ReadFile(*seedFile)
	if readError != nil {
		return readError
	}
	connection, connectError := postgres.Connect(context.Background(), configuration.Database)
	if connectError != nil {
		return connectError
	}
	defer func() { _ = connection.Close(context.Background()) }()
	accountPassword, accountPasswordError := secret.Read(configuration.AccountPasswordFile)
	if accountPasswordError != nil {
		return errors.New("synthetic account password unavailable")
	}
	_, resetError := seed.Reset(context.Background(), connection, string(seedSQL), configuration.ExpectedSchemaVersion, accountPassword)
	return resetError
}
