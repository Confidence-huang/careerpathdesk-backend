/*
CareerPathDesk production migration 入口：只从一个身份精确匹配的不可变发布根前滚 schema。
命令不 seed、不降级、不删表，也不会从当前目录猜测 migration 或发布身份。
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/migrate"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/postgres"
)

var errInvalidProductionMigrationArguments = errors.New("production migration arguments are invalid")
var errProductionMigrationOnly = errors.New("production migration command is production-only")
var errReleaseIdentityMismatch = errors.New("production release identity does not match")
var errProductionMigrationSetMismatch = errors.New("production migration set does not match schema contract")
var fullReleaseSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

type productionMigrationArguments struct {
	migrationDirectory string
	expectedReleaseSHA string
}

func main() {
	migrationCount, migrateError := migrateProduction(os.Args[1:], os.Getenv)
	if migrateError != nil {
		fmt.Fprintln(os.Stderr, "FAIL: production migration was not completed")
		os.Exit(1)
	}
	fmt.Printf("careerpathdesk-migrate-production status=ok migrations=%d schema=%d\n", migrationCount, config.SupportedSchemaVersion)
}

// migrateProduction 验证配置和发布身份后，才建立生产数据库连接并前滚完整 migration 集合。
func migrateProduction(arguments []string, getEnvironmentValue func(string) string) (int, error) {
	options, parseError := parseProductionArguments(arguments)
	if parseError != nil {
		return 0, parseError
	}
	database, configurationError := config.LoadDatabase(getEnvironmentValue)
	if configurationError != nil {
		return 0, configurationError
	}
	if database.RuntimeMode != "production" {
		return 0, errProductionMigrationOnly
	}
	if identityError := verifyReleaseIdentity(options.migrationDirectory, options.expectedReleaseSHA); identityError != nil {
		return 0, identityError
	}
	migrations, loadError := migrate.Load(os.DirFS(options.migrationDirectory))
	if loadError != nil {
		return 0, loadError
	}
	if migrationSetError := validateProductionMigrations(migrations); migrationSetError != nil {
		return 0, migrationSetError
	}

	connection, connectError := postgres.Connect(context.Background(), database)
	if connectError != nil {
		return 0, connectError
	}
	defer func() { _ = connection.Close(context.Background()) }()
	if applyError := migrate.Apply(context.Background(), connection, migrations); applyError != nil {
		return 0, applyError
	}
	return len(migrations), nil
}

func parseProductionArguments(arguments []string) (productionMigrationArguments, error) {
	flags := flag.NewFlagSet("careerpathdesk-migrate-production", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	migrationDirectory := flags.String("migration-dir", "", "absolute reviewed production migration directory")
	expectedReleaseSHA := flags.String("expected-release-sha", "", "full immutable release SHA")
	if parseError := flags.Parse(arguments); parseError != nil || flags.NArg() != 0 {
		return productionMigrationArguments{}, errInvalidProductionMigrationArguments
	}
	if !filepath.IsAbs(*migrationDirectory) || filepath.Clean(*migrationDirectory) != *migrationDirectory || !fullReleaseSHA.MatchString(*expectedReleaseSHA) {
		return productionMigrationArguments{}, errInvalidProductionMigrationArguments
	}
	if filepath.Base(*migrationDirectory) != "migrations" || filepath.Base(filepath.Dir(*migrationDirectory)) != "database" {
		return productionMigrationArguments{}, errInvalidProductionMigrationArguments
	}
	return productionMigrationArguments{migrationDirectory: *migrationDirectory, expectedReleaseSHA: *expectedReleaseSHA}, nil
}

// verifyReleaseIdentity 把 migration 路径绑定到同一不可变发布根的精确 RELEASE-SHA。
func verifyReleaseIdentity(migrationDirectory string, expectedReleaseSHA string) error {
	databaseDirectory := filepath.Dir(migrationDirectory)
	releaseRoot := filepath.Dir(databaseDirectory)
	for _, directory := range []string{releaseRoot, databaseDirectory, migrationDirectory} {
		information, statError := os.Lstat(directory)
		if statError != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
			return errReleaseIdentityMismatch
		}
	}

	identityPath := filepath.Join(releaseRoot, "RELEASE-SHA")
	fileDescriptor, openError := unix.Open(identityPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if openError != nil {
		return errReleaseIdentityMismatch
	}
	identityFile := os.NewFile(uintptr(fileDescriptor), identityPath)
	if identityFile == nil {
		_ = unix.Close(fileDescriptor)
		return errReleaseIdentityMismatch
	}
	defer func() { _ = identityFile.Close() }()
	information, statError := identityFile.Stat()
	if statError != nil || !information.Mode().IsRegular() || information.Size() != 41 {
		return errReleaseIdentityMismatch
	}
	identityBytes, readError := io.ReadAll(io.LimitReader(identityFile, 42))
	if readError != nil || string(identityBytes) != expectedReleaseSHA+"\n" {
		return errReleaseIdentityMismatch
	}
	return nil
}

func validateProductionMigrations(migrations []migrate.Migration) error {
	if len(migrations) != int(config.SupportedSchemaVersion) {
		return errProductionMigrationSetMismatch
	}
	for index, migration := range migrations {
		if migration.Version != int64(index+1) {
			return errProductionMigrationSetMismatch
		}
	}
	return nil
}
