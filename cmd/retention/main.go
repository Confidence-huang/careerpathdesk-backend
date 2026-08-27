/*
生产保留维护入口：dry-run 只输出匿名摘要；execute 只消费新鲜 0600 确认文件并重算同一摘要。
命令不接受 force、默认时间、默认数据库或 positional 参数。
*/
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/confidence-huang/careerpathdesk-backend/internal/auth"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/postgres"
	"github.com/confidence-huang/careerpathdesk-backend/internal/privacy"
)

var errInvalidArguments = errors.New("retention arguments are invalid")
var errInvalidConfirmation = errors.New("retention confirmation is invalid")
var errProductionOnly = errors.New("retention command is production-only")

type commandArguments struct {
	mode             string
	asOf             time.Time
	confirmationFile string
}

type confirmation struct {
	ownerAccountID string
	asOf           time.Time
	digest         string
}

type confirmationDocument struct {
	OwnerAccountID string `json:"owner_account_id"`
	AsOf           string `json:"as_of"`
	Digest         string `json:"digest"`
}

func main() {
	if runError := run(os.Args[1:], os.Getenv, os.Stdout, time.Now().UTC()); runError != nil {
		fmt.Fprintln(os.Stderr, "FAIL: retention maintenance was not completed")
		os.Exit(1)
	}
}

func run(arguments []string, getEnvironmentValue func(string) string, output io.Writer, now time.Time) error {
	options, parseError := parseArguments(arguments)
	if parseError != nil {
		return parseError
	}
	database, configurationError := config.LoadDatabase(getEnvironmentValue)
	if configurationError != nil {
		return configurationError
	}
	if database.RuntimeMode != "production" {
		return errProductionOnly
	}
	connection, connectError := postgres.Connect(context.Background(), database)
	if connectError != nil {
		return connectError
	}
	defer func() { _ = connection.Close(context.Background()) }()
	commands, constructionError := privacy.NewRetentionCommands(connection, func() time.Time { return now.UTC() })
	if constructionError != nil {
		return constructionError
	}
	if options.mode == "dry-run" {
		summary, dryRunError := commands.DryRun(context.Background(), options.asOf)
		if dryRunError != nil {
			return dryRunError
		}
		return json.NewEncoder(output).Encode(summary)
	}
	confirmed, readError := readConfirmation(options.confirmationFile, now.UTC())
	if readError != nil {
		return readError
	}
	currentSummary, dryRunError := commands.DryRun(context.Background(), confirmed.asOf)
	if dryRunError != nil || currentSummary.Digest != confirmed.digest {
		return errInvalidConfirmation
	}
	executed, executeError := commands.Execute(context.Background(), auth.Account{ID: confirmed.ownerAccountID, Role: "owner", State: "active"}, confirmed.asOf, confirmed.digest)
	if executeError != nil {
		return executeError
	}
	return json.NewEncoder(output).Encode(executed)
}

func parseArguments(arguments []string) (commandArguments, error) {
	flags := flag.NewFlagSet("careerpathdesk-retention", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "", "dry-run or execute")
	asOfText := flags.String("as-of", "", "explicit RFC3339 dry-run boundary")
	confirmationFile := flags.String("confirmation-file", "", "protected execute confirmation")
	if parseError := flags.Parse(arguments); parseError != nil || flags.NArg() != 0 {
		return commandArguments{}, errInvalidArguments
	}
	if *mode == "dry-run" {
		asOf, parseError := time.Parse(time.RFC3339, *asOfText)
		if parseError != nil || *confirmationFile != "" {
			return commandArguments{}, errInvalidArguments
		}
		return commandArguments{mode: *mode, asOf: asOf.UTC()}, nil
	}
	if *mode == "execute" && *asOfText == "" && filepath.IsAbs(*confirmationFile) && filepath.Clean(*confirmationFile) == *confirmationFile {
		return commandArguments{mode: *mode, confirmationFile: *confirmationFile}, nil
	}
	return commandArguments{}, errInvalidArguments
}

func readConfirmation(path string, now time.Time) (confirmation, error) {
	fileDescriptor, openError := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if openError != nil {
		return confirmation{}, errInvalidConfirmation
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	if file == nil {
		_ = unix.Close(fileDescriptor)
		return confirmation{}, errInvalidConfirmation
	}
	defer func() { _ = file.Close() }()
	information, statError := file.Stat()
	if statError != nil || !information.Mode().IsRegular() || information.Mode().Perm() != 0o600 {
		return confirmation{}, errInvalidConfirmation
	}
	age := now.UTC().Sub(information.ModTime().UTC())
	if age < -time.Minute || age > 10*time.Minute {
		return confirmation{}, errInvalidConfirmation
	}
	body, readError := io.ReadAll(io.LimitReader(file, 4097))
	if readError != nil || len(body) > 4096 {
		return confirmation{}, errInvalidConfirmation
	}
	document := confirmationDocument{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decodeError := decoder.Decode(&document); decodeError != nil {
		return confirmation{}, errInvalidConfirmation
	}
	if trailingError := decoder.Decode(&struct{}{}); !errors.Is(trailingError, io.EOF) {
		return confirmation{}, errInvalidConfirmation
	}
	asOf, parseError := time.Parse(time.RFC3339, document.AsOf)
	digestBytes, digestError := hex.DecodeString(strings.ToLower(document.Digest))
	if parseError != nil || digestError != nil || len(digestBytes) != 32 || !validOwnerAccountID(document.OwnerAccountID) {
		return confirmation{}, errInvalidConfirmation
	}
	return confirmation{ownerAccountID: document.OwnerAccountID, asOf: asOf.UTC(), digest: strings.ToLower(document.Digest)}, nil
}

func validOwnerAccountID(value string) bool {
	return len(value) >= 15 && len(value) <= 83 && strings.HasPrefix(value, "A-")
}
