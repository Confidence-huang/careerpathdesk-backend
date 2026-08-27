/*
一次性生产老板初始化入口：从三个 root:root 0600 普通文件读取最小身份与随机临时密码。
命令只反馈固定成功/失败状态；输入内容、路径和生成的账号 ID 都不会进入终端输出。
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/bootstrap"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/config"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/identity"
	"github.com/confidence-huang/careerpathdesk-backend/internal/platform/postgres"
)

var errInvalidBootstrapArguments = errors.New("owner bootstrap arguments are invalid")
var errInvalidBootstrapFile = errors.New("owner bootstrap file is invalid")
var errBootstrapProductionOnly = errors.New("owner bootstrap command is production-only")

const bootstrapUsernamePath = "/run/careerpathdesk-production/bootstrap-owner-username"
const bootstrapDisplayNamePath = "/run/careerpathdesk-production/bootstrap-owner-display-name"
const bootstrapPasswordPath = "/run/careerpathdesk-production/bootstrap-owner-password"

type bootstrapOwnerArguments struct {
	usernameFile    string
	displayNameFile string
	passwordFile    string
}

type bootstrapOwnerResult struct {
	accountCount int
}

func main() {
	result, bootstrapError := runBootstrapOwner(os.Args[1:], os.Getenv, 0)
	if bootstrapError != nil {
		fmt.Fprintln(os.Stderr, "FAIL: production owner bootstrap was not completed")
		os.Exit(1)
	}
	fmt.Printf("careerpathdesk-bootstrap-owner status=ok accounts=%d must_change_password=true\n", result.accountCount)
}

func runBootstrapOwner(arguments []string, getEnvironmentValue func(string) string, requiredOwnerUID uint32) (bootstrapOwnerResult, error) {
	options, parseError := parseBootstrapOwnerArguments(arguments)
	if parseError != nil {
		return bootstrapOwnerResult{}, parseError
	}
	database, configurationError := config.LoadDatabase(getEnvironmentValue)
	if configurationError != nil {
		return bootstrapOwnerResult{}, configurationError
	}
	if database.RuntimeMode != "production" {
		return bootstrapOwnerResult{}, errBootstrapProductionOnly
	}
	username, usernameError := readBootstrapValue(options.usernameFile, requiredOwnerUID)
	displayName, displayNameError := readBootstrapValue(options.displayNameFile, requiredOwnerUID)
	password, passwordError := readBootstrapValue(options.passwordFile, requiredOwnerUID)
	if usernameError != nil || displayNameError != nil || passwordError != nil {
		return bootstrapOwnerResult{}, errInvalidBootstrapFile
	}

	connection, connectError := postgres.Connect(context.Background(), database)
	if connectError != nil {
		return bootstrapOwnerResult{}, connectError
	}
	defer func() { _ = connection.Close(context.Background()) }()
	commands, constructionError := bootstrap.New(connection, identity.New)
	if constructionError != nil {
		return bootstrapOwnerResult{}, constructionError
	}
	if _, bootstrapError := commands.Bootstrap(context.Background(), bootstrap.Input{
		Username: username, DisplayName: displayName, Password: password,
	}); bootstrapError != nil {
		return bootstrapOwnerResult{}, bootstrapError
	}
	return bootstrapOwnerResult{accountCount: 1}, nil
}

func parseBootstrapOwnerArguments(arguments []string) (bootstrapOwnerArguments, error) {
	flags := flag.NewFlagSet("careerpathdesk-bootstrap-owner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	usernameFile := flags.String("username-file", "", "root-owned 0600 one-time username file")
	displayNameFile := flags.String("display-name-file", "", "root-owned 0600 one-time display-name file")
	passwordFile := flags.String("password-file", "", "root-owned 0600 one-time password file")
	if parseError := flags.Parse(arguments); parseError != nil || flags.NArg() != 0 {
		return bootstrapOwnerArguments{}, errInvalidBootstrapArguments
	}
	if *usernameFile != bootstrapUsernamePath || *displayNameFile != bootstrapDisplayNamePath || *passwordFile != bootstrapPasswordPath {
		return bootstrapOwnerArguments{}, errInvalidBootstrapArguments
	}
	return bootstrapOwnerArguments{usernameFile: *usernameFile, displayNameFile: *displayNameFile, passwordFile: *passwordFile}, nil
}

// readBootstrapValue 用一个 nofollow 文件描述符完成身份、权限和内容读取，避免检查后替换目标。
func readBootstrapValue(path string, requiredOwnerUID uint32) (string, error) {
	fileDescriptor, openError := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if openError != nil {
		return "", errInvalidBootstrapFile
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	if file == nil {
		_ = unix.Close(fileDescriptor)
		return "", errInvalidBootstrapFile
	}
	defer func() { _ = file.Close() }()
	information, statError := file.Stat()
	unixInformation := unix.Stat_t{}
	fstatError := unix.Fstat(fileDescriptor, &unixInformation)
	if statError != nil || fstatError != nil || !information.Mode().IsRegular() || information.Mode().Perm() != 0o600 || unixInformation.Uid != requiredOwnerUID {
		return "", errInvalidBootstrapFile
	}
	valueBytes, readError := io.ReadAll(io.LimitReader(file, 4097))
	if readError != nil || len(valueBytes) > 4096 {
		return "", errInvalidBootstrapFile
	}
	value := strings.TrimSpace(string(valueBytes))
	if value == "" {
		return "", errInvalidBootstrapFile
	}
	return value, nil
}
