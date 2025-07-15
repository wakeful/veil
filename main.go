// Copyright 2025 variHQ OÜ
// SPDX-License-Identifier: BSD-3-Clause

// Package main provides a tool for analysing AWS IAM role trust relationships.
//
// It outputs a JSON representation of the trust relationships, making it easier to
// audit and understand the trust configuration of IAM roles in an AWS account.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"golang.org/x/sync/errgroup"
)

var version = "dev"

func main() {
	region := flag.String("region", "eu-west-1", "AWS region used for IAM communication")
	showVersion := flag.Bool("version", false, "show version")
	verbose := flag.Bool("verbose", false, "verbose log output")
	flag.Parse()

	slog.SetDefault(getLogger(os.Stderr, verbose))

	if *showVersion {
		slog.Info(
			"veil",
			slog.String("repo", "https://github.com/wakeful/veil"),
			slog.String("version", version),
		)

		return
	}

	ctx := context.Background()

	client, err := NewApp(ctx, *region, &DefaultConfigLoader{})
	if err != nil {
		slog.Error("failed to initialize app", slog.String("error", err.Error()))

		return
	}

	marshal, err := client.runScanIAM(ctx)
	if err != nil {
		slog.Error("failed to scan IAM roles", slog.String("error", err.Error()))

		return
	}

	_, _ = os.Stdout.Write(marshal)
}

// ServiceIAM lists IAM roles via AWS SDK clients.
type ServiceIAM interface {
	iam.ListRolesAPIClient
}

// App represents a struct that provides functionality for interacting with the AWS IAM service.
type App struct {
	client ServiceIAM
}

var _ iam.ListRolesAPIClient = (ServiceIAM)(nil)

var errEmptyRegion = errors.New("region cannot be empty")

// ConfigLoader defines an interface for loading AWS SDK configurations with customisable options.
type ConfigLoader interface {
	LoadDefaultConfig(
		ctx context.Context,
		optFns ...func(*config.LoadOptions) error,
	) (cfg aws.Config, err error)
}

// DefaultConfigLoader provides functionality for loading default AWS SDK configurations with optional customisation.
type DefaultConfigLoader struct{}

// LoadDefaultConfig loads the default AWS SDK configuration with optional modifications using the provided option
// functions.
//
//nolint:nonamedreturns
func (d DefaultConfigLoader) LoadDefaultConfig(
	ctx context.Context,
	optFns ...func(*config.LoadOptions) error,
) (cfg aws.Config, err error) {
	return config.LoadDefaultConfig(ctx, optFns...) //nolint:wrapcheck
}

var _ ConfigLoader = (*DefaultConfigLoader)(nil)

// NewApp initialises and returns a new App instance configured with the provided region and context.
func NewApp(ctx context.Context, region string, loader ConfigLoader) (*App, error) {
	if region == "" {
		return nil, errEmptyRegion
	}

	if loader == nil {
		loader = DefaultConfigLoader{}
	}

	cfg, err := loader.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config, %w", err)
	}

	return &App{
		client: iam.NewFromConfig(cfg),
	}, nil
}

func (a *App) getRolesWithTrust(ctx context.Context) (map[string][]string, error) {
	var mutex sync.Mutex

	output := make(map[string][]string)
	group, gCtx := errgroup.WithContext(ctx)

	paginator := iam.NewListRolesPaginator(a.client, &iam.ListRolesInput{
		Marker:     nil,
		MaxItems:   nil,
		PathPrefix: nil,
	})
	for paginator.HasMorePages() {
		page, errListRoles := paginator.NextPage(gCtx)
		if errListRoles != nil {
			return nil, fmt.Errorf("failed to list roles: %w", errListRoles)
		}

		for _, role := range page.Roles {
			group.Go(func() error {
				select {
				case <-gCtx.Done():
					return gCtx.Err()
				default:
					policy, errDecodeTrust := decodeRoleTrust(role)
					if errDecodeTrust != nil {
						return fmt.Errorf("failed to decode role trust policy: %w", errDecodeTrust)
					}

					mutex.Lock()
					defer mutex.Unlock()

					output[*role.Arn] = policy.getAllPrincipals()

					return nil
				}
			})
		}
	}

	err := group.Wait()
	if err != nil {
		return nil, fmt.Errorf("failed to process IAM roles trust policies: %w", err)
	}

	return output, nil
}

func (a *App) runScanIAM(ctx context.Context) ([]byte, error) {
	output, err := a.getRolesWithTrust(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IAM roles: %w", err)
	}

	flip := mapFlip(output)
	slog.Debug(
		"found IAM roles and principals",
		slog.Int("roles", len(output)),
		slog.Int("principals", len(flip)),
	)

	marshal, err := json.MarshalIndent(flip, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal output: %w", err)
	}

	return marshal, nil
}
