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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sync"

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

	client, err := NewApp(ctx, *region)
	if err != nil {
		slog.Error("failed to initialize app", slog.String("error", err.Error()))

		return
	}

	output, err := client.getRolesWithTrust(ctx)
	if err != nil {
		slog.Error("failed to fetch IAM roles", slog.String("error", err.Error()))

		return
	}

	flip := mapFlip(output)
	slog.Debug(
		"found IAM roles and principals",
		slog.Int("roles", len(output)),
		slog.Int("principals", len(flip)),
	)

	marshal, err := json.MarshalIndent(flip, "", "  ")
	if err != nil {
		slog.Error("failed to marshal output", slog.String("error", err.Error()))

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

// NewApp initialises and returns a new App instance configured with the provided region and context.
func NewApp(ctx context.Context, region string) (*App, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
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

	if err := group.Wait(); err != nil {
		return nil, fmt.Errorf("failed to process IAM roles trust policies: %w", err)
	}

	return output, nil
}
