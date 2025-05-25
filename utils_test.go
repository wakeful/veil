// Copyright 2025 variHQ OÜ
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	_ "embed"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func Test_mapFlip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input map[string][]string
		want  map[string][]string
	}{
		{
			name: "simple",
			input: map[string][]string{
				"role1": {"principal1", "principal2"},
				"role2": {"principal1", "principal3"},
			},
			want: map[string][]string{
				"principal1": {"role1", "role2"},
				"principal2": {"role1"},
				"principal3": {"role2"},
			},
		},
		{
			name:  "empty",
			input: map[string][]string{},
			want:  map[string][]string{},
		},
		{
			name:  "nil",
			input: nil,
			want:  map[string][]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := mapFlip(tt.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mapFlip() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		verbose          *bool
		testMessage      string
		useLevel         slog.Level
		expectInOutput   bool
		testOutputSearch string
	}{
		{
			name:             "returns configured logger with verbose=false",
			verbose:          aws.Bool(false),
			testMessage:      "debug message",
			useLevel:         slog.LevelDebug,
			expectInOutput:   false,
			testOutputSearch: "debug message",
		},
		{
			name:             "enables debug logging when verbose=true",
			verbose:          aws.Bool(true),
			testMessage:      "debug message",
			useLevel:         slog.LevelDebug,
			expectInOutput:   true,
			testOutputSearch: "debug message",
		},
		{
			name:             "info messages are always logged",
			verbose:          aws.Bool(false),
			testMessage:      "info message",
			useLevel:         slog.LevelInfo,
			expectInOutput:   true,
			testOutputSearch: "info message",
		},
		{
			name:             "handles nil verbose flag",
			verbose:          nil,
			testMessage:      "info message",
			useLevel:         slog.LevelInfo,
			expectInOutput:   true,
			testOutputSearch: "info message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer

			logger := getLogger(&buf, tt.verbose)

			if logger == nil {
				t.Fatal("Expected logger to not be nil")
			}

			switch tt.useLevel {
			case slog.LevelDebug:
				logger.Debug(tt.testMessage)
			case slog.LevelInfo:
				logger.Info(tt.testMessage)
			case slog.LevelWarn:
				logger.Warn(tt.testMessage)
			case slog.LevelError:
				logger.Error(tt.testMessage)
			}

			logOutput := buf.String()
			containsMessage := strings.Contains(logOutput, tt.testOutputSearch)

			if containsMessage != tt.expectInOutput {
				if tt.expectInOutput {
					t.Errorf("Expected log output to contain '%s', but it did not. Got: %s",
						tt.testOutputSearch, logOutput)
				} else {
					t.Errorf("Expected log output to NOT contain '%s', but it did. Got: %s",
						tt.testOutputSearch, logOutput)
				}
			}
		})
	}
}

func Test_uniqSlice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name: "simple",
			input: []string{
				"c",
				"a",
				"b",
				"c",
				"a",
				"b",
				"c",
			},
			want: []string{
				"a",
				"b",
				"c",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := uniqSlice(tt.input); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("uniqSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

var (
	//go:embed fixtures/AWSServiceRoleForECS.json
	fixtureAWSServiceRoleForECS string
	//go:embed fixtures/AWSReservedSSOFullAdmin.json
	fixtureAWSReservedSSOFullAdmin string
	//go:embed fixtures/EmptyAction.json
	fixtureEmptyAction string
	//go:embed fixtures/InvalidDataTypeNumber.json
	fixtureInvalidDataTypeNumber string
)

func Test_decodeRoleTrust(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		role    types.Role
		want    TrustPolicy
		wantErr bool
	}{
		{
			name: "failed to decode trust policy",
			role: types.Role{
				Arn:                      aws.String("arn:aws:iam::0123456789:trust/test"),
				AssumeRolePolicyDocument: aws.String("test%2x"),
			},
			want:    TrustPolicy{},
			wantErr: true,
		},
		{
			name: "invalid trust policy",
			role: types.Role{
				Arn:                      aws.String("arn:aws:iam::0123456789:trust/test"),
				AssumeRolePolicyDocument: aws.String("test"),
			},
			want:    TrustPolicy{},
			wantErr: true,
		},
		{
			name: "empty trust policy",
			role: types.Role{
				Arn:                      aws.String("arn:aws:iam::0123456789:trust/test"),
				AssumeRolePolicyDocument: aws.String("{}"),
			},
			want:    TrustPolicy{},
			wantErr: false,
		},
		{
			name: "valid trust policy",
			role: types.Role{
				Arn: aws.String(
					"arn:aws:iam::0123456789:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS",
				),
				AssumeRolePolicyDocument: aws.String(fixtureAWSServiceRoleForECS),
			},
			want: TrustPolicy{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect: "Allow",
						Principal: Principal{
							Service: Items{"ecs.amazonaws.com"},
						},
						Action: Items{"sts:AssumeRole"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid trust policy with array",
			role: types.Role{
				Arn: aws.String(
					"arn:aws:iam::0123456789:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_FullAdmin",
				),
				AssumeRolePolicyDocument: aws.String(fixtureAWSReservedSSOFullAdmin),
			},
			want: TrustPolicy{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect: "Allow",
						Principal: Principal{
							Federated: Items{
								"arn:aws:iam::0123456789:saml-provider/AWSSSO_24_DO_NOT_DELETE",
								"arn:aws:iam::0123456789:saml-provider/AWSSSO_42_DO_NOT_DELETE",
							},
						},
						Action: []string{"sts:AssumeRoleWithSAML", "sts:TagSession"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "null action value",
			role: types.Role{
				Arn:                      aws.String("arn:aws:iam::0123456789:role/test-role"),
				AssumeRolePolicyDocument: aws.String(fixtureEmptyAction),
			},
			want: TrustPolicy{
				Version: "2012-10-17",
				Statement: []Statement{
					{
						Effect: "Allow",
						Principal: Principal{
							Service: Items{"lambda.amazonaws.com"},
						},
						Action: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid data type (number)",
			role: types.Role{
				Arn:                      aws.String("arn:aws:iam::0123456789:role/test-role"),
				AssumeRolePolicyDocument: aws.String(fixtureInvalidDataTypeNumber),
			},
			want:    TrustPolicy{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeRoleTrust(tt.role)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeRoleTrust() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decodeRoleTrust() got = %v, want %v", got, tt.want)
			}
		})
	}
}
