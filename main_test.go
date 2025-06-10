// Copyright 2025 variHQ OÜ
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type MockServiceIAM struct {
	mockRoles    []types.Role
	mockRolesErr error
}

func (m MockServiceIAM) ListRoles(
	_ context.Context,
	_ *iam.ListRolesInput,
	_ ...func(*iam.Options),
) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: m.mockRoles}, m.mockRolesErr
}

var _ ServiceIAM = (*MockServiceIAM)(nil)

func TestApp_getRolesWithTrust(t *testing.T) {
	t.Parallel()
	withTimeout, _ := context.WithTimeout(t.Context(), -time.Second) //nolint:govet
	invalidRoles := []types.Role{
		{
			Arn:                      aws.String("arn:aws:iam::123456789012:role/test"),
			AssumeRolePolicyDocument: aws.String("invalid policy"),
		},
	}
	tests := []struct {
		name    string
		ctx     context.Context //nolint:containedctx
		client  ServiceIAM
		want    map[string][]string
		wantErr bool
	}{
		{
			name: "failed to list roles",
			ctx:  t.Context(),
			client: &MockServiceIAM{
				mockRoles:    []types.Role{},
				mockRolesErr: errors.New("test error"),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "no roles found",
			ctx:     t.Context(),
			client:  &MockServiceIAM{},
			want:    map[string][]string{},
			wantErr: false,
		},
		{
			name: "found roles with invalid trust policy",
			ctx:  t.Context(),
			client: &MockServiceIAM{
				mockRoles: invalidRoles,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "fail with ctx timeout",
			ctx:  withTimeout,
			client: &MockServiceIAM{
				mockRoles: invalidRoles,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "success with decoding",
			ctx:  t.Context(),
			client: &MockServiceIAM{
				mockRoles: []types.Role{
					{
						Arn: aws.String(
							"arn:aws:iam::0123456789:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_FullAdmin",
						),
						AssumeRolePolicyDocument: aws.String(fixtureAWSReservedSSOFullAdmin),
					},
				},
			},
			want: map[string][]string{
				"arn:aws:iam::0123456789:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_FullAdmin": {
					"arn:aws:iam::0123456789:saml-provider/AWSSSO_24_DO_NOT_DELETE",
					"arn:aws:iam::0123456789:saml-provider/AWSSSO_42_DO_NOT_DELETE",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := &App{
				client: tt.client,
			}

			got, err := a.getRolesWithTrust(tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("getRolesWithTrust() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getRolesWithTrust() got = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockConfigLoader struct {
	mockConfig    aws.Config
	mockConfigErr error
}

//nolint:nonamedreturns
func (m *mockConfigLoader) LoadDefaultConfig(
	_ context.Context,
	_ ...func(*config.LoadOptions) error,
) (cfg aws.Config, err error) {
	return m.mockConfig, m.mockConfigErr
}

var _ ConfigLoader = (*mockConfigLoader)(nil)

func TestNewApp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		loader  ConfigLoader
		region  string
		wantApp bool
		wantErr bool
	}{
		{
			name:    "empty region",
			loader:  nil,
			region:  "",
			wantApp: false,
			wantErr: true,
		},
		{
			name: "config loader error",
			loader: &mockConfigLoader{
				mockConfigErr: errors.New("test error"),
			},
			region:  "eu-west-1",
			wantApp: false,
			wantErr: true,
		},
		{
			name: "success setup with mock config",
			loader: &mockConfigLoader{
				mockConfig: aws.Config{},
			},
			region:  "eu-west-1",
			wantApp: true,
			wantErr: false,
		},
		{
			name:    "success setup with default config",
			loader:  nil,
			region:  "eu-west-1",
			wantApp: true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewApp(t.Context(), tt.region, tt.loader)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewApp() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if (got != nil) != tt.wantApp {
				t.Errorf("got app = %v, want non-nil: %v", got, tt.wantApp)
			}
		})
	}
}

func TestApp_runScanIAM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		client  ServiceIAM
		want    []byte
		wantErr bool
	}{
		{
			name: "success",
			client: &MockServiceIAM{
				mockRoles: []types.Role{
					{
						Arn: aws.String(
							"arn:aws:iam::0123456789:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_FullAdmin",
						),
						AssumeRolePolicyDocument: aws.String(fixtureAWSReservedSSOFullAdmin),
					},
				},
			},
			want: []byte{
				123, 10, 32, 32, 34, 97, 114, 110, 58, 97, 119, 115, 58, 105, 97, 109, 58, 58, 48, 49, 50, 51, 52, 53,
				54, 55, 56, 57, 58, 115, 97, 109, 108, 45, 112, 114, 111, 118, 105, 100, 101, 114, 47, 65, 87, 83, 83,
				83, 79, 95, 50, 52, 95, 68, 79, 95, 78, 79, 84, 95, 68, 69, 76, 69, 84, 69, 34, 58, 32, 91, 10, 32, 32,
				32, 32, 34, 97, 114, 110, 58, 97, 119, 115, 58, 105, 97, 109, 58, 58, 48, 49, 50, 51, 52, 53, 54, 55,
				56, 57, 58, 114, 111, 108, 101, 47, 97, 119, 115, 45, 114, 101, 115, 101, 114, 118, 101, 100, 47, 115,
				115, 111, 46, 97, 109, 97, 122, 111, 110, 97, 119, 115, 46, 99, 111, 109, 47, 65, 87, 83, 82, 101, 115,
				101, 114, 118, 101, 100, 83, 83, 79, 95, 70, 117, 108, 108, 65, 100, 109, 105, 110, 34, 10, 32, 32, 93,
				44, 10, 32, 32, 34, 97, 114, 110, 58, 97, 119, 115, 58, 105, 97, 109, 58, 58, 48, 49, 50, 51, 52, 53,
				54, 55, 56, 57, 58, 115, 97, 109, 108, 45, 112, 114, 111, 118, 105, 100, 101, 114, 47, 65, 87, 83, 83,
				83, 79, 95, 52, 50, 95, 68, 79, 95, 78, 79, 84, 95, 68, 69, 76, 69, 84, 69, 34, 58, 32, 91, 10, 32, 32,
				32, 32, 34, 97, 114, 110, 58, 97, 119, 115, 58, 105, 97, 109, 58, 58, 48, 49, 50, 51, 52, 53, 54, 55,
				56, 57, 58, 114, 111, 108, 101, 47, 97, 119, 115, 45, 114, 101, 115, 101, 114, 118, 101, 100, 47, 115,
				115, 111, 46, 97, 109, 97, 122, 111, 110, 97, 119, 115, 46, 99, 111, 109, 47, 65, 87, 83, 82, 101, 115,
				101, 114, 118, 101, 100, 83, 83, 79, 95, 70, 117, 108, 108, 65, 100, 109, 105, 110, 34, 10, 32, 32, 93,
				10, 125,
			},
			wantErr: false,
		},
		{
			name: "failed to list roles",
			client: &MockServiceIAM{
				mockRoles:    []types.Role{},
				mockRolesErr: errors.New("test error"),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			a := &App{
				client: tt.client,
			}

			got, err := a.runScanIAM(t.Context())
			if (err != nil) != tt.wantErr {
				t.Errorf("runScanIAM() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("runScanIAM() got = %v, want %v", got, tt.want)
			}
		})
	}
}
