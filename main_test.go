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
