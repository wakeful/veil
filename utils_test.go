// Copyright 2025 variHQ OÜ
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
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
