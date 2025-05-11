// Copyright 2025 variHQ OÜ
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"sort"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// uniqSlice returns a sorted slice with duplicates removed from the input.
// It uses a map to track unique elements and logs the input and output sizes for debugging.
func uniqSlice(input []string) []string {
	hashMap := make(map[string]struct{}, len(input))

	for _, item := range input {
		hashMap[item] = struct{}{}
	}

	output := make([]string, 0, len(hashMap))
	for item := range hashMap {
		output = append(output, item)
	}

	slog.Debug("uniq output", slog.Int("input", len(input)), slog.Int("output", len(output)))

	sort.Strings(output)

	return output
}

// decodeRoleTrust decodes an IAM role's trust policy document into a TrustPolicy.
// It unescapes the URL-encoded document, unmarshals the JSON, and returns the policy or an error.
func decodeRoleTrust(role types.Role) (TrustPolicy, error) {
	slog.Debug("decoding trust policy", slog.String("role", *role.Arn))

	data, err := url.QueryUnescape(*role.AssumeRolePolicyDocument)
	if err != nil {
		return TrustPolicy{}, fmt.Errorf("failed to unescape URL: %w", err)
	}

	var policy TrustPolicy
	if errUnmarshal := json.Unmarshal([]byte(data), &policy); errUnmarshal != nil {
		return TrustPolicy{}, fmt.Errorf("failed to unmarshal JSON: %w", errUnmarshal)
	}

	return policy, nil
}

// getLogger returns a slog.Logger configured with the given output and log level.
// If verbose is true, the log level is set to debug; otherwise, it defaults to info.
func getLogger(output io.Writer, verbose *bool) *slog.Logger {
	logLevel := slog.LevelInfo
	if verbose != nil && *verbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(
		slog.NewTextHandler(output, &slog.HandlerOptions{
			AddSource:   false,
			Level:       logLevel,
			ReplaceAttr: nil,
		}),
	)

	return logger
}

// mapFlip inverts a map from strings to slices of strings, producing a map from each value in the slices
// to its corresponding key.
func mapFlip(input map[string][]string) map[string][]string {
	output := make(map[string][]string)

	for role, principals := range input {
		for _, principal := range principals {
			output[principal] = append(output[principal], role)
		}
	}

	return output
}
