// Copyright 2025 variHQ OÜ
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Items is a slice of strings that supports unmarshalling from JSON arrays, single strings, or null values.
type Items []string

// UnmarshalJSON implements json.Unmarshaler for Items.
// It parses JSON into a slice of strings, supporting arrays, single strings, and null values.
// It returns an error if the input is not a valid string or slice of strings.
func (i *Items) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		*i = nil

		return nil
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 4 && bytes.EqualFold(trimmed, []byte("null")) {
		*i = nil

		return nil
	}

	var (
		single string
		err    error
	)

	if err = json.Unmarshal(data, &single); err == nil {
		*i = []string{single}

		return nil
	}

	var many []string
	if err = json.Unmarshal(data, &many); err == nil {
		*i = many

		return nil
	}

	return fmt.Errorf("failed to parse raw message: not a string or array %w", err)
}

var _ json.Unmarshaler = (*Items)(nil)

// TrustPolicy represents a policy that defines trust relationships for roles,
// including associated permissions and access control rules.
type TrustPolicy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// getAllPrincipals returns a deduplicated list of principals from the trust policy statements.
func (p *TrustPolicy) getAllPrincipals() []string {
	output := make([]string, 0)
	for _, statement := range p.Statement {
		output = append(output, statement.Principal.getAll()...)
	}

	return uniqSlice(output)
}

// Statement represents a single entry in a policy that defines permissions and access control rules.
// It specifies the effect, principal entities, and actions that are allowed or denied.
type Statement struct {
	Effect    string    `json:"Effect"`
	Principal Principal `json:"Principal"`
	Action    Items     `json:"Action"`
}

// Principal represents an entity that can perform actions or access resources in an AWS policy statement.
// It includes fields for various principal types: Service, AWS, Federated, CanonicalUser, and Anonymous.
type Principal struct {
	Service       Items `json:"Service"`
	AWS           Items `json:"AWS"`
	Federated     Items `json:"Federated"`
	CanonicalUser Items `json:"CanonicalUser"`
	Anonymous     Items `json:"*"`
}

// getAll returns a deduplicated list of principal identifiers across Service, AWS, Federated, CanonicalUser,
// and Anonymous types.
func (p *Principal) getAll() []string {
	capacity := len(
		p.Service,
	) + len(
		p.AWS,
	) + len(
		p.Federated,
	) + len(
		p.CanonicalUser,
	) + len(
		p.Anonymous,
	)
	allItems := make([]string, 0, capacity)

	allItems = append(allItems, p.Service...)
	allItems = append(allItems, p.AWS...)
	allItems = append(allItems, p.Federated...)
	allItems = append(allItems, p.CanonicalUser...)
	allItems = append(allItems, p.Anonymous...)

	return uniqSlice(allItems)
}
