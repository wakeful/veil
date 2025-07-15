// Copyright 2025 variHQ OÜ
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"reflect"
	"testing"
)

func TestItems_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected Items
		wantErr  bool
	}{
		{
			name:     "empty data",
			input:    []byte{},
			expected: nil,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var items Items

			err := items.UnmarshalJSON(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("UnmarshalJSON() expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Errorf("UnmarshalJSON() unexpected error: %v", err)

				return
			}

			if !reflect.DeepEqual(items, tt.expected) {
				t.Errorf("UnmarshalJSON() got = %v, want %v", items, tt.expected)
			}
		})
	}
}
