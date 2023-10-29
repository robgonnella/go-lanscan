// SPDX-License-Identifier: GPL-3.0-or-later

package util_test

import (
	"testing"

	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestSliceIncludes(t *testing.T) {
	t.Run("returns true if slice includes value", func(st *testing.T) {
		s := []string{"a", "b", "c"}
		included := util.SliceIncludes(s, "b")
		assert.True(st, included)
	})

	t.Run("returns false if slice does not include value", func(st *testing.T) {
		s := []string{"a", "b", "c"}
		included := util.SliceIncludes(s, "d")
		assert.False(st, included)
	})
}

func TestSliceIncludesFunc(t *testing.T) {
	t.Run("returns true if callback returns true", func(st *testing.T) {
		s := []string{"a", "b", "c"}
		included := util.SliceIncludesFunc(s, func(v string, idx int) bool {
			return v == "b"
		})
		assert.True(st, included)
	})

	t.Run("returns false if callback returns false", func(st *testing.T) {
		s := []string{"a", "b", "c"}
		included := util.SliceIncludesFunc(s, func(v string, idx int) bool {
			return v == "d"
		})
		assert.False(st, included)
	})
}

func TestFilterSlice(t *testing.T) {
	t.Run("filters slice", func(st *testing.T) {
		s := []string{"a", "b", "c"}
		filteredSlice := util.FilterSlice(s, func(v string) bool {
			return v != "b"
		})

		assert.Equal(st, 2, len(filteredSlice))
		assert.Equal(st, "a", filteredSlice[0])
		assert.Equal(st, "c", filteredSlice[1])
	})
}
