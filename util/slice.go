// SPDX-License-Identifier: GPL-3.0-or-later

package util

/**
 * Generic shared utilities
 */

// SliceIncludes helper for detecting if a slice includes a value
func SliceIncludes[T comparable](s []T, val T) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}
	return false
}

// SliceIncludesFunc similar to SliceIncludes but using callback
func SliceIncludesFunc[T comparable](s []T, f func(v T, idx int) bool) bool {
	for i, v := range s {
		if f(v, i) {
			return true
		}
	}
	return false
}

// FilterSlice filters a slice into a new slice
func FilterSlice[T comparable](s []T, f func(v T) bool) []T {
	newSlice := []T{}

	for _, v := range s {
		if f(v) {
			newSlice = append(newSlice, v)
		}
	}

	return newSlice
}
