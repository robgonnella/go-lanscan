// SPDX-License-Identifier: GPL-3.0-or-later

package util_test

import (
	"errors"
	"net"
	"testing"

	"github.com/robgonnella/go-lanscan/internal/util"
	"github.com/stretchr/testify/assert"
)

func TestLoopNetIPHosts(t *testing.T) {
	t.Run("loops over ipnet hosts", func(st *testing.T) {
		_, ipnet, err := net.ParseCIDR("172.16.1.1/28")

		totalHosts := 16
		callbackCalledCount := 0

		assert.NoError(st, err)

		callback := func(ip net.IP) error {
			callbackCalledCount++
			return nil
		}

		err = util.LoopNetIPHosts(ipnet, callback)

		assert.NoError(st, err)

		assert.Equal(st, totalHosts, callbackCalledCount)
	})

	t.Run("returns error if callback returns error", func(st *testing.T) {
		_, ipnet, err := net.ParseCIDR("172.16.1.1/28")

		assert.NoError(st, err)

		testErr := errors.New("test loop ipnet hosts error")

		callback := func(ip net.IP) error {
			return testErr
		}

		actualErr := util.LoopNetIPHosts(ipnet, callback)

		assert.Error(st, actualErr)

		assert.ErrorIs(st, testErr, actualErr)
	})
}

func TestIPHostTotal(t *testing.T) {
	t.Run("returns total host count for ipnet", func(st *testing.T) {
		_, ipnet, err := net.ParseCIDR("172.16.1.1/28")

		assert.NoError(st, err)

		expectedTotalHosts := 16

		totalHosts := util.IPHostTotal(ipnet)

		assert.Equal(st, expectedTotalHosts, totalHosts)
	})
}

func TestLoopTargets(t *testing.T) {
	t.Run("loops both cidr targets and non-cidr targets", func(st *testing.T) {
		targets := []string{
			"172.16.1.1/28",
			"172.17.1.1-172.17.1.3",
			"172.17.1.5",
		}

		callbackCalledCount := 0

		callback := func(ip net.IP) error {
			callbackCalledCount++
			return nil
		}

		err := util.LoopTargets(targets, callback)

		assert.NoError(st, err)

		assert.Equal(st, 20, callbackCalledCount)
	})

	t.Run("returns error if fails to parse cidr", func(st *testing.T) {
		targets := []string{
			"1/28",
		}

		callback := func(ip net.IP) error {
			return nil
		}

		err := util.LoopTargets(targets, callback)

		assert.Error(st, err)
	})

	t.Run("returns error if loop ipnet callback returns error", func(st *testing.T) {
		targets := []string{
			"172.16.1.1/28",
		}

		testErr := errors.New("test error looping ipnet targets")

		callback := func(ip net.IP) error {
			return testErr
		}

		actualErr := util.LoopTargets(targets, callback)

		assert.Error(st, actualErr)
		assert.ErrorIs(st, testErr, actualErr)
	})

	t.Run("returns error if loop range callback returns error", func(st *testing.T) {
		targets := []string{
			"172.17.1.1-172.17.1.3",
		}

		testErr := errors.New("test error looping range targets")

		callback := func(ip net.IP) error {
			return testErr
		}

		actualErr := util.LoopTargets(targets, callback)

		assert.Error(st, actualErr)
		assert.ErrorIs(st, testErr, actualErr)
	})

	t.Run("returns error if loop single target callback returns error", func(st *testing.T) {
		targets := []string{
			"172.17.1.1",
		}

		testErr := errors.New("test error looping single target")

		callback := func(ip net.IP) error {
			return testErr
		}

		actualErr := util.LoopTargets(targets, callback)

		assert.Error(st, actualErr)
		assert.ErrorIs(st, testErr, actualErr)
	})
}

func TestTotalTargets(t *testing.T) {
	t.Run("returns total count of targets", func(st *testing.T) {
		targets := []string{
			"172.16.1.1/28",
			"172.17.1.1-172.17.1.3",
			"172.17.1.5",
		}

		expectedTotal := 20

		total := util.TotalTargets(targets)

		assert.Equal(st, expectedTotal, total)
	})
}

func TestTargetsHas(t *testing.T) {
	t.Run("returns true if targets contains ip", func(st *testing.T) {
		targets := []string{
			"172.16.1.1/28",
			"172.17.1.1-172.17.1.3",
			"172.17.1.5",
		}

		target := net.ParseIP("172.16.1.5")

		hasTarget := util.TargetsHas(targets, target)

		assert.True(st, hasTarget)
	})

	t.Run("returns false if targets does not contains ip", func(st *testing.T) {
		targets := []string{
			"172.16.1.1/28",
			"172.17.1.1-172.17.1.3",
			"172.17.1.5",
		}

		target := net.ParseIP("172.17.1.6")

		hasTarget := util.TargetsHas(targets, target)

		assert.False(st, hasTarget)
	})
}

func TestLoopPorts(t *testing.T) {
	t.Run("loops ports", func(st *testing.T) {
		ports := []string{
			"1-10",
			"22",
		}

		callbackCalledCount := 0
		expectedCallCount := 11

		callback := func(p uint16) error {
			callbackCalledCount++
			return nil
		}

		err := util.LoopPorts(ports, callback)

		assert.NoError(st, err)

		assert.Equal(st, expectedCallCount, callbackCalledCount)
	})

	t.Run("returns error for invalid port range", func(st *testing.T) {
		ports := []string{
			"-",
			"22",
		}

		callback := func(p uint16) error {
			return nil
		}

		err := util.LoopPorts(ports, callback)

		assert.Error(st, err)
	})

	t.Run("returns error for invalid port starting range", func(st *testing.T) {
		ports := []string{
			"abc-10",
		}

		callback := func(p uint16) error {
			return nil
		}

		err := util.LoopPorts(ports, callback)

		assert.Error(st, err)
	})

	t.Run("returns error for invalid port ending range", func(st *testing.T) {
		ports := []string{
			"1-abc",
		}

		callback := func(p uint16) error {
			return nil
		}

		err := util.LoopPorts(ports, callback)

		assert.Error(st, err)
	})

	t.Run("returns error for invalid port value", func(st *testing.T) {
		ports := []string{
			"abc",
		}

		callback := func(p uint16) error {
			return nil
		}

		err := util.LoopPorts(ports, callback)

		assert.Error(st, err)
	})

	t.Run("returns error if callback returns error for range", func(st *testing.T) {
		ports := []string{
			"1-10",
		}

		testErr := errors.New("test error looping port range")

		callback := func(p uint16) error {
			return testErr
		}

		err := util.LoopPorts(ports, callback)

		assert.Error(st, err)

		assert.ErrorIs(st, testErr, err)
	})

	t.Run("returns error if callback returns error for single port value", func(st *testing.T) {
		ports := []string{
			"22",
		}

		testErr := errors.New("test error looping port single value")

		callback := func(p uint16) error {
			return testErr
		}

		err := util.LoopPorts(ports, callback)

		assert.Error(st, err)

		assert.ErrorIs(st, testErr, err)
	})
}

func TestPortTotal(t *testing.T) {
	t.Run("returns total port count", func(st *testing.T) {
		ports := []string{
			"1-10",
			"22",
		}

		expectedTotal := 11

		total := util.PortTotal(ports)

		assert.Equal(st, expectedTotal, total)
	})
}
