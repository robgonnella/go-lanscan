package core_test

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/robgonnella/go-lanscan/internal/core"
	mock_scanner "github.com/robgonnella/go-lanscan/mock/scanner"
	"github.com/robgonnella/go-lanscan/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestDeviceResult(t *testing.T) {
	t.Run("is serializable", func(st *testing.T) {
		mac, _ := net.ParseMAC("00:00:00:00:00:00")
		result := &core.DeviceResult{
			IP:     net.ParseIP("127.0.0.1"),
			MAC:    mac,
			Vendor: "unknown",
			Status: scanner.StatusOnline,
			OpenPorts: []scanner.Port{
				{
					ID:      22,
					Service: "ssh",
					Status:  scanner.PortOpen,
				},
			},
		}

		serializable := result.Serializable()

		serialized, err := json.Marshal(serializable)

		assert.NoError(st, err)

		resultMap := map[string]interface{}{}

		err = json.Unmarshal(serialized, &resultMap)

		assert.NoError(st, err)

		openPorts := resultMap["openPorts"].([]interface{})
		port := openPorts[0].(map[string]interface{})

		assert.Equal(st, resultMap["ip"], result.IP.String())
		assert.Equal(st, resultMap["mac"], result.MAC.String())
		assert.Equal(st, resultMap["vendor"], result.Vendor)
		assert.Equal(st, resultMap["status"], string(result.Status))
		assert.Equal(st, port["id"], float64(22))
		assert.Equal(st, port["service"], "ssh")
		assert.Equal(st, port["status"], string(scanner.PortOpen))

	})
}

func TestResults(t *testing.T) {
	t.Run("converts to serializable then marshals json", func(st *testing.T) {
		mac, _ := net.ParseMAC("00:00:00:00:00:00")
		deviceResult := &core.DeviceResult{
			IP:     net.ParseIP("127.0.0.1"),
			MAC:    mac,
			Vendor: "unknown",
			Status: scanner.StatusOnline,
			OpenPorts: []scanner.Port{
				{
					ID:      22,
					Service: "ssh",
					Status:  scanner.PortOpen,
				},
			},
		}

		results := &core.Results{
			Devices: []*core.DeviceResult{deviceResult},
		}

		data, err := results.MarshalJSON()

		assert.NoError(st, err)

		assert.NotNil(st, data)

		unmarshalResults := []interface{}{}

		err = json.Unmarshal(data, &unmarshalResults)

		assert.NoError(st, err)

		device := unmarshalResults[0].(map[string]interface{})

		openPorts := device["openPorts"].([]interface{})
		port := openPorts[0].(map[string]interface{})

		assert.Equal(st, device["ip"], deviceResult.IP.String())
		assert.Equal(st, device["mac"], deviceResult.MAC.String())
		assert.Equal(st, device["vendor"], deviceResult.Vendor)
		assert.Equal(st, device["status"], string(deviceResult.Status))
		assert.Equal(st, port["id"], float64(22))
		assert.Equal(st, port["service"], "ssh")
		assert.Equal(st, port["status"], string(scanner.PortOpen))
	})
}

func TestCore(t *testing.T) {
	ctrl := gomock.NewController(t)

	defer ctrl.Finish()

	t.Run("initializes", func(st *testing.T) {
		mockScanner := mock_scanner.NewMockScanner(ctrl)

		mockScanner.EXPECT().SetRequestNotifications(gomock.Any())

		runner := core.New()

		runner.Initialize(
			mockScanner,
			make(chan *scanner.ScanResult),
			1,
			1,
			false,
			false,
			false,
		)
	})

	t.Run("initialization disables logging when noProgress is true", func(st *testing.T) {
		mockScanner := mock_scanner.NewMockScanner(ctrl)

		runner := core.New()

		runner.Initialize(
			mockScanner,
			make(chan *scanner.ScanResult),
			1,
			1,
			true,
			true,
			true,
		)
	})

	t.Run("handles scanner error", func(st *testing.T) {
		mockScanner := mock_scanner.NewMockScanner(ctrl)

		runner := core.New()

		scanResults := make(chan *scanner.ScanResult)

		mockScanner.EXPECT().SetRequestNotifications(gomock.Any())

		mockScanner.EXPECT().Scan().DoAndReturn(func() error {
			return errors.New("mock scanner error")
		})

		runner.Initialize(
			mockScanner,
			scanResults,
			1,
			1,
			false,
			true,
			false,
		)

		err := runner.Run()

		assert.Error(st, err)
	})

	t.Run("performs arp only scan and prints text table", func(st *testing.T) {
		mockScanner := mock_scanner.NewMockScanner(ctrl)

		runner := core.New()

		scanResults := make(chan *scanner.ScanResult)

		mockScanner.EXPECT().SetRequestNotifications(gomock.Any())

		mockScanner.EXPECT().Scan().DoAndReturn(func() error {
			mac, _ := net.ParseMAC("00:00:00:00:00:00")
			scanResults <- &scanner.ScanResult{
				Type: scanner.ARPResult,
				Payload: &scanner.ArpScanResult{
					IP:     net.ParseIP("172.17.0.1"),
					MAC:    mac,
					Vendor: "Apple",
				},
			}
			time.AfterFunc(time.Second, func() {
				scanResults <- &scanner.ScanResult{
					Type: scanner.ARPDone,
				}
			})
			return nil
		})

		mockScanner.EXPECT().Stop()

		runner.Initialize(
			mockScanner,
			scanResults,
			1,
			1,
			false,
			true,
			false,
		)

		err := runner.Run()

		assert.NoError(st, err)
	})

	t.Run("performs arp only scan and prints json", func(st *testing.T) {
		mockScanner := mock_scanner.NewMockScanner(ctrl)

		runner := core.New()

		scanResults := make(chan *scanner.ScanResult)

		mockScanner.EXPECT().SetRequestNotifications(gomock.Any())

		mockScanner.EXPECT().Scan().DoAndReturn(func() error {
			mac, _ := net.ParseMAC("00:00:00:00:00:00")
			scanResults <- &scanner.ScanResult{
				Type: scanner.ARPResult,
				Payload: &scanner.ArpScanResult{
					IP:     net.ParseIP("172.17.0.1"),
					MAC:    mac,
					Vendor: "Apple",
				},
			}
			time.AfterFunc(time.Second, func() {
				scanResults <- &scanner.ScanResult{
					Type: scanner.ARPDone,
				}
			})
			return nil
		})

		mockScanner.EXPECT().Stop()

		runner.Initialize(
			mockScanner,
			scanResults,
			1,
			1,
			false,
			true,
			true,
		)

		err := runner.Run()

		assert.NoError(st, err)
	})

	t.Run("performs arp only scan and silences output", func(st *testing.T) {
		mockScanner := mock_scanner.NewMockScanner(ctrl)

		runner := core.New()

		scanResults := make(chan *scanner.ScanResult)

		mockScanner.EXPECT().Scan().DoAndReturn(func() error {
			mac, _ := net.ParseMAC("00:00:00:00:00:00")
			scanResults <- &scanner.ScanResult{
				Type: scanner.ARPResult,
				Payload: &scanner.ArpScanResult{
					IP:     net.ParseIP("172.17.0.1"),
					MAC:    mac,
					Vendor: "Apple",
				},
			}
			time.AfterFunc(time.Second, func() {
				scanResults <- &scanner.ScanResult{
					Type: scanner.ARPDone,
				}
			})
			return nil
		})

		mockScanner.EXPECT().Stop()

		runner.Initialize(
			mockScanner,
			scanResults,
			1,
			1,
			true,
			true,
			true,
		)

		err := runner.Run()

		assert.NoError(st, err)
	})

	t.Run("performs syn scan and prints text table", func(st *testing.T) {
		mockScanner := mock_scanner.NewMockScanner(ctrl)

		runner := core.New()

		scanResults := make(chan *scanner.ScanResult)

		mockScanner.EXPECT().SetRequestNotifications(gomock.Any())

		mockScanner.EXPECT().Scan().DoAndReturn(func() error {
			ip := net.ParseIP("172.17.0.1")
			mac, _ := net.ParseMAC("00:00:00:00:00:00")
			scanResults <- &scanner.ScanResult{
				Type: scanner.ARPResult,
				Payload: &scanner.ArpScanResult{
					IP:     ip,
					MAC:    mac,
					Vendor: "Apple",
				},
			}
			time.AfterFunc(time.Second, func() {
				scanResults <- &scanner.ScanResult{
					Type: scanner.ARPDone,
				}
				scanResults <- &scanner.ScanResult{
					Type: scanner.SYNResult,
					Payload: &scanner.SynScanResult{
						IP:     ip,
						MAC:    mac,
						Status: scanner.StatusOnline,
						Port: scanner.Port{
							ID:      22,
							Service: "ssh",
							Status:  scanner.PortOpen,
						},
					},
				}
			})
			time.AfterFunc(time.Second*2, func() {
				scanResults <- &scanner.ScanResult{
					Type: scanner.SYNDone,
				}
			})

			return nil
		})

		mockScanner.EXPECT().Stop()

		runner.Initialize(
			mockScanner,
			scanResults,
			1,
			1,
			false,
			false,
			false,
		)

		err := runner.Run()

		assert.NoError(st, err)
	})

	t.Run("performs syn scan and prints json", func(st *testing.T) {
		mockScanner := mock_scanner.NewMockScanner(ctrl)

		runner := core.New()

		scanResults := make(chan *scanner.ScanResult)

		mockScanner.EXPECT().SetRequestNotifications(gomock.Any())

		mockScanner.EXPECT().Scan().DoAndReturn(func() error {
			ip := net.ParseIP("172.17.0.1")
			mac, _ := net.ParseMAC("00:00:00:00:00:00")
			scanResults <- &scanner.ScanResult{
				Type: scanner.ARPResult,
				Payload: &scanner.ArpScanResult{
					IP:     ip,
					MAC:    mac,
					Vendor: "Apple",
				},
			}
			time.AfterFunc(time.Second, func() {
				scanResults <- &scanner.ScanResult{
					Type: scanner.ARPDone,
				}
				scanResults <- &scanner.ScanResult{
					Type: scanner.SYNResult,
					Payload: &scanner.SynScanResult{
						IP:     ip,
						MAC:    mac,
						Status: scanner.StatusOnline,
						Port: scanner.Port{
							ID:      22,
							Service: "ssh",
							Status:  scanner.PortOpen,
						},
					},
				}
			})
			time.AfterFunc(time.Second*2, func() {
				scanResults <- &scanner.ScanResult{
					Type: scanner.SYNDone,
				}
			})

			return nil
		})

		mockScanner.EXPECT().Stop()

		runner.Initialize(
			mockScanner,
			scanResults,
			1,
			1,
			false,
			false,
			true,
		)

		err := runner.Run()

		assert.NoError(st, err)
	})

	t.Run("performs syn scan silences output", func(st *testing.T) {
		mockScanner := mock_scanner.NewMockScanner(ctrl)

		runner := core.New()

		scanResults := make(chan *scanner.ScanResult)

		mockScanner.EXPECT().Scan().DoAndReturn(func() error {
			ip := net.ParseIP("172.17.0.1")
			mac, _ := net.ParseMAC("00:00:00:00:00:00")
			scanResults <- &scanner.ScanResult{
				Type: scanner.ARPResult,
				Payload: &scanner.ArpScanResult{
					IP:     ip,
					MAC:    mac,
					Vendor: "Apple",
				},
			}
			time.AfterFunc(time.Second, func() {
				scanResults <- &scanner.ScanResult{
					Type: scanner.ARPDone,
				}
				scanResults <- &scanner.ScanResult{
					Type: scanner.SYNResult,
					Payload: &scanner.SynScanResult{
						IP:     ip,
						MAC:    mac,
						Status: scanner.StatusOnline,
						Port: scanner.Port{
							ID:      22,
							Service: "ssh",
							Status:  scanner.PortOpen,
						},
					},
				}
			})
			time.AfterFunc(time.Second*2, func() {
				scanResults <- &scanner.ScanResult{
					Type: scanner.SYNDone,
				}
			})

			return nil
		})

		mockScanner.EXPECT().Stop()

		runner.Initialize(
			mockScanner,
			scanResults,
			1,
			1,
			true,
			false,
			true,
		)

		err := runner.Run()

		assert.NoError(st, err)
	})
}
