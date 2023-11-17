// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type defaultPacketCapture struct{}

func (pc *defaultPacketCapture) OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (handle PacketCaptureHandle, _ error) {
	return pcap.OpenLive(device, snaplen, promisc, timeout)
}

func (pc *defaultPacketCapture) SerializeLayers(w gopacket.SerializeBuffer, opts gopacket.SerializeOptions, layers ...gopacket.SerializableLayer) error {
	return gopacket.SerializeLayers(w, opts, layers...)
}
