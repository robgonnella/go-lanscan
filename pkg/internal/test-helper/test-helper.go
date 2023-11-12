package test_helper

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NewArpReplyReadResult(srcIP net.IP, srcHwAddr net.HardwareAddr) (data []byte, ci gopacket.CaptureInfo, err error) {
	eth := layers.Ethernet{
		SrcMAC:       srcHwAddr,
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,                            // ARP reply
		SourceHwAddress:   srcHwAddr,                                  // Your MAC address
		SourceProtAddress: []byte(srcIP.To4()),                        // Your IP address
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Target MAC address
		DstProtAddress:    []byte{192, 168, 1, 1},                     // Target IP address
	}

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Serialize the ARP packet.
	gopacket.SerializeLayers(buf, opts, &eth, &arp)

	return buf.Bytes(), gopacket.CaptureInfo{}, nil
}

func NewArpRequestReadResult() (data []byte, ci gopacket.CaptureInfo, err error) {
	eth := layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,                          // ARP reply
		SourceHwAddress:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Your MAC address
		SourceProtAddress: []byte{192, 168, 1, 100},                   // Your IP address
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Target MAC address
		DstProtAddress:    []byte{192, 168, 1, 1},                     // Target IP address
	}

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Serialize the ARP packet.
	gopacket.SerializeLayers(buf, opts, &eth, &arp)

	return buf.Bytes(), gopacket.CaptureInfo{}, nil
}

func NewSynWithAckResponsePacketBytes(
	srcIP net.IP,
	srcPort uint16,
	listenPort uint16,
) (data []byte, ci gopacket.CaptureInfo, err error) {
	eth := layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := layers.IPv4{
		SrcIP:    srcIP.To4(),
		DstIP:    net.ParseIP("127.0.0.1").To4(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(listenPort),
		SYN:     true,
		ACK:     true,
	}

	tcp.SetNetworkLayerForChecksum(&ip4)

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Serialize the ARP packet.
	gopacket.SerializeLayers(buf, opts, &eth, &ip4, &tcp)

	return buf.Bytes(), gopacket.CaptureInfo{}, nil
}
