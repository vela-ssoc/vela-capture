package capture

import (
	"github.com/google/gopacket/layers"
)

func (c *capture) L3(box *Box) {
	nt := box.pkt.NetworkLayer()
	if nt == nil {
		return
	}

	box.layerT = nt.LayerType()
	switch nt.LayerType() {
	case layers.LayerTypeIPv4:
		ip := nt.(*layers.IPv4)
		box.cnn.SrcIP = ip.SrcIP
		box.cnn.DstIP = ip.DstIP
		box.cnn.Proto = "IP"
		c.ICMPv4(box, ip)

	case layers.LayerTypeIPv6:
		ip := nt.(*layers.IPv6)
		box.cnn.SrcIP = ip.SrcIP
		box.cnn.DstIP = ip.DstIP
		box.cnn.Proto = "IP"
		c.ICMPv6(box, ip)

	default:
		return
	}

	box.layer = NETWORK
}
