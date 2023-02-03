package capture

import (
	"github.com/google/gopacket/layers"
)

func (c *capture) ICMPv4(box *Box, ip *layers.IPv4) {

	if c.cfg.proto&ICMP == 0 {
		return
	}

	if ip.Protocol != layers.IPProtocolICMPv4 {
		return
	}

	lv := box.pkt.Layer(layers.LayerTypeICMPv4)
	iv, ok := lv.(*layers.ICMPv4)
	if !ok {
		return
	}

	box.Payload = iv.TypeCode.String()
}

func (c *capture) ICMPv6(box *Box, ip *layers.IPv6) {
	if c.cfg.proto&(ICMP) == 0 {
		return
	}

	if ip.NextHeader != layers.IPProtocolICMPv4 {
		return
	}

	box.cnn.Proto = "ICMPv6"
	lv := box.pkt.Layer(layers.LayerTypeICMPv6)
	iv, ok := lv.(*layers.ICMPv6)
	if !ok {
		return
	}
	box.Payload = iv.TypeCode.String()
}
