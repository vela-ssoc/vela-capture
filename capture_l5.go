package capture

import (
	"github.com/google/gopacket/layers"
)

func (c *capture) L5(box *Box) {
	if box.layer < TRANSPORT {
		return
	}

	app := box.pkt.ApplicationLayer()
	if app == nil {
		return
	}

	box.layer = APPLICATION
	switch app.LayerType() {
	case layers.LayerTypeDNS:
		c.DNS(box)
	}
}
