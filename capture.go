package capture

import (
	"github.com/google/gopacket"
	"github.com/vela-ssoc/vela-kit/audit"
	"github.com/vela-ssoc/vela-kit/lua"
	"reflect"
	"time"
)

var typeOf = reflect.TypeOf((*capture)(nil)).String()

func newCapture(cfg *config) *capture {
	c := &capture{cfg: cfg}
	c.V(lua.VTInit, typeOf, time.Now())
	return c
}

func (c *capture) Name() string {
	return c.cfg.name
}

func (c *capture) Type() string {
	return typeOf
}

func (c *capture) Start() error {
	return c.run()
}

func (c *capture) Close() error {
	return c.stop()
}

func (c *capture) ignore(box *Box) bool {
	n := len(c.cfg.ignore)
	if n == 0 {
		return false
	}

	for i := 0; i < n; i++ {
		cnd := c.cfg.ignore[i]
		if cnd.Match(box) {
			return true
		}
	}

	return false
}

func (c *capture) filter(box *Box) bool {
	n := len(c.cfg.filter)
	if n == 0 {
		return true
	}

	for i := 0; i < n; i++ {
		cnd := c.cfg.filter[i]
		if cnd.Match(box) {
			return true
		}
	}

	return false
}

func (c *capture) pipe(box *Box) {
	if c.cfg.pipe == nil {
		return
	}
	if box.state == DROP {
		return
	}

	c.cfg.pipe.Do(box, c.cfg.co, func(err error) {
		audit.Debug("%s capture pipe call fail %v", c.Name(), err)
	})
}

func (c *capture) to(box *Box) {
	if c.cfg.to == nil {
		return
	}

	if box.state == DROP {
		return
	}

	_, e := c.cfg.to.Write(box.Byte())
	if e != nil {
		xEnv.Errorf("%s output fail %v", c.Name(), e)
	}
}

func (c *capture) use(box *Box) {
	if c.cfg.vsh.Len() == 0 {
		return
	}
	c.cfg.vsh.Do(box)
}

func (c *capture) rate(box *Box) bool {
	var iv uint32 = 1

	if c.cfg.rate == nil {
		return false
	}

	key := c.cfg.rate.Index(box)
	val, err := c.cfg.rate.shared.Get(key)
	if err != nil {
		c.cfg.rate.shared.Set(key, &iv, c.cfg.rate.ttl)
		return false
	}

	v, ok := val.(*uint32)
	if ok {
		*v = *v + 1
		return true
	}

	c.cfg.rate.shared.Set(key, &iv, c.cfg.rate.ttl)
	return false
}

func (c *capture) OnReadPacket(pkt gopacket.Packet) {
	box := &Box{pkt: pkt, layer: Ethernet}
	c.L3(box) //网络层解码
	c.L4(box) //传输层解码
	c.L5(box) //应用层解码

	if box.layer < NETWORK {
		return
	}

	if c.ignore(box) {
		return
	}

	if !c.filter(box) {
		return
	}

	if c.rate(box) {
		return
	}

	c.ref(box)
	c.use(box)
	c.pipe(box)
	c.to(box)
}
