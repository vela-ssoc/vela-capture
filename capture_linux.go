package capture

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/vela-ssoc/vela-kit/execpt"
	"github.com/vela-ssoc/vela-kit/lua"
)

type Handle struct {
	cfg *config
	ctx context.Context
	dev Interface
	Ehh *pcapgo.EthernetHandle
}

func (h *Handle) thread(id int, queue chan gopacket.Packet, read func(gopacket.Packet)) {
	for {
		select {
		case <-h.ctx.Done():
			xEnv.Errorf("%s name thread.id=%d exit", h.cfg.name, id)
			return
		case pkt := <-queue:
			read(pkt)
		}
	}
}

func (h *Handle) ReadPacket(cfg *config, onRead func(gopacket.Packet)) {
	src := gopacket.NewPacketSource(h.Ehh, layers.LayerTypeEthernet)
	queue := src.Packets()
	for i := 0; i < cfg.thread; i++ {
		go h.thread(i, queue, onRead)
	}
}

type capture struct {
	lua.SuperVelaData
	cfg     *config
	handles []*Handle
	ctx     context.Context
	cancel  context.CancelFunc
}

func (c *capture) stop() error {
	if c.cancel != nil {
		c.cancel()
	}

	for _, handle := range c.handles {
		handle.Ehh.Close()
	}
	c.handles = nil
	return nil
}

func (c *capture) SetBPF() error {
	if len(c.cfg.bpf) == 0 {
		return nil
	}

	err := execpt.New()
	for _, ehh := range c.handles {
		if e := ehh.Ehh.SetBPF(c.cfg.bpf); e != nil {
			err.Try(ehh.dev.Name, e)
		}
	}
	return err.Wrap()
}

func (c *capture) spawn() {
	for _, handle := range c.handles {
		handle.ReadPacket(c.cfg, c.OnReadPacket)
	}
}

func (c *capture) run() error {
	c.ctx, c.cancel = context.WithCancel(context.Background())
	for _, dev := range c.cfg.devs {
		ehh, err := pcapgo.NewEthernetHandle(dev.Name)
		if err != nil {
			return err
		}
		c.handles = append(c.handles, &Handle{cfg: c.cfg, ctx: c.ctx, dev: dev, Ehh: ehh})
	}

	if len(c.handles) == 0 {
		return fmt.Errorf("%s not found valid handle", c.Name())
	}

	if e := c.SetBPF(); e != nil {
		return e
	}

	c.spawn()
	return nil
}
