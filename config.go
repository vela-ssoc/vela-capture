package capture

import (
	"fmt"
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	vswitch "github.com/vela-ssoc/vela-switch"
	"golang.org/x/net/bpf"
)

type Proto uint64

const (
	ICMP = Proto(1) << 1
	TCP  = Proto(1) << 2
	UDP  = Proto(1) << 3
	DNS  = Proto(1) << 4
)

type dnsConfig struct {
	ignore []*cond.Cond
	filter []*cond.Cond
	pipe   *pipe.Px
	to     lua.Writer
	vsh    *vswitch.Switch
}

type config struct {
	name   string
	devs   []Interface
	bpfVal string
	bpf    []bpf.RawInstruction
	thread int
	proto  Proto
	co     *lua.LState
	ref    bool
	rate   *RateConfig
	ignore []*cond.Cond
	filter []*cond.Cond
	pipe   *pipe.Px
	to     lua.Writer
	vsh    *vswitch.Switch
	dns    *dnsConfig
}

type body struct {
	Expr string `json:"expr"`
}

type bpfReply struct {
	Data []bpf.RawInstruction `json:"data"`
}

func newConfig(L *lua.LState) *config {
	lv := L.Get(1)
	cfg := &config{
		co:  xEnv.Clone(L),
		vsh: vswitch.NewL(L),
		dns: &dnsConfig{
			vsh: vswitch.NewL(L),
		},
	}
	switch lv.Type() {
	case lua.LTString:
		cfg.name = lv.String()
	case lua.LTTable:
		//todo

	}

	if e := cfg.verify(); e != nil {
		L.RaiseError("%v", e)
		return nil
	}
	return cfg
}

func (cfg *config) BuildBPF(v string) error {
	var r bpfReply
	cfg.bpfVal = v
	err := xEnv.PostJSON("/v1/bpf/compile", body{Expr: v}, &r)
	cfg.bpf = r.Data
	return err
}

/*
 tab = {
	{0x28, 0, 0, 0x0000000c},
	{0x15, 0, 10, 0x00000800},
 }
*/

func (cfg *config) BuildBPFbyTuple(tab *lua.LTable) error {
	tuple := tab.Array()
	if len(tuple) == 0 {
		return nil
	}

	var b []bpf.RawInstruction
	for i, lv := range tuple {
		if lv.Type() != lua.LTTable {
			return fmt.Errorf("%d invalid bpf rawinstruction", i)
		}
		item := lv.(*lua.LTable)
		op, ok := item.RawGetInt(1).AssertFloat64()
		jt, ok := item.RawGetInt(2).AssertFloat64()
		jf, ok := item.RawGetInt(3).AssertFloat64()
		k, ok := item.RawGetInt(4).AssertFloat64()
		if !ok {
			return fmt.Errorf("%d invalid bpf rawinstruction", i)
		}

		b = append(b, bpf.RawInstruction{
			Op: uint16(op),
			Jt: uint8(jt),
			Jf: uint8(jf),
			K:  uint32(k),
		})
	}

	cfg.bpf = b
	return nil
}

func (cfg *config) verify() error {
	if e := auxlib.Name(cfg.name); e != nil {
		return e
	}
	return nil
}
