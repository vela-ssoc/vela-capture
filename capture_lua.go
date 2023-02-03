package capture

import (
	"fmt"
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	vswitch "github.com/vela-ssoc/vela-switch"
)

func (c *capture) devL(L *lua.LState) int {
	cnd := cond.CheckMany(L)
	if e := c.cfg.findDev(cnd); e != nil {
		L.RaiseError("%s %v", c.Name(), e)
	}

	return 0
}

func (c *capture) devUpL(L *lua.LState) int {
	cnd := cond.New("up = true")
	cnd.CheckMany(L)
	if e := c.cfg.findDev(cnd); e != nil {
		L.RaiseError("%s %v", c.Name(), e)
	}
	return 0
}

func (c *capture) startL(L *lua.LState) int {
	xEnv.Start(L, c).From(L.CodeVM()).Do()
	return 0
}

func (c *capture) bpfL(L *lua.LState) int {
	var err error
	lv := L.Get(1)
	switch lv.Type() {
	case lua.LTString:
		err = c.cfg.BuildBPF(lv.String())

	case lua.LTTable:
		err = c.cfg.BuildBPFbyTuple(lv.(*lua.LTable))

	default:
		err = fmt.Errorf("%s #1 must be string or table , got %s", c.cfg.name, lv.Type().String())
	}

	if err != nil {
		L.RaiseError("bpf error %v", err)
	}

	return 0
}

func (c *capture) threadL(L *lua.LState) int {
	n := L.IsInt(1)
	if n == 0 {
		c.cfg.thread = 3
	} else {
		c.cfg.thread = n
	}
	return 0
}

func (c *capture) protoL(L *lua.LState) int {
	n := L.GetTop()
	if n == 0 {
		return 0
	}

	for i := 1; i <= n; i++ {
		lv := L.CheckNumber(i)
		c.cfg.proto = c.cfg.proto | Proto(lv)
	}
	return 0
}

func (c *capture) ignoreL(L *lua.LState) int {
	cnd := cond.CheckMany(L)
	c.cfg.ignore = append(c.cfg.ignore, cnd)
	return 0
}

func (c *capture) filterL(L *lua.LState) int {
	cnd := cond.CheckMany(L)
	c.cfg.filter = append(c.cfg.filter, cnd)
	return 0
}

func (c *capture) pipeL(L *lua.LState) int {
	if c.cfg.pipe == nil {
		c.cfg.pipe = pipe.NewByLua(L)
	} else {
		c.cfg.pipe.CheckMany(L)
	}
	return 0
}

func (c *capture) outputL(L *lua.LState) int {
	proc := L.CheckVelaData(1)
	c.cfg.to = lua.CheckWriter(proc)
	return 0
}

func (c *capture) refL(_ *lua.LState) int {
	c.cfg.ref = true
	return 0
}

func (c *capture) rateL(L *lua.LState) int {
	param := L.CheckString(1)
	size := L.IsInt(2)
	ttl := L.IsInt(3)

	rc := &RateConfig{
		param:  param,
		ttl:    ttl,
		shared: xEnv.NewLRU(c.Name(), size),
	}

	if e := rc.Prepare(); e != nil {
		L.RaiseError("%s cache prepare fail %v", c.Name(), e)
		return 0
	}

	c.cfg.rate = rc
	return 0
}

func (c *capture) DnsIgnoreL(L *lua.LState) int {
	cnd := cond.CheckMany(L)
	c.cfg.dns.ignore = append(c.cfg.dns.ignore, cnd)
	return 0
}

func (c *capture) DnsFilterL(L *lua.LState) int {
	cnd := cond.CheckMany(L)
	c.cfg.dns.filter = append(c.cfg.dns.filter, cnd)
	return 0
}

func (c *capture) DnsPipeL(L *lua.LState) int {
	if c.cfg.dns.pipe == nil {
		c.cfg.dns.pipe = pipe.NewByLua(L)
	} else {
		c.cfg.dns.pipe.CheckMany(L)
	}
	return 0
}

func (c *capture) DnsOutputL(L *lua.LState) int {
	proc := L.CheckVelaData(1)
	c.cfg.dns.to = lua.CheckWriter(proc)
	return 0
}

func (c *capture) switchL(L *lua.LState) int {
	c.cfg.vsh = vswitch.NewSwitchL(L)
	return 0
}

func (c *capture) DnsSwitchL(L *lua.LState) int {
	c.cfg.dns.vsh = vswitch.NewSwitchL(L)
	return 0
}

func (c *capture) CaseL(L *lua.LState) int {
	L.Push(c.cfg.vsh.Index(L, "case"))
	return 1
}

func (c *capture) DnsCaseL(L *lua.LState) int {
	L.Push(c.cfg.dns.vsh.Index(L, "case"))
	return 1
}

func (c *capture) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "dev":
		return lua.NewFunction(c.devL)
	case "dev_up":
		return lua.NewFunction(c.devUpL)
	case "start":
		return lua.NewFunction(c.startL)
	case "bpf":
		return lua.NewFunction(c.bpfL)
	case "thread":
		return lua.NewFunction(c.threadL)
	case "sniffer":
		return lua.NewFunction(c.protoL)
	case "ignore":
		return lua.NewFunction(c.ignoreL)
	case "filter":
		return lua.NewFunction(c.filterL)
	case "pipe":
		return lua.NewFunction(c.pipeL)
	case "output": //c.output()
		return lua.NewFunction(c.outputL)
	case "ref": // c.ref()
		return lua.NewFunction(c.refL)
	case "rate": //c.rate('dst' , 3000 , 60)
		return lua.NewFunction(c.rateL)
	case "case": //c.case("dst == 127.0.0.1").pipe(do)
		return c.cfg.vsh.Index(L, "case")
	case "dns_ignore":
		return lua.NewFunction(c.DnsIgnoreL)
	case "dns_filter":
		return lua.NewFunction(c.DnsFilterL)
	case "dns_pipe":
		return lua.NewFunction(c.DnsPipeL)
	case "dns_output":
		return lua.NewFunction(c.DnsOutputL)
	case "dns_case":
		return c.cfg.dns.vsh.Index(L, "case")
	}

	return lua.LNil
}
