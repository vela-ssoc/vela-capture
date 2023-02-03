package capture

import (
	"github.com/vela-ssoc/vela-kit/vela"
	"github.com/vela-ssoc/vela-kit/lua"
)

var xEnv vela.Environment

func newCaptureL(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewVelaData(cfg.name, typeOf)
	if proc.IsNil() {
		proc.Set(newCapture(cfg))
	} else {
		old := proc.Data.(*capture)
		old.cfg = cfg
	}
	L.Push(proc)
	return 1
}

func index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "drop":
		return lua.GoFuncErr(drop)
	case "TCP":
		return lua.LNumber(TCP)
	case "UDP":
		return lua.LNumber(UDP)
	case "ICMP":
		return lua.LNumber(ICMP)
	case "DNS":
		return lua.LNumber(DNS)
	case "L4":
		return lua.LNumber(uint64(TCP | UDP))
	case "HAVE_IP":
		return lua.S2L(DevHaveIP)
	case "UP":
		return lua.S2L(DevUp)
	case "LOOPBACK":
		return lua.S2L(DevLoopBack)
	case "TCP_OUTBOUND_BPF":
		return lua.S2L(TcpOutboundBPF())
	case "UDP_OUTBOUND_BPF":
		return lua.S2L(UdpOutboundBPF())
	case "NOT_LOOPBACK":
		return lua.S2L(DevNotLoopBack)
	case "NOT_TCP_LISTEN_BPF":
		return NotListenBPF("tcp")
	case "NOT_UDP_LISTEN_BPF":
		return NotListenBPF("udp")
	case "NOT_TCP_LISTEN_PORT":
		return NotListenPort("tcp")
	case "NOT_UDP_LISTEN_PORT":
		return NotListenPort("udp")
	}

	return lua.LNil
}

func WithEnv(env vela.Environment) {
	xEnv = env
	name := "vela.capture.export"
	xEnv.Set("capture", lua.NewExport(name, lua.WithIndex(index), lua.WithFunc(newCaptureL)))
}
