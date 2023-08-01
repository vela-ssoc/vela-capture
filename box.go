package capture

import (
	"fmt"
	"github.com/google/gopacket"
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/audit"
	"github.com/vela-ssoc/vela-kit/kind"
	"github.com/vela-ssoc/vela-kit/lua"
	risk "github.com/vela-ssoc/vela-risk"
	vtime "github.com/vela-ssoc/vela-time"
	"net"
	"strings"
)

const (
	Ethernet uint8 = iota + 2
	NETWORK
	TRANSPORT
	APPLICATION
)

const (
	DROP uint8 = iota + 1
	ACCEPT
)

type Connection struct {
	Pid      uint32 `json:"pid"`
	SrcIP    net.IP `json:"src"`
	SrcPort  uint16 `json:"src_port"`
	DstIP    net.IP `json:"dst"`
	DstPort  uint16 `json:"dst_port"`
	Proto    string `json:"proto"`
	Path     string `json:"path"`
	State    string `json:"state"`
	Process  string `json:"process"`
	UID      uint32 `json:"uid"`
	IFace    uint32 `json:"iface"`
	Inode    uint32 `json:"inode"`
	Username string `json:"username"`
}

type Box struct {
	pkt     gopacket.Packet
	cnn     Connection
	layer   uint8
	layerT  gopacket.LayerType
	Payload string `json:"payload"`
	state   uint8
}

func (box *Box) String() string                         { return lua.B2S(box.Byte()) }
func (box *Box) Type() lua.LValueType                   { return lua.LTObject }
func (box *Box) AssertFloat64() (float64, bool)         { return 0, false }
func (box *Box) AssertString() (string, bool)           { return "", false }
func (box *Box) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (box *Box) Peek() lua.LValue                       { return box }

func (box *Box) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "time":
		return vtime.VTime(box.pkt.Metadata().Timestamp)
	case "src":
		return lua.S2L(box.cnn.SrcIP.String())
	case "src_port":
		return lua.LInt(box.cnn.SrcPort)
	case "dst":
		return lua.S2L(box.cnn.DstIP.String())
	case "dst_port":
		return lua.LInt(box.cnn.DstPort)
	case "proto":
		return lua.S2L(box.cnn.Proto)
	case "payload":
		return lua.S2L(box.Payload)
	case "layer":
		return lua.LInt(box.layer)
	case "layer_type":
		return lua.S2L(box.layerT.String())
	case "debug":
		return lua.NewFunction(box.debugL)
	case "risk":
		return lua.NewFunction(box.ToRiskL)

	default:
		if strings.HasPrefix(key, "risk_") {
			ev := box.risk(key[5:])
			ev.FromCode = L.CodeVM()
			return ev
		}
	}

	return lua.LNil
}

func (box *Box) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("minion_id", xEnv.ID())
	enc.KV("minion_inet", xEnv.Inet())
	enc.KV("@timestamp", box.pkt.Metadata().Timestamp)
	enc.KV("time", box.pkt.Metadata().Timestamp)
	enc.KV("src", box.cnn.SrcIP)
	enc.KV("src_port", box.cnn.SrcPort)
	enc.KV("dst", box.cnn.DstIP)
	enc.KV("dst_port", box.cnn.DstPort)
	enc.KV("proto", box.cnn.Proto)
	enc.KV("payload", box.Payload)
	enc.KV("layer", box.layerT.String())
	enc.KV("pid", box.cnn.Pid)
	enc.KV("process", box.cnn.Process)
	enc.KV("username", box.cnn.Username)
	enc.End("}")
	return enc.Bytes()
}

func (box *Box) debugL(L *lua.LState) int {
	audit.Debug(box.String())
	xEnv.Errorf("%s", box.String())
	return 0
}

func (box *Box) risk(v string) *risk.Event {
	ev := risk.NewEv()
	ev.Class = risk.WithClass(v)
	ev.LocalIP = box.cnn.SrcIP.String()
	ev.LocalPort = int(box.cnn.SrcPort)
	ev.RemoteIP = box.cnn.DstIP.String()
	ev.RemotePort = int(box.cnn.DstPort)
	ev.Payload = box.cnn.Process
	ev.Reference = "流量监控"
	ev.Time = box.pkt.Metadata().Timestamp
	ev.Subject = "发现异常流量"
	ev.Alert = true
	ev.High()
	return ev
}

func (box *Box) ToRiskL(L *lua.LState) int {
	ev := box.risk("")
	ev.FromCode = L.CodeVM()
	ev.Class = risk.CheckClass(L, 1)
	L.Push(ev)
	return 1
}

func (box *Box) ref() *cond.Cond {
	f := fmt.Sprintf
	return cond.New(
		f("local_addr = %s", box.cnn.SrcIP),
		f("local_port = %d", box.cnn.SrcPort),
		f("remote_addr = %s", box.cnn.DstIP),
		f("remote_port = %d", box.cnn.DstPort),
	)
}

func (box *Box) drop() error {
	box.state = DROP
	return nil
}

func drop(v ...interface{}) error {
	if len(v) == 0 {
		return nil
	}

	lv := v[0]
	if lv == nil {
		return nil
	}

	box, ok := lv.(*Box)
	if ok {
		return box.drop()
	}

	dns, ok := lv.(*Dns)
	if ok {
		return dns.drop()
	}

	return nil
}
