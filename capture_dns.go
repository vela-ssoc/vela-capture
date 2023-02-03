package capture

import (
	"bytes"
	"github.com/google/gopacket/layers"
	"github.com/vela-ssoc/vela-kit/audit"
	cond "github.com/vela-ssoc/vela-cond"
	"github.com/vela-ssoc/vela-kit/auxlib"
	"github.com/vela-ssoc/vela-kit/kind"
	"github.com/vela-ssoc/vela-kit/lua"
	risk "github.com/vela-ssoc/vela-risk"
	"strings"
	"time"
)

type RR struct {
	RName  string
	RType  string
	TTL    uint32
	RValue string
}

func (rr RR) String() string                         { return "vela.dns.rr" }
func (rr RR) Type() lua.LValueType                   { return lua.LTObject }
func (rr RR) AssertFloat64() (float64, bool)         { return 0, false }
func (rr RR) AssertString() (string, bool)           { return "", false }
func (rr RR) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (rr RR) Peek() lua.LValue                       { return rr }

func (rr RR) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "name":
		return lua.S2L(rr.RName)
	case "type":
		return lua.S2L(rr.RType)
	case "ttl":
		return lua.LInt(rr.TTL)
	case "value":
		return lua.S2L(rr.RValue)
	}
	return lua.LNil
}

type Reply []RR

func (r Reply) String() string                         { return "vela.dns.reply" }
func (r Reply) Type() lua.LValueType                   { return lua.LTObject }
func (r Reply) AssertFloat64() (float64, bool)         { return 0, false }
func (r Reply) AssertString() (string, bool)           { return "", false }
func (r Reply) AssertFunction() (*lua.LFunction, bool) { return lua.NewFunction(r.ToLFunc), false }
func (r Reply) Peek() lua.LValue                       { return r }

func (r Reply) ToLFunc(L *lua.LState) int {
	n := L.GetTop()
	if n == 0 {
		L.Push(lua.LNil)
		return 1
	}

	size := len(r)
	for i := 1; i <= n; i++ {
		idx := L.IsInt(i)
		if idx <= 0 || idx > size {
			L.Push(lua.LNil)
		} else {
			L.Push(r[idx-1])
		}
	}
	return size
}

type Dns struct {
	time  time.Time
	cnn   Connection
	QType string
	QName string
	Reply []RR
	state uint8
}

func (d *Dns) String() string                         { return lua.B2S(d.Byte()) }
func (d *Dns) Type() lua.LValueType                   { return lua.LTObject }
func (d *Dns) AssertFloat64() (float64, bool)         { return 0, false }
func (d *Dns) AssertString() (string, bool)           { return "", false }
func (d *Dns) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (d *Dns) Peek() lua.LValue                       { return d }

func (d *Dns) drop() error {
	d.state = DROP
	return nil
}

func (d *Dns) risk(v string) *risk.Event {
	ev := risk.NewEv()
	ev.Class = risk.WithClass(v)
	ev.LocalIP = d.cnn.SrcIP.String()
	ev.LocalPort = int(d.cnn.SrcPort)
	ev.RemoteIP = d.cnn.DstIP.String()
	ev.RemotePort = int(d.cnn.DstPort)
	ev.Payload = d.QName
	ev.Time = d.time
	ev.Subject = "发现异常域名"
	ev.Alert = true
	ev.High()
	return ev
}

func (d *Dns) ToRisk(L *lua.LState) int {
	ev := d.risk(L.CheckString(1))
	ev.FromCode = L.CodeVM()
	L.Push(ev)
	return 1
}

func (d *Dns) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("time", d.time)
	enc.KV("@timestamp", d.time)
	enc.KV("minion_id", xEnv.ID())
	enc.KV("minion_inet", xEnv.Inet())
	enc.KV("src", d.cnn.SrcIP)
	enc.KV("src_port", d.cnn.SrcPort)
	enc.KV("dst", d.cnn.DstIP)
	enc.KV("dst_port", d.cnn.DstPort)
	enc.KV("proto", d.cnn.Proto)
	enc.KV("q_type", d.QType)
	enc.KV("q_name", d.QName)

	enc.Arr("reply")
	for _, r := range d.Reply {
		enc.Tab("")
		enc.KV("r_name", r.RName)
		enc.KV("r_type", r.RType)
		enc.KV("r_value", r.RValue)
		enc.KV("ttl", r.TTL)
		enc.End("},")
	}
	enc.End("]}")
	return enc.Bytes()
}

/*
	pipe(function(v)
		print(v.q_type)
		print(v.q_type)
		print(v.q_type)
		print(v.q_type)
		print(v.rr)
		print(v.rr(1))
	end)

*/

func (d *Dns) helper(L *lua.LState, name string, fn func(string, string) bool) int {
	n := L.GetTop()
	if n < 2 {
		L.Push(lua.LFalse)
		return 1
	}

	for i := 2; i <= n; i++ {
		val := L.CheckString(i)
		if fn(name, val) {
			L.Push(lua.LTrue)
			return 1
		}
	}

	L.Push(lua.LFalse)
	return 1
}

func (d *Dns) prefixL(L *lua.LState) int {
	return d.helper(L, d.QName, strings.HasPrefix)
}
func (d *Dns) prefixTrimL(L *lua.LState) int {
	str := L.CheckString(1)

	name := d.QName
	nl := len(name)
	sl := len(str)

	if nl > sl && name[0:sl] == str {
		L.Push(lua.S2L(name[sl:]))
		return 1
	}

	L.Push(lua.LNil)
	return 1
}

func (d *Dns) suffixL(L *lua.LState) int {
	return d.helper(L, d.QName, strings.HasSuffix)
}

func (d *Dns) suffixTrimL(L *lua.LState) int {
	str := L.CheckString(1)
	name := d.QName
	nl := len(name)
	sl := len(str)

	if nl > sl && name[nl-sl:] == str {
		L.Push(lua.S2L(name[:nl-sl]))
		return 1
	}
	L.Push(lua.LNil)
	return 1
}

func (d *Dns) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "q_type":
		return lua.S2L(d.QType)
	case "q_name":
		return lua.S2L(d.QName)
	case "r_size":
		return lua.LInt(len(d.Reply))
	case "rr":
		return Reply(d.Reply)
	case "prefix":
		return lua.NewFunction(d.prefixL)
	case "prefix_trim":
		return lua.NewFunction(d.prefixTrimL)

	case "suffix":
		return lua.NewFunction(d.suffixL)
	case "suffix_trim":
		return lua.NewFunction(d.suffixTrimL)
	case "proto":
		return lua.S2L(d.cnn.Proto)
	case "risk":
		return lua.NewFunction(d.ToRisk)

	default:
		if strings.HasPrefix(key, "risk_") {
			ev := d.risk(key[5:])
			ev.FromCode = L.CodeVM()
			return ev
		}
	}

	return lua.LNil
}

func (d *Dns) CompareQType(val string, cnd cond.Method) bool {
	return cnd(d.QType, val)
}

func (d *Dns) CompareQName(val string, cnd cond.Method) bool {
	return cnd(d.QName, val)
}

func (d *Dns) CompareRValue(val string, cnd cond.Method) bool {
	n := len(d.Reply)
	if n == 0 {
		return false
	}

	for i := 0; i < n; i++ {
		rr := d.Reply[i]
		return cnd(rr.RValue, val)
	}

	return false
}

func (d *Dns) CompareRType(val string, cnd cond.Method) bool {
	n := len(d.Reply)
	if n == 0 {
		return false
	}

	for i := 0; i < n; i++ {
		rr := d.Reply[i]
		return cnd(rr.RType, val)
	}
	return false
}

func (d *Dns) CompareRName(val string, cnd cond.Method) bool {
	n := len(d.Reply)
	if n == 0 {
		return false
	}

	for i := 0; i < n; i++ {
		rr := d.Reply[i]
		return cnd(rr.RName, val)
	}
	return false

}

func (d *Dns) Compare(key, val string, cnd cond.Method) bool {
	switch key {
	case "q_type":
		return d.CompareQType(val, cnd)
	case "q_name":
		return d.CompareQName(val, cnd)
	case "r_name":
		return d.CompareRName(val, cnd)
	case "r_value":
		return d.CompareRValue(val, cnd)
	case "r_type":
		return d.CompareRType(val, cnd)
	}

	return cnd(d.Index(nil, key).String(), val)
}

func Q2Payload(v []layers.DNSQuestion) string {
	if len(v) == 0 {
		return ""
	}

	var buf bytes.Buffer
	for i, q := range v {
		if i > 0 {
			buf.WriteByte(',')
		}

		buf.Write(q.Name)
	}

	return buf.String()
}

func RR2Payload(v []layers.DNSResourceRecord) string {
	if len(v) == 0 {
		return ""
	}

	var buf bytes.Buffer
	for i, rr := range v {
		if i > 0 {
			buf.WriteByte('|')
		}
		buf.WriteString(RR2Value(rr))
	}

	return buf.String()
}

func (c *capture) DNS(box *Box) {
	if c.cfg.proto&DNS == 0 {
		return
	}

	box.cnn.Proto = "DNS"
	dv := box.pkt.Layer(layers.LayerTypeDNS)
	msg, ok := dv.(*layers.DNS)
	if !ok {
		return
	}

	if !msg.QR {
		box.cnn.Proto = "DNS|REQUEST"
		box.Payload = Q2Payload(msg.Questions)
		c.DnsQueryH(box, msg)
	} else {
		box.cnn.Proto = "DNS|RESPONSE"
		box.Payload = Q2Payload(msg.Questions) + ":" + RR2Payload(msg.Answers)
		c.DnsRecordH(box, msg)
	}
}

func (c *capture) DnsQueryH(box *Box, msg *layers.DNS) {
	n := len(msg.Questions)
	if n == 0 {
		return
	}

	for i := 0; i < n; i++ {
		q := msg.Questions[i]
		c.DnsHandler(&Dns{
			time:  box.pkt.Metadata().Timestamp,
			cnn:   box.cnn,
			QType: q.Type.String(),
			QName: auxlib.B2S(q.Name),
			Reply: ToReply(msg.Answers),
		})
	}
}

func (c *capture) DnsRecordH(box *Box, msg *layers.DNS) {
	n := len(msg.Questions)
	if n == 0 {
		c.DnsHandler(&Dns{
			time:  box.pkt.Metadata().Timestamp,
			cnn:   box.cnn,
			QType: "NaN",
			QName: "NaN",
			Reply: ToReply(msg.Answers),
		})
	}
	c.DnsQueryH(box, msg)
}

func (c *capture) DnsIgnore(v *Dns) bool {
	n := len(c.cfg.dns.ignore)
	if n == 0 {
		return false
	}

	for _, cnd := range c.cfg.dns.ignore {
		if cnd.Match(v) {
			return true
		}
	}
	return false
}

func (c *capture) DnsFilter(v *Dns) bool {
	n := len(c.cfg.dns.filter)
	if n == 0 {
		return true
	}

	for _, cnd := range c.cfg.dns.filter {
		if cnd.Match(v) {
			return true
		}
	}
	return false
}

func (c *capture) DnsPipe(v *Dns) {
	pip := c.cfg.dns.pipe
	if pip == nil {
		return
	}

	if v.state == DROP {
		return
	}

	pip.Do(v, c.cfg.co, func(err error) {
		audit.Debug("%s dns pipe call fail %v", c.Name(), err).From(c.CodeVM()).Put()
	})
}

func (c *capture) DnsTo(v *Dns) {
	output := c.cfg.dns.to
	if output == nil {
		return
	}

	if v.state == DROP {
		return
	}

	output.Write(v.Byte())
}

func (c *capture) DnsUse(v *Dns) {
	if c.cfg.dns.vsh.Len() == 0 {
		return
	}

	c.cfg.dns.vsh.Do(v)
}

func (c *capture) DnsHandler(v *Dns) {
	if c.cfg.dns == nil {
		return
	}

	if c.DnsIgnore(v) {
		return
	}

	if !c.DnsFilter(v) {
		return
	}

	c.DnsUse(v)
	c.DnsPipe(v)
	c.DnsTo(v)
}
