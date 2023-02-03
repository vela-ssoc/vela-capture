# 抓包组件
> 提供服务器端抓包功能 注意:windows 需要安装npcap

## 内置信息
- [vela.capture(cfg)](#抓包服务) &emsp;构建抓包服务
- [内置常量](#内置常量) &emsp;限制固定环境常量

## 抓包服务
> cap = vela.capture(string) <br />
> string:名称  返回:[抓包服务对象](#抓包服务) 数据:[box](#数据包)

内置方法:

- [dev(cnd)](#) &emsp;接口过滤条件,内置:[接口过滤条件](#接口过滤条件)
- [dev_up(cnd)](#) &emsp;监听启动的接口,内置:[接口过滤条件](#接口过滤条件)
- [sniffer(proto)](#) &emsp;解包协议:[协议变量](#协议变量)
- [ignore(cnd)](#)
- [filter(cnd)](#)
- [pipe(px)](#)
- [thread(int)](#)
- [bpf()](#)
- [ref()](#)      &emsp;关联进程
- [case()](#)     &emsp;c.case("dst == 127.0.0.1").pipe(do)
- [output(io.writer)](#) &emsp;c.output()
- [rate(key , max , timeout)](#) &emsp;c.rate('dst' , 3000 , 60)
- [dns_ignore(cnd)](#)
- [dns_filter(cnd)](#)
- [dns_pipe(px)](#)
- [dns_output(io.writer)](#)
- [dns_case(string)](#)
- [start()](#)   &emsp;启动
- [获取DNS信息](#DNS采集)
- [获取OUTBOUND](#OUTBOUND)


```lua
    local cap = vela.capture("capture")
    //todo
    cap.dev("name = eth0")
    cap.start()
```

## 内置常量

#### BPF变量
- [TCP_OUTBOUND_BPF](#)
- [TCP_OUTBOUND_BPF](#)
- [UDP_OUTBOUND_BPF](#)
- [NOT_LOOPBACK](#)
- [NOT_TCP_LISTEN_BPF](#)
- [NOT_UDP_LISTEN_BPF](#)
- [NOT_TCP_LISTEN_PORT](#)
- [NOT_UDP_LISTEN_PORT](#)

#### 内置变量

动作函数:
- [drop](#) &emsp;丢弃数据包

#### 协议变量
- [TCP](#)
- [UDP](#)
- [ICMP](#)
- [DNS](#)
- [L4](#)

#### 接口过滤条件

- [HAVE_IP](#) &emsp;接口需要有IP地址
- [UP](#) &emsp;&emsp;接口必须是UP的
- [LOOPBACK](#) &emsp;回环接口
- [NOT_LOOPBACK](#) &emsp;非回环接口



对应接口字段:

- [name](#)
- [flag](#)  &emsp;接口标签
- [loopback](#)
- [not_ip](#)
- [up](#)



## DNS采集
获取主机上的DNS访问记录
内置字段:
- q_type
- q_name
- r_size
- rr
- risk_virus
- risk_web
- risk_login
- risk_weak
- risk_monitor
- risk_xxx &emsp;xxx为risk class 类型

内置函数:
- prefix(v)
- prefix_trim(v)
- suffix(v)
- suffix_trim(v)
- risk(class)

```lua
    local vela = vela
    local TVirus = vela.TVirus
    local c = vela.capture
    local out = task.stream.output


    --发现恶意域名
    local call = vela.call{uri="dns/risk?have&kind=miner&kind=virus&kind=cc"}
    --设置缓存 60s
    call.cache("dns_risk_bucket" , 60)

    local function handle(dns)
      if not call.r(dns.q_name) then
          return
      end
      
      local ev = dns.risk(TVirus)
      
      ev.alert = true
      ev.send()
    end

    local d = c("dns")

    --设置线程
    d.thread(2)

    --设置解包函数
    d.sniffer(c.UDP , c.DNS) 

    --监听数据包
    d.dev_up(c.NOT_LOOPBACK)

    --过滤数据
    d.bpf("udp and port 53")

    --忽略
    d.dns_ignore("q_name re *.eastmoney.com,*.aliyun.com,*.baidu.com,*.in-addr.arpa")

    --设置输出对象
    d.dns_output(out.clone("vela-dns-query"))

    --检测对象
    d.dns_case("proto = DNS|REQUEST").pipe(handle , print)
    d.dns_case("name -> /risk/dns?kind=").pipe(handle , print)

    --启动
    d.start()
```

## OUTBOUND
监听出网流量
```lua
    local vela = vela
    local call = vela.call
    local capture = vela.capture
    local out = task.stream.output
    local f   = vela.format
    local TVirus = vela.TVirus
 
    local c = capture("outbound")

    --关联进程
    c.ref()

    --设置线程
    c.thread(3)

    --设置解包函数
    c.sniffer(capture.L4) 

    --监听数据包
    c.dev_up(capture.NOT_LOOPBACK)

    --过滤数据
    local addr = vela.addr().concat(" or ")
    local broker = vela.broker()

    c.bpf(f("tcp and tcp[tcpflags] == tcp-syn and src host %s and host not %s and dst net not 10.0.0.0/8" , addr , broker))

    --设置输出对象
    c.output(out.clone("vela-outbound"))
    
    -- 命中告警
    c.case("dst -> ip/risk?have&kind=miner&kind=virus&kind=cc").pipe(function(box)
        box.risk(TVirus).send()
    end)

    c.pipe(handle)

    --启动
    c.start()

```