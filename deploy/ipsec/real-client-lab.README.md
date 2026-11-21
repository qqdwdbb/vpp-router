# VROUTER 真实客户端公网联测

下文涉及设备的地址、MAC 和 PCI BDF 为示例，请按目标设备配置替换。

此入口是有界隔离联测，不是 nic0/VPP 生产切换。用户已明确授权本次联测期间
停止原 Linux IKEv2。特殊报文和人为低 MTU 专项已暂缓，不作为本入口的前置条件。

## 行为与凭据

`real-client-lab.py --prepare` 在服务器私有目录
`/opt/vpp-vrouter-migration/private-ipsec-real-client` 生成配置。沿用当前
`/etc/ipsec.conf` 的证书/EAP 身份、信任链、地址池、DNS 和分流选择器，强制
`forceencaps=yes`、`mobike=no`、`auto=add`；拒绝未知选项、外部 include 和 hooks。
不复制私钥或密码：charon 在私有 mount/network namespace 中只读绑定原
`/etc/ipsec.d` 和 `/etc/ipsec.secrets`，私有插件目录强制 `kernel-vpp!`。

VPP 使用新建 TAP `vrouter-ike-wan`、网络命名空间 `vrouter-ike-server` 和原生 ESP
数据面；Linux 只提供上游路由/NAT。现有公网 WAN 地址、域名及 nic0 保持不变。
临时 nft 表 `vrouter_ike_live` 仅把 WAN 本机地址上的 UDP 500/4500 DNAT 到 VPP，
回包由 conntrack 还原公网源地址。增加的转发规则仅匹配实验 TAP/地址，并追加
在现有规则之后；不清空生产规则集。IPv4 内层保留客户端源地址，交给 Linux 现有策略路由与出口 NAT，避免提前
SNAT 掩盖 EAP 的 10.62.20.0/24 源策略；本联测不启用 VPP EI。EAP
原有 ULA 地址池经 Linux NAT66，证书 profile 的公网 IPv6 地址池不做 NAT66。

`clear-ike-conntrack.c` 使用系统已有 libnetfilter_conntrack，仅清理原始目的为
指定本机 WAN 地址且 UDP 目的端口为 500/4500 的流。启动与回退各执行一次，
防止旧连接跟踪绕过临时 DNAT 或继续指向已关闭的实验实例；不打印连接元组。

私有 VPP/charon、两个 profile 和 API 连接就绪后才停止原 strongSwan，安装
实验回程路由并接管 IKE。监控文件只输出 IKE/CHILD 是否建立、VPP SA 数量和
服务端 Linux XFRM 是否为空，不输出 SA 明细或密钥。

## 运行与回退

先确认没有其他 VPP 或同名资源。目录存在时先检查其 state，不覆盖或删除
仍在运行的实验。旧已恢复的实验目录可保留在同一私有父目录供诊断。

```sh
sudo python3 /opt/vpp-vrouter-migration/source/scripts/vrouter/ipsec/real-client-lab.py --prepare
sudo systemd-run --unit=vrouter-ipsec-real-client --collect \
  --property=RuntimeMaxSec=1900s --property=TimeoutStopSec=25s \
  --property=KillMode=control-group \
  '--property=ExecStopPost=/usr/bin/python3 /opt/vpp-vrouter-migration/source/scripts/vrouter/ipsec/real-client-lab.py --recover' \
  /usr/bin/python3 /opt/vpp-vrouter-migration/source/scripts/vrouter/ipsec/real-client-lab.py --serve --seconds 1800
```

不用 SSH 前台常驻代替 transient systemd 的断线/超时保护。不启用开机启动。

查看安全状态文件：

```sh
sudo cat /opt/vpp-vrouter-migration/private-ipsec-real-client/status.json
```

提前结束：

```sh
sudo systemctl stop vrouter-ipsec-real-client
```

正常退出、失败或超时均停止私有进程，删除自己的 nft 表/带标签转发规则、池
回程路由、TAP 和 namespace，再恢复之前 active 的 `strongswan-starter`。
`--recover` 是幂等兜底；仍有 VPP 运行时应先停止实验 unit，再调用它，不得
针对生产接口或其他 VPP 清理。私有日志保留，不复制进项目。

## 客户端与验收边界

客户端断开 Wi-Fi，使用移动网络或其他外部网络，重新连接原域名
`vpn.example.com`，沿用现有账号或客户端证书。不要将原凭据写入项目或聊天。
核对证书/EAP、IKE/CHILD、VPP SA、服务端无 Linux XFRM，然后核对 DNS、IPv4/
IPv6 业务与重连。服务端 ready 只证明配置就绪，不证明真实客户端或公网入站
已验收。窗口结束会恢复原 VPN，客户端可能需要重新连接。

目前已完成短窗口接管/自动恢复演练，以及 VPP 到公网的 IPv4 3/3 ping；真实
客户端证书认证及网页/DNS/IPv6 已通过，EAP 认证及上网已通过；结果见
`artifacts/vrouter/ipsec-real-client-20261017.json`。EAP IPv6、重连及修正后的 IPv4
策略出口也经用户确认正常；公网 IPv6 外层仍待确认。没有因此批准生产 MTU/MSS，未启用
特殊场景 clamp，也没有切换 nic0。

## IPv6 IKE initial-response neighbor repair (2026-10-17)

A cold neighbor entry for the namespace default gateway can remain INCOMPLETE
when IKE binds the WAN /128 alias. The response stays before VPP forwarding.
The lab now obtains the actual VPP control-TAP MAC and installs a permanent
IPv6 neighbor for fd42:1111:2222:50::1 inside the private namespace. This is a
point-to-point instance-local neighbor; deleting the namespace removes it.
Cold probes reached only the namespace TAP; after repair, probes reached the
Linux TAP and WAN with hop limits 64, 63 and 62. Client acceptance is separate.
Evidence: artifacts/vrouter/ipsec-ike-response-path-20261017.json.
