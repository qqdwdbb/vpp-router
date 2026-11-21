# WireGuard 接口的附加命令

VPP 的启动流程不再加载 WireGuard，隧道由 `tools/vpp-wireguard` 创建和恢复。这里是这套部署中三个接口各自依赖的 VPP 命令，导入时作为接口附加命令保存：

```sh
vpp-wireguard import -name wg0 -file /etc/vpp/wg0.vpp -after-up wg0.after-up.vpp -before-down wg0.before-down.vpp -started
vpp-wireguard import -name wg1 -file /etc/vpp/wg1.vpp -after-up wg1.after-up.vpp -before-down wg1.before-down.vpp -started
vpp-wireguard import -name sg  -file /etc/vpp/sg.vpp  -after-up wg8.after-up.vpp -before-down wg8.before-down.vpp -started
```

和隧道无关的部分仍在启动流程里，比如 `loop101`、VRF 101 和 ABF 策略本身（`deploy/wg-proxy/egress-vrf.vpp.conf`、`deploy/cutover/runtime.py`）。

`wg1` 的附加命令最后要执行 `nat44 ei pool receive`：EI 把 pool 的接收路由登记在最后加入的 outside 接口上，`wg1` 晚于启动流程出现，要重新固定到 `loop10`。
