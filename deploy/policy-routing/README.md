# 可选的 VPP 源地址策略路由

`source-routes.py --config FILE` 用 VPP ACL/ABF 管理按源网段选出口的策略，并跟随 VPP 重启及输入接口的出现恢复。它不配置 Linux fwmark，不属于通用安装器的默认启动链；仅在站点确有需要时单独部署。

配置显式提供 `policies` 列表，每项包含 `id`、`name`、`sources`、`via`、`output_interface`、`interfaces`。`exclude_destinations` 中的目的网段继续使用正常 FIB；可选 `exclude_lan_interface` 将该接口当前地址对应的网段加入排除列表，适用于动态 IPv6-PD。

```json
{"policies":[{"id":6000,"name":"vpn-clients","sources":["10.10.0.0/24"],"exclude_destinations":["10.0.0.0/8"],"via":"192.0.2.1","output_interface":"wan1","interfaces":["wg0"]}]}
```

先用 `--once` 验证，再由独立的站点服务运行。策略 ID 必须与其他 ABF 使用者分开；工具根据 ACL tag 校验所有权，遇到外来策略会拒绝覆盖。`/run/vpp-source-routes/state.json` 记录本次 VPP 实例的状态。

常驻运行时每 2 秒只读一次 `show interface address`。配置文件、VPP 实例或接口地址变化，或上次失败时，才完整对账 ACL/ABF；平时每 5 分钟再对账一次，以修复被手工删除的策略。`show acl-plugin acl` 在未打 `patches/vpp/0026` 的 VPP 上每次调用都会泄漏主堆，因此不再按 2 秒周期调用它。
