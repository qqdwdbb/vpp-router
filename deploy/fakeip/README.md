# Fake-IP

把匹配域名的 DNS 应答换成保留地址池里的地址，由 VPP 路由到本机透明代理（见 [tproxy-path.md](../tproxy-path.md)）。

- `fakeip.ipv4`、`fakeip.ipv6`：保留地址池，和需要走代理的目的地址段。
- `prepare.py`、`native.py`、`activate.py`、`retire.py`：生成配置、启用和停用。

本目录不含域名列表和服务规则。要走代理的域名写在 DNS 分流配置里，见 [dns-route-gate](../dns-route-gate/README.md)，代理程序需要自行部署。

`prepare.py` 默认转换 `proxylist` 和 `proxylist6`。如果已有其他分流规则也需要迁移到同一 Fake-IP 地址池，用 `--extra-ipv4-rule` 和 `--extra-ipv6-rule` 传入设备配置中的对应规则名。每个参数可独立使用。
