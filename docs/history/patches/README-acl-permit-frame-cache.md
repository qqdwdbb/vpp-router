# ACL 普通 permit 的帧内结果复用

补丁：`acl-permit-frame-cache.patch`；配套头文件：`acl-permit-frame-cache.h`。
目标：当前 VPP 26.06 ACL dataplane，保留普通 permit 的单向、无会话语义。

## 实现

在每次 `acl_fa_inner_node_fn` 调用的栈上保存一个普通 permit 结果。
当批次开头两个包的完整 tuple 与完整接口号相同时，才启用本次调用的缓存。
后续包仍先做原有会话检查；确需 ACL 匹配时，完整 key 相同才复用结果。
其他情况调用原有 classifier。

- key 覆盖完整 48 字节 tuple、完整 32 位 sw_if_index、lookup context。
  tuple 包含 IPv4/IPv6 地址、端口、协议、方向、L4 有效性、TCP flags 和分片状态。
- 只保存 `is_match && action == 1`。deny 与 permit+reflect 不进入缓存。
- trace 路径使用原 classifier；规则匹配元数据和逐包计数路径保留。
- 会话查找、会话老化和 reflect 会话创建逻辑不变。
- 缓存不跨 node 调用、frame、worker 或控制平面 barrier；不引入持久流表、超时或 epoch 回绕问题。
- 仅增加末尾 node counter：`frame permit cache hits`。不调整原有 error/action 索引。

这是针对批内重复流的优化，不能替代跨批次的多流缓存。首两个包不同会关闭该批次缓存；
这可能放弃一些后续重复包的优化，但不会改变匹配结果。典型2万流轮转不受益，仍走原查表路径。

## 构建

将补丁、头文件复制到 VROUTER 的同一个 assets 目录，然后执行：

```sh
python3 build/history/build-acl-permit-cache.py \
  --assets /absolute/path/to/assets \
  --output /absolute/path/to/new-candidate-directory
```

构建器使用 `/usr/local/src/vpp-vrouter/nic1-test` 中保留的构建命令。
先重新链接原对象并验证其 `.text`、`.rodata`、`.data`、`.eh_frame` 与运行库一致，
再仅重编译 `dataplane_node.c`，在独立目录链接候选。安装库存在 RUNPATH 重定位，
不能仅用整文件 SHA 比较重新链接的原始产物。

构建不覆盖源树、原对象、运行库或恢复基线，不重启 VPP。

## 验证

```sh
cc -O2 -Wall -Wextra -Werror -fsanitize=address,undefined \
  tests/unit/test_acl_permit_frame_cache.c -o /tmp/test-acl-cache
/tmp/test-acl-cache
python3 tests/integration/integration_acl_permit_frame_cache.py \
  --candidate /absolute/path/to/acl_plugin.so \
  --benchmark-packets 1000000 --output /tmp/acl-cache-result.json
```

集成测试需在 VROUTER 以 root 运行。它仅启动隔离 VPP/PG，使用 CPU6，不创建生产物理口或 TAP；
基准期间临时锁定 policy6 为 2208 MHz，并在 finally 恢复。原版和候选均执行普通 permit、
反向拒绝、TCP flags、端口变化、IPv6、分片、规则替换、trace、reflect 以及单流/2万流基准。

2026-10-30 最终候选：
`/usr/local/src/vpp-vrouter/maintenance/acl-permit-frame-cache-v3/acl_plugin.so`。
SHA256：`9c126c015d5e530b9b436afcdc74cb94cc925f1b1f4a34264ffffd12a87322e0`。

隔离单流基准的 ACL 节点 Packet-Clocks 约下降51%；2万流轮转未观察到回退。
上述隔离结果不直接等于线上 NAT PPS 增幅。
后续现场28阶段A/B已完成：单流2MPPS输入时有效转发均值约提高12.39%，
候选两次1.8MPPS/10秒收齐；2万流轮转缓存命中为0，未证明稳定收益。
现场测试后曾恢复原ACL库；随后用户授权正式部署，2026-10-30已接受上述v3候选，
运行库、安装输入和恢复基线已同步，13服务及WAN/DNS/HTTPS检查通过。
部署记录见 `artifacts/vrouter/acl-cache-accepted-20261030.md`。
隔离验证见 `artifacts/vrouter/acl-permit-frame-cache-20261030.md`；
现场验证见 `artifacts/vrouter/acl-cache-nat-20261030.md`。
