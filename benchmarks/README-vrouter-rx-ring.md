# VROUTER RX ring 对照测试

只调整 nic0-dpdk 的 num-rx-desc，1024/2048/4096，其余 PMD、worker、RX队列数、
TX队列/描述符及8192 buffers配置保持不变。实际测试路径为nic0的WAN VLAN100入、未打标LAN出。
Linux使用既有namespace内的DPDK序号接收器。配置变更需要重启VPP。

`vrouter_rx_ring_trial.py` 必须在VROUTER root环境运行，复用现有recovery模块的验证和健康检查。
它严格匹配当前基线，保存startup.conf原始字节与权限，只改目标接口RX描述符数。
每次apply先启用8分钟独立恢复timer，切换失败也恢复；拒绝覆盖试验范围外的配置变化。
原配置和试验状态私有保存在 `/var/lib/vpp-vrouter/rx-ring-trial/`，不修改安装输入或恢复快照。
已有状态时prepare会拒绝覆盖，重新试验应先检查、确认恢复并归档旧试验记录。

将工具安装到root拥有的 `/run/vrouter-rx-ring-controller.py` 后：

```sh
python3 /run/vrouter-rx-ring-controller.py prepare
python3 /run/vrouter-rx-ring-controller.py apply --ring 1024
# 可能影响当前管理链路的切换应从独立systemd job执行
systemd-run --unit=vrouter-rx-ring-switch2048 --property=RuntimeMaxSec=400 \
  /usr/bin/python3 /run/vrouter-rx-ring-controller.py apply --ring 2048
# 查journal及status确认成功后再发包；不要在测试阶段切换ring
python3 /run/vrouter-rx-ring-controller.py status
# 结束后精确恢复原字节、重启（如有需要）、健康验证并取消回退timer
python3 /run/vrouter-rx-ring-controller.py restore
```

运行renderer与防覆盖测试：

```sh
python3 -m unittest discover -s tests -p test_vrouter_rx_ring_trial.py
```

DPDK接收器启动方法见 `README-vrouter-linux-nat.md`，使用新JSON文件名。
每个ring阶段运行同一组有界流量（每次更换run-base及output）：

```sh
python3 benchmarks/vrouter_trex_sequence_benchmark.py --linux-dpdk \
  --receiver-ip 10.61.20.198 --linux-rx-namespace vrouter-nat-rx \
  --capture-json /tmp/vrouter-ring-dpdk-rx.json \
  --rates 1000,1450000,1500000,1600000,1500000,1600000 \
  --seconds 15 --run-base 361000 --sample-rx-status \
  --output artifacts/vrouter/rx-ring-stage.json
```

1000 PPS功能验证为1秒，其余每阶段15秒；单流64字节源以太帧（含FCS）。
各ring阶段均启用相同的只读RDU采样。harness会记录前后show buffers、分配错误及接收端统计。
此采样影响与前次未加采样的结果不同，应以同轮ring对照为准。
顺序采用1024→2048→4096→1024，最后一轮用于观察重启/时段漂移；不是随机化实验。
DPDK接收器最多32个run，每次6个，本轮共24个。结束停止DPDK/TRex并清除临时NAT/timer。
