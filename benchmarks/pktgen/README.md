# pktgen-net

临时配置发包服务器的网络，只改运行时状态，状态文件在 `/run/pktgen-net`，重启后全部消失。

```sh
cp pktgen-net.conf.example pktgen-net.conf   # 改成自己的接口和地址
sudo ./pktgen-net.sh up                   # 默认 120 分钟后自动恢复
sudo ./pktgen-net.sh up --ttl 30
./pktgen-net.sh status
sudo ./pktgen-net.sh down
```

脚本用 `ss` 查所有已建立的 SSH 连接（端口由 `SSH_PORT` 指定，默认 22），这些网口只会增减地址，不会被清空，NetworkManager 托管状态也不变。配置文件也可以用 `--conf FILE` 指定。

`DEFAULT_VIA` 会改默认路由，如果 SSH 客户端不在直连网段，可能断开连接，此时靠自动恢复还原。

`up` 保存并修改：接口 IPv4 地址、NetworkManager 托管状态、默认路由、PAUSE、CPU 调频策略。`down` 按保存的状态恢复。IPv6 不处理。
