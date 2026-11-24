# linux-socket-receive-buffer-drop-analyzer

离线分析 socket 接收缓冲、cgroup 内存压力与丢包归因的工具（Python 3.8.2）。

**本工具只分析离线导出的指标文件，不采集、不修改任何线上系统配置。**

## 输入

JSON 文件，包含 `config`（阈值，可缺省）与 `slices`（按时间片导出的指标）：

| 字段 | 含义 |
| --- | --- |
| `timestamp` | 时间片起始时间（秒） |
| `bytes_arrived` / `bytes_read` | 该时间片到达字节数 / 应用读取字节数 |
| `sk_rcvbuf` | 当前 socket 接收缓冲（autotuning 后的实际值） |
| `rmem_max` / `rmem_default` | `net.core.rmem_max` / `rmem_default` |
| `autotuning_enabled` | `net.ipv4.tcp_moderate_rcvbuf` 是否开启 |
| `cgroup_usage` / `cgroup_limit` / `cgroup_stall_ms` | cgroup 内存用量、限额与 memory stall |
| `skb_total` / `skb_merged` | skb 总数与合并（GRO 等）数量 |
| `drops` | 该时间片丢包计数 |

示例见 `examples/sample_input.json`。

## 分析逻辑

按时间片计算：

- **有效缓冲** = `min(sk_rcvbuf, rmem_max)`，若 cgroup 内存接近限额或存在 stall，则进一步受 cgroup 剩余内存约束；
- **缓冲占用** 由到达与读取字节数累积估计；
- **丢包归因** 分为四类：应用读取慢、autotuning 未生效（未开启或被 SO_RCVBUF 固定在默认值）、cgroup 内存不足、短时突发；
- 多个因素同时成立或证据不足的时间片归入**仍需人工判断的区间**，不做武断归因；
- 若检测到持续的应用读取停顿，报告会明确警告：**扩大 rmem/sk_rcvbuf 只会推迟丢包，不能掩盖应用停顿**，扩容建议自动降级。

## 输出

- 缓冲曲线（每时间片占用/有效缓冲的 ASCII 曲线与标记）
- 丢包归因统计（各类原因计数与占比）
- 应用读取停顿区间
- 仍需人工判断的区间
- 修复建议

## 使用

```bash
python -m rcvbuf_analyzer examples/sample_input.json
python -m rcvbuf_analyzer input.json -o report.txt
```

## 测试

```bash
python -m unittest
```

测试覆盖慢读取、cgroup 限流、突发流量、autotuning 失效与归因不明等场景。
