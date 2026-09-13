# QEMU 限速：vibeOS 与 RISC-V Debian（2026-09-13）

本轮为探索性测量：每个坐标 1 个独立 VM、1 次预热、5 次保留样本。未执行正式 5 VM × 20 样本资格矩阵，也未更新正式 baseline。

## 环境与口径

- 双方 QEMU 11.0.3、virt/rv64、单核 TCG、512 MiB RAM，1 GiB 独立数据盘，virtio queue size 128，`cache=none,aio=threads`。
- 仅数据盘限速：读 4 MiB/s、写 2 MiB/s、读 400 IOPS、写 200 IOPS。QEMU 平均速率允许突发；该模型不模拟 SD 固件、擦除或 flush 延迟。
- vibeOS 使用当前源代码重建的 `storage-bench` 固件，PageDevice cache 固定 64 页；临时构建修改已恢复。实验性 root-bundle 未启用。
- Debian 13 nocloud build 20260810-2566，配置记录的内核为 6.12.101+deb13-riscv64；root 盘独立且不参与数据盘限速。ext4 `data=ordered,barrier=1`。
- 原始块设备在双方均绕过文件页缓存。对象读取为写后立即读取，保留各自缓存语义，不能解释为冷盘 get。
- Linux 对象 put 包含临时文件写入、fdatasync、rename、目录 fsync 与读回核验。vibeOS 为原生对象持久化路径，包含能力/内容完整性元数据；两者存储语义并非逐项等价。
- raw 顺序为 64 MiB 写入、flush、64 MiB 读回，每次提交 128 KiB；下表报完整耗时。原 JSON latency 是完整耗时除以 512，不能把它直接称为整个 64 MiB 耗时。
- 文件顺序为 16 MiB 写入、持久化、读回校验和删除的完整耗时，不是纯 write。
- 不同负载交替先运行 Debian/vibeOS；计时期间本任务未运行编译或测试。只有单主机单 VM 样本，不能排除主机调度影响。

## 中位数

比值为 vibeOS / Debian，越小越好。任一端 CV > 10% 标为高波动，倍数仅描述本次样本。

| 工作负载 / 阶段 | vibeOS | Debian | 比值 | 波动 |
|---|---:|---:|---:|---|
| raw 随机读 4 KiB | 2.487 ms | 2.488 ms | 1.00× | CV ≤ 10%（0.1%/1.4%） |
| raw 随机写 4 KiB + flush | 4.988 ms | 4.987 ms | 1.00× | CV ≤ 10%（0.1%/6.1%） |
| raw 顺序 64 MiB 写 + 64 MiB 读 | 47.718 s | 47.717 s | 1.00× | 高波动（16.5%/0.0%） |
| 对象 put 4 KiB | 49.396 ms | 11.696 ms | 4.22× | 高波动（102.5%/85.5%） |
| 对象 get 4 KiB（写后） | 0.128 ms | 0.084 ms | 1.52× | 高波动（7.5%/114.7%） |
| 对象 put 128 KiB | 36.469 ms | 83.040 ms | 0.44× | CV ≤ 10%（2.4%/9.5%） |
| 对象 get 128 KiB（写后） | 5.795 ms | 0.179 ms | 32.37× | 高波动（16.2%/22.6%） |
| 对象 1 MiB put + get | 729.260 ms | 521.129 ms | 1.40× | CV ≤ 10%（3.3%/2.6%） |
| 文件顺序 16 MiB 完整负载 | 13.337 s | 8.182 s | 1.63× | 高波动（0.7%/17.0%） |

## 对象 I/O（完整 put + get，中位数）

| 大小 | 系统 | 读 KiB | 写 KiB | 写放大 | 读/写/flush 请求 |
|---|---|---:|---:|---:|---|
| 4 KiB | linux-ext4 | 0 | 48 | 12.00× | 0/5/4 |
| 4 KiB | storage-v2 | 4 | 108 | 27.00× | 1/6/3 |
| 128 KiB | linux-ext4 | 0 | 172 | 1.34× | 0/5/4 |
| 128 KiB | storage-v2 | 32 | 236 | 1.84× | 2/7/3 |
| 1024 KiB | linux-ext4 | 0 | 1068 | 1.04× | 0/5/4 |
| 1024 KiB | storage-v2 | 1116 | 1232 | 1.20× | 16/20/3 |

## 运行与正确性证据

- 所有命令、固件及镜像 SHA、原始样本、串口记录和统计位于 `target/storage-debian-throttled-512m-20260913/`。`analysis.json` 还保留每项 min/max/CV。
- `run.py` 在每个非 raw 的 vibeOS VM 结束后执行离线 v2 verifier；Linux runner 在负载结束后卸载数据盘并执行 `e2fsck -fn`。以实际 runner/offline 日志与最终汇总为准。
- `file-batch-create-unique` 没有 Debian 实现，不计算性能比值。
- 128 MiB 尝试因 Debian 停留 UEFI 而超时，记录在 `target/storage-debian-throttled-20260913/`，不参与本表。
- 首次 raw 样本在提交 I/O 前遇到启动恢复的 QueueFull。计时前等待从 1 秒增至 10 秒后重跑，失败尝试独立保留，未纳入统计；该等待不是普遍的就绪保证。
- root-bundle 11 项针对性测试与 RISC-V 裸机编译检查通过，但它仍是独立恢复实验，不属于本次性能优化收益。

## 结论与收尾

在本次限速模型下，raw 随机读写稳定地达到约 400/200 IOPS，继续优化
QD1 提交开销很难在此配置中体现收益。对象层仍有优化空间：4 KiB 写放大
为 27× 对 12×，1 MiB 为 1.20× 对 1.04×；应优先关注小对象元数据写入量
和读取验证所需的真实 I/O。实验性元数据 bundle 暂停在恢复适配器边界，
本轮不接入生产路径、不宣称其获得 QEMU 加速。

128 KiB put 的 0.44× 比值不代表突破 2 MiB/s 的持续写带宽。QEMU 允许突发，
本实验测 guest API 内部阶段，调用外初始化/恢复及串口间隔不在该阶段内；
短阶段可能利用其间积累的额度。本表不能外推到稳态连续请求或真实 SD 卡。

JSONL validate 和 summarize 通过。96 条记录中 90 条 ok（含 15 次预热、
75 次保留测量），6 条为 Debian unique batch 的 unsupported（含 1 次预热）。
5 个非 raw vibeOS 镜像离线检查、8 次 Debian ext4 检查全部通过。
compare 返回 1：能自动配对的指标中 4 项 ok、4 项 inconclusive，未获得资格通过。
旧 Linux agent 的对象记录缺少 content_class，4/128 KiB 还缺 object_count；
自动比较器因此不配对这些对象坐标。本报告按实际调用的一次单对象 put/get
人工配对，原始 JSON 未补写元数据。它是语义接近的工作负载对比，不是完整
qualification 的通过证明。

文件顺序的旧 Linux agent 结果已排除；该坐标使用当前 C 源码重建的独立
agent 补跑，输出 splitmix64-offset-v1 与 workload scope。其他 Linux 坐标
使用原已配置 agent，各自 SHA 保存在环境记录中。原镜像与 agent 没有被覆盖。
补跑 agent 使用本地 LLVM clang、Rust 提供的 ld.lld、已有 Debian sysroot
和 Linux 6.12.27 UAPI 头文件，静态链接；源码 SHA 与二进制 SHA 随报告保存。

所有测试进程已经结束。源码收尾只增加 raw benchmark 失败原因输出和实验
边界文档；无提交、发布或真实 SD 测量。本次也未覆盖原表所有尺寸、revoke、
range-get、GC 或多 VM 稳态资格测试。
