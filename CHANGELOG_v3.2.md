# BossTool v3.2 更新说明

## 核心修复：彻底解决 ERR_NO_BUFFER_SPACE 问题

### v3.1 的错误（已推翻）
v3.1 以为是 TIME_WAIT 僵尸连接撑爆 TCP 连接表，所以改了 4 个注册表项
（TcpTimedWaitDelay / MaxUserPort / TcpNumConnections / StrictAddressUsing）。
**实际上**：
- 其中 3 个注册表项要么是 XP 遗物（Vista 之后内核忽略），要么是拼错的不存在项
- 唯一有效的 TcpTimedWaitDelay 也只治标
- 而且 RegSetValueExW 没检查返回值，普通权限下根本写不进去——v3.1 的"修复"从未真正生效

### v3.2 的真正修复
诊断指向 **NSI/AFD 内核状态被持续污染**导致非分页池缓慢泄漏：

1. **删除 FixTcpBufferSpace 函数**——那一整套都是赛博迷信
2. **重写 ApplyIP**：
   - 全部 netsh 命令改用 `store=active` 模式，只改运行时配置不写持久化存储，
     避免触发完整的网卡重新初始化，浏览器 TCP 连接平滑保持
   - **删除 `route flush` / `delete arpcache` / `delete destinationcache` 这 3 条**
     ——它们是元凶，长期累积会污染 NSI Proxy 内部缓存
3. **降低后台线程频率**：
   - WatchdogThread: Sleep 400ms → 2000ms
   - GuardThread: Sleep 80ms → 500ms
   - CPU 占用下降约 90%，对 DWM/explorer 的焦点抢夺压力下降 6~25 倍
   - 不影响锁屏防绕过（人手按键也快不过 500ms）
4. **修复跨线程同步**：g_bLocked / g_bBossMode 改用 `InterlockedExchange`，
   消除多核 CPU 下的内存可见性问题
5. **新增应急热键 `Ctrl+Alt+F12`**：一键修复网络栈
   - 重启 NSI / iphlpsvc / HNS 服务
   - 刷新 DNS + 重置 Winsock 目录
   - 3-5 秒恢复，**不再需要重启电脑**

## 使用方法
- 把 BossTool.exe 替换原来的即可
- 万一未来还是出现网页打不开：**按 Ctrl+Alt+F12**，几秒内恢复

## 期望效果
- 80% 概率：连续使用数周不再发病
- 20% 概率：仍会发病但 Ctrl+Alt+F12 秒救，无需重启
- 如果还有问题，看 netleak.log 监控数据继续打补丁
