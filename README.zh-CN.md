# dsh-windows-settlement-proof

作者 / 维护者：贺去病（贺方升 / Dosen）· [hequbing.com](https://www.hequbing.com)

这是 Windows 企业运维的“落地结算证据层”：对照显式哈希锁，离线验证一次已批准变更是否在服务配置、服务运行态、计划任务、事件记录与策略投影等必需表面真正收敛，并满足时间顺序、证据新鲜度和重启代数要求。

它只验证，不执行。不会调用 PowerShell、`sc.exe`、注册表或任意子进程，也不会读取或输出服务名、命令行、任务 XML、事件正文或业务内容。报告只含公开计数、布尔判决与 SHA-256。

与 `dsh-windows-readiness-proof` 的“开工前先决条件”互补；与通用的 `dsh-decision-effect-proof` 互补。本插件专门验证 Windows 控制面变更的跨表面、跨重启落地，不实现第二套动作核心。

示例见 [`examples/settled.json`](examples/settled.json)。运行：

```bash
npm test
npm run check
node bin/dsh-windows-settlement-proof.mjs verify examples/settled.json
```
