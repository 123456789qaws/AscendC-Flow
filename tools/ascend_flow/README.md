# 昇腾执行流程研究工具

Python标准库实现，目标为Ascend910B4 / CANN9.1.x。官方工具负责采集；本工具负责保留证据、检查缺口，并分析明确给定的有限语义模型。

## 当前能做什么

1. 导入Chrome事件格式的官方仿真 `trace.json`，保留事件地址、原始参数、管线标识、来源索引及文件哈希。
2. 将 `core*_instr_exe.csv` 识别为聚合统计，避免把累计耗时误当执行时间戳。其他CSV事件表必须提供显式列映射。
3. 对手工声明的有限流水程序生成资源身份展开后的P/T网、运行完整状态空间搜索，并导出PNML和可重放反例。
4. 分开报告死锁、非法协议、结束后残留资源，以及搜索截断。采集失败状态可通过哈希绑定的manifest附带到观察结果。

**尚不支持**：任意Ascend C源码解析、自动恢复框架eventID、从不完整轨迹生成全程序模型、真实硬件等价性证明、有限完全行为展开前缀。PNML属于颜色实例化结果，不是行为展开。工具不会从一次运行“没挂”推出程序无死锁。

## 使用

以下命令均从项目根目录执行。Windows使用 `python`，Linux可用 `python3`，不需要安装第三方包。

```text
python -m tools.ascend_flow doctor
python -m tools.ascend_flow analyze examples/ascend_flow/add_manual_missing_signal.json --output output/missing_signal.json
python -m tools.ascend_flow export-pnml examples/ascend_flow/add_manual_normal.json --output output/normal.pnml
python -m tools.ascend_flow import-trace /path/to/trace.json --output output/observations.json
python -m unittest discover -s tests
```

`analyze --state-limit N` 限制储存标识数。CLI退出0只代表工具完成，不代表无缺陷；必须读取 `status`、`complete` 和全部 `counts`。存在已验证反例但搜索未完成时，反例依然有效，缺陷数量不完整。`unknown`绝不转换为安全。

真实轨迹的时间值保持原样；默认单位为unknown。只有确认对应导出格式的单位后才提供 `--time-unit us` 等标签。文件中的持续时间不证明采集正常结束。没有manifest时 `capture_status=unknown`。

## 两种输入不能混用

`ascend-observation/1` 是观察事实：记录了什么，不代表未记录行为不可能。

`ascend-program/1` 是显式语义声明：完整列出本次分析的有限动作序列、资源实例和物理旗标键。当前只接受 `manual_semantic_model`，并要求 `hardware_validated=false`。从观察结果直接调用 `analyze` 会被拒绝。

程序输入必需字段：`schema,target,provenance,resources,flags,programs`。样例JSON是可执行规范。操作只支持：

| 动作 | 必需参数 | 抽象语义 |
|---|---|---|
| work | 无，可加label | 一个原子完成步骤，不是异步发射 |
| acquire | resource | 从空闲取得确定身份资源 |
| release | resource | 由持有者归还，其他情况报告协议错误 |
| set | flag | 0变1；已为1时进入诊断边界 |
| wait | flag | 1变0；0时等待 |

每个动作可携带 `source` JSON对象，原样进入反例，便于以后绑定源码或指令地址。未知动作、未声明身份、重复物理旗标、未支持的guard/loop字段均拒绝，不能静默忽略。

## 研究边界

Add手工样例保留X/Y/Z三个缓冲身份及四类通知，但采用简化生命周期控制，未从编译产物生成，也不是现有VAdd XML的修复版。它会限制某些实际重叠执行，不能用于硬件无死锁或性能结论。两个tile是显式有限重复，不证明任意迭代。

分析网使用全局RUN令牌使协议错误成为停止分析的终点。该编码保持所定义的交错状态语义，但给不同流水加入人工结构依赖；不能据此声称偏序展开有缩减效果。后续行为展开研究应分离合法行为网和诊断监视器。

## 采集证据归档

自行使用官方工具完成采集后，可归档轨迹、统计和日志，并生成 SHA-256 清单：

```text
python -m tools.ascend_flow.collect_capture_artifacts /path/to/capture /path/to/capture.log output/capture
python -m tools.ascend_flow import-trace output/capture/trace.json --capture-manifest output/capture/manifest.json --output output/observations.json
```

采集目录需包含恰好一个 `OPPROF_*/simulator/trace.json`。可重复传入 `--completion-marker` 指定应用自身的完成标记；profiler 退出码为 0 不代表应用成功。

本仓库仅包含通用 Python 工具、手工模型样例和不依赖本地采集数据的单元测试。本机专用采集脚本、真实采集数据、日志、分析输出及论文资料不随仓库分发。原工作区的 CLI 集成测试依赖未分发的真实采集数据，因此不纳入本仓库；CLI 可按上面的样例命令验证。

所有结果均为辅助研究材料，需使用者核查。
