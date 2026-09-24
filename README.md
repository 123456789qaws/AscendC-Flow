# AscendC-Flow

昇腾算子执行流程研究工具：导入执行轨迹、分析显式声明的有限 Petri 网模型，并导出 PNML 与可重放反例。

仅使用 Python 标准库，无第三方 Python 依赖；已在 Python 3.14 上验证。分析手工模型无需安装 CANN，真实轨迹采集需自行配置官方工具。

```text
python -m tools.ascend_flow doctor
python -m tools.ascend_flow analyze examples/ascend_flow/add_manual_missing_signal.json --output output/missing_signal.json
python -m unittest discover -s tests
```

详见 [工具说明](tools/ascend_flow/README.md)。`examples/ascend_flow/` 包含正常流程、缺失通知、错误事件、重复通知与两个 tile 的有限模型。

研究边界：本工具不解析任意 Ascend C 源码，不实现有限完全行为展开前缀，也不证明真实硬件无死锁。单次轨迹不能代表完整程序语义。
