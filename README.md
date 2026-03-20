# SELinux Syscall Trace Analyzer

一个轻量的、面向 syscall 序列的 SELinux 静态分析器。

## 功能

- 分析 syscall 序列的 SELinux 权限检查
- 支持 reverse shell 场景分析（socket/connect/dup2）
- 输出详细的分析 trace（hook 链、AVC 四元组、判定结果）
- 支持文本和 JSON 输出格式

## 项目结构

```
selinux_trace_analyzer/
├── models.py           # 核心数据结构
├── knowledge/
│   └── base.py         # 安全知识访问层（policy 查询）
├── handlers/
│   ├── socket_handler.py   # socket() 分析
│   ├── connect_handler.py  # connect() 分析
│   └── dup2_handler.py     # dup2() 分析
├── engine.py           # 主流程驱动
├── report.py           # 输出层
├── main.py             # 主入口
└── tests/
    └── test_analyzer.py    # 单元测试
```

## 快速开始

### 运行演示

```bash
python -m selinux_trace_analyzer.main
```

### 运行测试

```bash
python -m pytest selinux_trace_analyzer/tests/test_analyzer.py -v
```

### 编程使用

```python
from selinux_trace_analyzer import (
    AnalyzerEngine,
    KnowledgeBase,
    Syscall,
)
from selinux_trace_analyzer.report import format_trace_text

# 创建 syscall 序列
syscalls = [
    Syscall(name="socket", args={"family": "AF_INET", "type": "SOCK_STREAM", "protocol": 0}, ret=3),
    Syscall(name="connect", args={"fd": 3, "ip": "10.0.0.1", "port": 4444}),
    Syscall(name="dup2", args={"oldfd": 3, "newfd": 0}),
]

# 初始化并运行分析
kb = KnowledgeBase()
engine = AnalyzerEngine(kb)
trace = engine.analyze(syscalls, current_domain="httpd_t")

# 输出结果
print(format_trace_text(trace))
```

## 设计原则

1. **不做完整内核模拟** - 只维护最小符号状态
2. **显式记录源码逻辑** - 每个 handler 都标注对应的 Linux/SELinux 源码位置
3. **输出 trace 而非仅 allow/deny** - 展示完整的分析轨迹
4. **简化必须显式说明** - 所有简化都通过注释或 rationale 说明

## 支持的 Syscall

| Syscall | LSM Hook | SELinux Hook | AVC 检查 |
|---------|----------|--------------|----------|
| socket | security_socket_create | selinux_socket_create | create |
| connect | security_socket_connect | selinux_socket_connect_helper | connect, name_connect |
| dup2 | 无 | 无 | 无（仅更新 fd 映射） |

## 简化说明（第一版）

- **Policy 查询**: 使用内置规则表，不解析真实 policy 文件
- **端口类型**: 使用内置端口映射，未映射端口返回 `unreserved_port_t`
- **Socket target type**: 简化为与创建 domain 相同
- **不支持**: domain transition、MLS/MCS、NetLabel 等高级特性

## 扩展新 Syscall

1. 在 `handlers/` 目录创建新的 handler 文件
2. 实现 handler 函数：`def handle_xxx(syscall, state, kb) -> StepTrace`
3. 在 `engine.py` 的 `HANDLER_REGISTRY` 中注册

## 参考源码

- Linux kernel: `security/selinux/hooks.c`
- SELinux hooks: `selinux_socket_create()`, `selinux_socket_connect_helper()`
