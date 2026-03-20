"""
report.py - 输出层

功能：
把内部 AnalysisTrace 格式化为人类可读文本或 JSON。

输出形式：
========
A. 文本 trace - 适合调试和研究展示
B. JSON - 便于后续可视化和程序消费

简化说明：
========
- 第一版只实现基础格式化
- JSON 输出使用 dataclasses.asdict() 简单转换
- 不支持自定义输出模板
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from typing import Any

# 添加父目录到路径，以便导入
_parent_dir = os.path.dirname(os.path.abspath(__file__))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from models import AnalysisTrace, StepTrace, AVCCheck


def format_trace_text(trace: AnalysisTrace) -> str:
    """
    将 AnalysisTrace 格式化为人类可读文本。
    
    输出格式示例：
    =============
    [1] socket(AF_INET, SOCK_STREAM, 0) -> fd=3
      hook chain:
        syscall -> security_socket_create -> selinux_socket_create
      checks:
        1. (httpd_t, httpd_t, tcp_socket, create) => allow
      state:
        fd 3 -> socket#1 (tcp_socket)
    
    [2] connect(fd=3, 10.0.0.1:4444)
      hook chain:
        syscall -> security_socket_connect -> selinux_socket_connect_helper
      checks:
        1. (httpd_t, httpd_t, tcp_socket, connect) => allow
        2. (httpd_t, unreserved_port_t, tcp_socket, name_connect) => deny
      summary:
        connect denied by name_connect on unreserved_port_t
    
    Final:
      reverse shell blocked at connect()
    """
    lines: list[str] = []
    
    for i, step in enumerate(trace.steps, 1):
        syscall = step.syscall
        
        # 构建 syscall 描述
        syscall_desc = _format_syscall(syscall)
        
        # 步骤标题
        lines.append(f"[{i}] {syscall_desc}")
        
        # Hook 链信息（从第一个 check 获取）
        if step.checks:
            check = step.checks[0]
            hook_chain = _format_hook_chain(check)
            if hook_chain:
                lines.append(f"  hook chain:")
                lines.append(f"    {hook_chain}")
        
        # AVC 检查
        if step.checks:
            lines.append("  checks:")
            for j, check in enumerate(step.checks, 1):
                result_str = "allow" if (check.result and check.result.allowed) else "deny"
                lines.append(
                    f"    {j}. ({check.source_type}, {check.target_type}, "
                    f"{check.tclass}, {check.perm}) => {result_str}"
                )
                
                # 添加拒绝原因
                if check.result and not check.result.allowed:
                    lines.append(f"       reason: {check.result.reason}")
        
        # 状态更新
        if step.state_updates:
            lines.append("  state:")
            for update in step.state_updates:
                lines.append(f"    {update}")
        
        # 步骤摘要
        if step.summary:
            lines.append(f"  summary: {step.summary}")
        
        lines.append("")  # 空行分隔
    
    # 最终摘要
    lines.append("=" * 60)
    lines.append(f"Final Summary:")
    lines.append(f"  {trace.final_summary}")
    
    return "\n".join(lines)


def format_trace_json(trace: AnalysisTrace) -> str:
    """
    将 AnalysisTrace 格式化为 JSON 字符串。
    
    便于后续可视化和程序消费。
    """
    # 使用 dataclasses.asdict() 转换
    # 注意：需要处理可能的 None 值和非序列化对象
    
    def serialize(obj: Any) -> Any:
        """自定义序列化器。"""
        if hasattr(obj, '__dataclass_fields__'):
            return asdict(obj)
        elif isinstance(obj, dict):
            return {k: serialize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [serialize(v) for v in obj]
        else:
            return obj
    
    data = serialize(trace)
    return json.dumps(data, indent=2, ensure_ascii=False)


def _format_syscall(syscall: StepTrace | Any) -> str:
    """
    格式化 syscall 描述。
    """
    name = syscall.name
    args = syscall.args
    
    # 构建参数描述
    if name == "socket":
        family = args.get("family", "AF_INET")
        sock_type = args.get("type", "SOCK_STREAM")
        protocol = args.get("protocol", 0)
        desc = f"{name}({family}, {sock_type}, {protocol})"
        if syscall.ret is not None:
            desc += f" -> fd={syscall.ret}"
    
    elif name == "connect":
        fd = args.get("fd", "?")
        ip = args.get("ip", "0.0.0.0")
        port = args.get("port", 0)
        desc = f"{name}(fd={fd}, {ip}:{port})"
    
    elif name == "dup2":
        oldfd = args.get("oldfd", "?")
        newfd = args.get("newfd", "?")
        desc = f"{name}({oldfd}, {newfd})"
    
    else:
        # 通用格式
        args_str = ", ".join(f"{k}={v}" for k, v in args.items())
        desc = f"{name}({args_str})"
    
    return desc


def _format_hook_chain(check: AVCCheck) -> str:
    """
    格式化 hook 链描述。
    """
    parts = ["syscall"]
    
    if check.lsm_hook:
        parts.append(check.lsm_hook)
    
    if check.selinux_hook:
        parts.append(check.selinux_hook)
    
    if check.selinux_impl:
        # 只显示关键部分
        impl = check.selinux_impl
        if ";" in impl:
            impl = impl.split(";")[0]  # 只显示第一部分
        parts.append(impl)
    
    return " -> ".join(parts)


def print_trace(trace: AnalysisTrace, format: str = "text") -> None:
    """
    打印 trace 到标准输出。
    
    参数：
    - trace: AnalysisTrace 对象
    - format: 输出格式 ("text" 或 "json")
    """
    if format == "json":
        print(format_trace_json(trace))
    else:
        print(format_trace_text(trace))


def save_trace(trace: AnalysisTrace, path: str, format: str = "text") -> None:
    """
    保存 trace 到文件。
    
    参数：
    - trace: AnalysisTrace 对象
    - path: 输出文件路径
    - format: 输出格式 ("text" 或 "json")
    """
    if format == "json":
        content = format_trace_json(trace)
    else:
        content = format_trace_text(trace)
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
