#!/usr/bin/env python3
"""
main.py - SELinux Syscall Trace Analyzer 主入口

用法：
====
python -m selinux_trace_analyzer.main

或：
python main.py

本脚本演示 reverse shell 场景的 SELinux 分析：
- 当前 domain: httpd_t
- syscall 序列：socket -> connect -> dup2

预期结果：
========
- socket() 创建 tcp_socket: allow
- connect() 到 4444 端口：name_connect 被拒绝（因为 4444 是 unreserved_port_t）
"""

from .models import Syscall, AnalysisState, AnalysisTrace
from .knowledge.base import KnowledgeBase
from .engine import AnalyzerEngine
from .report import format_trace_text, format_trace_json


def create_reverse_shell_syscalls() -> list[Syscall]:
    """
    创建 reverse shell 场景的 syscall 序列。
    
    序列：
    1. socket(AF_INET, SOCK_STREAM, 0) -> fd=3
    2. connect(fd=3, ip=10.0.0.1, port=4444)
    3. dup2(oldfd=3, newfd=0)  # stdin
    4. dup2(oldfd=3, newfd=1)  # stdout
    5. dup2(oldfd=3, newfd=2)  # stderr
    """
    syscalls: list[Syscall] = []
    
    # 1. socket()
    syscalls.append(Syscall(
        name="socket",
        args={
            "family": "AF_INET",
            "type": "SOCK_STREAM",
            "protocol": 0,
        },
        ret=3,
        index=0,
    ))
    
    # 2. connect()
    syscalls.append(Syscall(
        name="connect",
        args={
            "fd": 3,
            "ip": "10.0.0.1",
            "port": 4444,
        },
        index=1,
    ))
    
    # 3. dup2(3, 0) - stdin
    syscalls.append(Syscall(
        name="dup2",
        args={"oldfd": 3, "newfd": 0},
        index=2,
    ))
    
    # 4. dup2(3, 1) - stdout
    syscalls.append(Syscall(
        name="dup2",
        args={"oldfd": 3, "newfd": 1},
        index=3,
    ))
    
    # 5. dup2(3, 2) - stderr
    syscalls.append(Syscall(
        name="dup2",
        args={"oldfd": 3, "newfd": 2},
        index=4,
    ))
    
    return syscalls


def create_http_connect_syscalls() -> list[Syscall]:
    """
    创建正常 HTTP 连接的 syscall 序列（用于对比）。
    
    序列：
    1. socket(AF_INET, SOCK_STREAM, 0) -> fd=3
    2. connect(fd=3, ip=93.184.216.34, port=80)  # example.com
    """
    syscalls: list[Syscall] = []
    
    # 1. socket()
    syscalls.append(Syscall(
        name="socket",
        args={
            "family": "AF_INET",
            "type": "SOCK_STREAM",
            "protocol": 0,
        },
        ret=3,
        index=0,
    ))
    
    # 2. connect() - 到 HTTP 端口（应该允许）
    syscalls.append(Syscall(
        name="connect",
        args={
            "fd": 3,
            "ip": "93.184.216.34",
            "port": 80,
        },
        index=1,
    ))
    
    return syscalls


def run_analysis(
    syscalls: list[Syscall],
    current_domain: str = "httpd_t",
    output_format: str = "text"
) -> AnalysisTrace:
    """
    运行 SELinux 分析。
    
    参数：
    - syscalls: syscall 序列
    - current_domain: 当前进程的 SELinux domain
    - output_format: 输出格式 ("text" 或 "json")
    
    返回：
    - AnalysisTrace 对象
    """
    # 初始化知识库
    kb = KnowledgeBase()
    
    # 初始化分析引擎
    engine = AnalyzerEngine(kb)
    
    # 运行分析
    trace = engine.analyze(syscalls, current_domain)
    
    # 输出结果
    if output_format == "json":
        print(format_trace_json(trace))
    else:
        print(format_trace_text(trace))
    
    return trace


def main():
    """主函数。"""
    print("=" * 60)
    print("SELinux Syscall Trace Analyzer - Reverse Shell 分析")
    print("=" * 60)
    print()
    
    # 分析 reverse shell 场景
    print("场景 1: Reverse shell (httpd_t 尝试连接 4444 端口)")
    print("-" * 60)
    reverse_shell_syscalls = create_reverse_shell_syscalls()
    trace1 = run_analysis(reverse_shell_syscalls, current_domain="httpd_t")
    print()
    
    # 分析正常 HTTP 连接场景
    print("=" * 60)
    print("场景 2: 正常 HTTP 连接 (httpd_t 连接 80 端口)")
    print("-" * 60)
    http_syscalls = create_http_connect_syscalls()
    trace2 = run_analysis(http_syscalls, current_domain="httpd_t")
    print()
    
    # 分析 unconfined_t 场景
    print("=" * 60)
    print("场景 3: Reverse shell (unconfined_t 尝试连接 4444 端口)")
    print("-" * 60)
    trace3 = run_analysis(reverse_shell_syscalls, current_domain="unconfined_t")
    print()


if __name__ == "__main__":
    main()
