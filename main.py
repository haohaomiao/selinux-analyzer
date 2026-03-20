#!/usr/bin/env python3
"""
main.py - SELinux Syscall Trace Analyzer 主入口

用法：
====
# 分析 reverse shell 场景（使用真实 policy 和 file_contexts）
python -m selinux_analyzer.main \
    --policy ./policy.30 \
    --fc ./fc \
    --portcon ./portcon.txt \
    --source-type httpd_t \
    --remote-port 4444

# 分析正常 HTTP 连接
python -m selinux_analyzer.main \
    --policy ./policy.30 \
    --fc ./fc \
    --portcon ./portcon.txt \
    --source-type httpd_t \
    --remote-port 80

# 使用 execve 场景
python -m selinux_analyzer.main \
    --policy ./policy.30 \
    --fc ./fc \
    --source-type httpd_t \
    --exec-path /bin/sh
"""

import argparse
import json
import sys
import os

# 添加父目录到路径，以便导入
_parent_dir = os.path.dirname(os.path.abspath(__file__))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from models import Syscall, AnalysisState, AnalysisTrace
from knowledge.base import KnowledgeBase
from engine import AnalyzerEngine
from report import format_trace_text, format_trace_json


def create_reverse_shell_syscalls(remote_port: int = 4444, remote_ip: str = "10.0.0.1") -> list[Syscall]:
    """
    创建 reverse shell 场景的 syscall 序列。

    序列：
    1. socket(AF_INET, SOCK_STREAM, 0) -> fd=3
    2. connect(fd=3, ip=<remote_ip>, port=<remote_port>)
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
            "ip": remote_ip,
            "port": remote_port,
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


def create_http_connect_syscalls(port: int = 80, ip: str = "93.184.216.34") -> list[Syscall]:
    """
    创建正常 HTTP 连接的 syscall 序列（用于对比）。

    序列：
    1. socket(AF_INET, SOCK_STREAM, 0) -> fd=3
    2. connect(fd=3, ip=<ip>, port=<port>)
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
            "ip": ip,
            "port": port,
        },
        index=1,
    ))

    return syscalls


def create_execve_syscalls(exec_path: str = "/bin/sh") -> list[Syscall]:
    """
    创建 execve 场景的 syscall 序列。

    序列：
    1. execve(path=<exec_path>, argv=[...], envp=None)
    """
    syscalls: list[Syscall] = []

    # 1. execve()
    syscalls.append(Syscall(
        name="execve",
        args={
            "path": exec_path,
            "argv": [exec_path, None],
            "envp": None,
        },
        index=0,
    ))

    return syscalls


def create_open_read_syscalls(file_path: str = "/etc/passwd") -> list[Syscall]:
    """
    创建 open/read 文件场景的 syscall 序列。

    序列：
    1. open(path=<file_path>, flags=O_RDONLY) -> fd=3
    2. read(fd=3, buf=stack, count=0xFFF)
    """
    syscalls: list[Syscall] = []

    # 1. open()
    syscalls.append(Syscall(
        name="open",
        args={
            "path": file_path,
            "flags": "O_RDONLY",
        },
        ret=3,
        index=0,
    ))

    # 2. read()
    syscalls.append(Syscall(
        name="read",
        args={
            "fd": 3,
            "buf": "stack",
            "count": 0xFFF,
        },
        index=1,
    ))

    return syscalls


def create_open_write_syscalls(file_path: str = "/etc/passwd") -> list[Syscall]:
    """
    创建 open/write 文件场景的 syscall 序列（如添加用户）。

    序列：
    1. open(path=<file_path>, flags=O_WRONLY|O_APPEND) -> fd=3
    2. write(fd=3, buf="...", count=N)
    """
    syscalls: list[Syscall] = []

    # 1. open()
    syscalls.append(Syscall(
        name="open",
        args={
            "path": file_path,
            "flags": "O_WRONLY|O_APPEND",
        },
        ret=3,
        index=0,
    ))

    # 2. write()
    syscalls.append(Syscall(
        name="write",
        args={
            "fd": 3,
            "buf": "new_user_entry",
            "count": 100,
        },
        index=1,
    ))

    return syscalls


def run_analysis(
    syscalls: list[Syscall],
    kb: KnowledgeBase,
    current_domain: str = "httpd_t",
    output_format: str = "text"
) -> AnalysisTrace:
    """
    运行 SELinux 分析。

    参数：
    - syscalls: syscall 序列
    - kb: KnowledgeBase 实例
    - current_domain: 当前进程的 SELinux domain
    - output_format: 输出格式 ("text" 或 "json")

    返回：
    - AnalysisTrace 对象
    """
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
    parser = argparse.ArgumentParser(
        description="SELinux Syscall Trace Analyzer - 分析 syscall 序列的 SELinux 权限检查",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Policy 和数据文件
    parser.add_argument(
        "--policy",
        type=str,
        default=None,
        help="SELinux policy 文件路径（如 policy.30）"
    )
    parser.add_argument(
        "--fc",
        type=str,
        default=None,
        help="file_contexts 文件路径"
    )
    parser.add_argument(
        "--portcon",
        type=str,
        default=None,
        help="port context 文件路径（如 portcon.txt）"
    )

    # 分析参数
    parser.add_argument(
        "--source-type",
        type=str,
        default="httpd_t",
        help="源 SELinux domain（进程类型）"
    )
    parser.add_argument(
        "--remote-port",
        type=int,
        default=4444,
        help="远程连接端口（用于 connect 场景）"
    )
    parser.add_argument(
        "--remote-ip",
        type=str,
        default="10.0.0.1",
        help="远程连接 IP"
    )
    parser.add_argument(
        "--exec-path",
        type=str,
        default=None,
        help="execve 执行的文件路径"
    )
    parser.add_argument(
        "--file-path",
        type=str,
        default=None,
        help="open/read/write 操作的文件路径"
    )

    # 场景选择
    parser.add_argument(
        "--scenario",
        type=str,
        choices=["reverse_shell", "http_connect", "execve", "open_read", "open_write"],
        default="reverse_shell",
        help="分析场景选择"
    )

    # 输出格式
    parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="输出格式"
    )

    args = parser.parse_args()

    # 确定当前工作目录（用于解析相对路径）
    # 使用 __file__ 获取脚本的绝对路径
    # main.py 在 selinux-analyzer/ 目录下，文件在父目录 f5_analysis/ 下
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)  # f5_analysis 目录

    # 解析 policy 路径
    policy_path = args.policy
    if policy_path:
        if not os.path.isabs(policy_path):
            policy_path = os.path.join(base_dir, os.path.basename(policy_path))
        policy_path = os.path.normpath(policy_path)

    # 解析 fc 路径
    fc_path = args.fc
    if fc_path:
        if not os.path.isabs(fc_path):
            fc_path = os.path.join(base_dir, os.path.basename(fc_path))
        fc_path = os.path.normpath(fc_path)

    # 解析 portcon 路径
    portcon_path = args.portcon
    if portcon_path:
        if not os.path.isabs(portcon_path):
            portcon_path = os.path.join(base_dir, os.path.basename(portcon_path))
        portcon_path = os.path.normpath(portcon_path)

    # 加载知识库
    print(f"加载知识库...", file=sys.stderr)
    print(f"  Policy: {policy_path or '未指定'}", file=sys.stderr)
    print(f"  FC: {fc_path or '未指定'}", file=sys.stderr)
    print(f"  Portcon: {portcon_path or '未指定'}", file=sys.stderr)

    kb = KnowledgeBase.load(
        policy_path=policy_path,
        fc_path=fc_path,
        portcon_path=portcon_path,
        current_domain=args.source_type,
    )

    # 根据场景创建 syscall 序列
    if args.scenario == "reverse_shell":
        syscalls = create_reverse_shell_syscalls(
            remote_port=args.remote_port,
            remote_ip=args.remote_ip,
        )
        scenario_desc = f"Reverse shell (连接 {args.remote_ip}:{args.remote_port})"
    elif args.scenario == "http_connect":
        syscalls = create_http_connect_syscalls(
            port=args.remote_port,
            ip=args.remote_ip,
        )
        scenario_desc = f"HTTP 连接 (连接 {args.remote_ip}:{args.remote_port})"
    elif args.scenario == "execve":
        if args.exec_path:
            syscalls = create_execve_syscalls(exec_path=args.exec_path)
            scenario_desc = f"Execve (执行 {args.exec_path})"
        else:
            print("错误：execve 场景需要指定 --exec-path", file=sys.stderr)
            sys.exit(1)
    elif args.scenario == "open_read":
        if args.file_path:
            syscalls = create_open_read_syscalls(file_path=args.file_path)
            scenario_desc = f"Open/Read (读取 {args.file_path})"
        else:
            print("错误：open_read 场景需要指定 --file-path", file=sys.stderr)
            sys.exit(1)
    elif args.scenario == "open_write":
        if args.file_path:
            syscalls = create_open_write_syscalls(file_path=args.file_path)
            scenario_desc = f"Open/Write (写入 {args.file_path})"
        else:
            print("错误：open_write 场景需要指定 --file-path", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"未知场景：{args.scenario}", file=sys.stderr)
        sys.exit(1)

    # 打印场景信息
    print("=" * 60)
    print(f"SELinux Syscall Trace Analyzer - {scenario_desc}")
    print(f"Domain: {args.source_type}")
    print("=" * 60)
    print()

    # 运行分析
    trace = run_analysis(
        syscalls=syscalls,
        kb=kb,
        current_domain=args.source_type,
        output_format=args.format,
    )


if __name__ == "__main__":
    main()
