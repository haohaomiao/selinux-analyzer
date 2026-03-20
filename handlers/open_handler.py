"""
handlers/open_handler.py - open/openat syscall 分析器

功能：
分析 open(path, flags, mode) 和 openat(dirfd, path, flags, mode)。

对应 Linux/SELinux 源码逻辑：
============================
syscall: open()
  ↓
LSM hook: security_file_open()
  ↓
SELinux hook: selinux_file_open()
  ↓
具体实现：security/selinux/hooks.c:selinux_file_open()
  - 调用 file_has_perm(file, acc_mode)
  - acc_mode 由 flags 决定 (O_RDONLY -> MAY_READ, etc.)

AVC 四元组构造逻辑：
==================
- source_type: 当前 task 的 domain
- target_type: 打开文件的 type（从 file_contexts 解析）
- class: file
- perm: open + (read/write/append 根据 flags)

简化说明：
========
- 不处理 openat 的 dirfd 参数
- 不处理 O_CREAT 等特殊标志
- 不处理 symlink 跟随
"""

from __future__ import annotations

import os
import sys

# 添加父目录到路径，以便导入
_parent_dir = os.path.dirname(os.path.abspath(__file__))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from models import (
    Syscall,
    AnalysisState,
    AnalysisTrace,
    StepTrace,
    AVCCheck,
    Decision,
)
from knowledge.base import KnowledgeBase, FileKind


# flags 到权限的映射
FLAG_TO_PERMS = {
    "O_RDONLY": ["read"],
    "O_WRONLY": ["write"],
    "O_RDWR": ["read", "write"],
    "O_APPEND": ["append"],
    "O_CREAT": ["create"],
    "O_TRUNC": ["write"],  # truncate 需要 write 权限
    "O_EXCL": [],  # O_EXCL 本身不产生额外权限
}


def parse_open_flags(flags_str: str) -> list[str]:
    """
    解析 open flags 字符串到权限列表。
    
    参数：
    - flags_str: 如 "O_RDONLY" 或 "O_WRONLY|O_APPEND"
    
    返回：
    - 权限列表，如 ["read"] 或 ["write", "append"]
    """
    perms = []
    
    # 处理组合 flags
    parts = flags_str.replace("|", " ").split()
    
    for part in parts:
        part = part.strip()
        if part in FLAG_TO_PERMS:
            perms.extend(FLAG_TO_PERMS[part])
    
    # 去重
    return list(set(perms))


def handle_open(
    syscall: Syscall,
    state: AnalysisState,
    kb: KnowledgeBase
) -> StepTrace:
    """
    处理 open() syscall。

    参数：
    - syscall: Syscall 对象，args 应包含 path, flags, mode
    - state: 当前分析状态
    - kb: 知识库

    返回：
    - StepTrace 对象，包含 AVC 检查结果和状态更新
    """
    checks: list[AVCCheck] = []
    state_updates: list[str] = []

    # =========================================================================
    # 步骤 1: 读取 syscall 参数
    # =========================================================================
    path = syscall.args.get("path", "")
    flags = syscall.args.get("flags", "O_RDONLY")
    mode = syscall.args.get("mode", 0o644)

    # =========================================================================
    # 步骤 2: 解析文件类型
    # 使用 file_contexts 查询
    # =========================================================================
    file_type = kb.resolve_path_type(path, kind_hint=FileKind.FILE)
    
    if not file_type:
        file_type = "unlabeled_t"
        state_updates.append(f"警告：无法从 file_contexts 解析 {path} 的类型，使用 {file_type}")
    else:
        state_updates.append(f"文件 {path} -> {file_type}")

    # =========================================================================
    # 步骤 3: 解析 flags 到权限
    # =========================================================================
    if isinstance(flags, str):
        perms = parse_open_flags(flags)
    else:
        # 如果是数字 flags，简化处理
        perms = ["read"]  # 默认
    
    # 确保至少有 open 权限
    if not perms:
        perms = ["read"]

    # =========================================================================
    # 步骤 4: 构造 AVC 检查
    # 参考：security/selinux/hooks.c:selinux_file_open()
    #   err = file_has_perm(file, acc_mode);
    # =========================================================================
    source_type = state.current_domain
    
    # open 权限总是需要的
    check_open = AVCCheck(
        syscall_index=syscall.index,
        syscall_name="open",
        lsm_hook="security_file_open",
        selinux_hook="selinux_file_open",
        selinux_impl=(
            f"file_has_perm(file, acc_mode) → "
            f"avc_has_perm(current_sid(), file_sid, file, FILE__OPEN)"
        ),
        source_type=source_type,
        target_type=file_type,
        tclass="file",
        perm="open",
        rationale=(
            f"open({path}) 需要检查文件的 open 权限。"
            f"根据 selinux_file_open() 实现，"
            f"需要检查当前 domain ({source_type}) 是否有权限打开 {file_type} 类型的文件。"
            f"四元组：({source_type}, {file_type}, file, open)"
        ),
    )

    check_open.result = kb.is_allowed(source_type, file_type, "file", "open")
    checks.append(check_open)

    # 为每个解析出的权限添加检查
    for perm in perms:
        check = AVCCheck(
            syscall_index=syscall.index,
            syscall_name="open",
            lsm_hook="security_file_open",
            selinux_hook="selinux_file_open",
            selinux_impl=(
                f"file_has_perm(file, MAY_{perm.upper()}) → "
                f"avc_has_perm(current_sid(), file_sid, file, FILE__{perm.upper()})"
            ),
            source_type=source_type,
            target_type=file_type,
            tclass="file",
            perm=perm,
            rationale=(
                f"open({path}) flags={flags} 需要 {perm} 权限。"
                f"四元组：({source_type}, {file_type}, file, {perm})"
            ),
        )

        check.result = kb.is_allowed(source_type, file_type, "file", perm)
        checks.append(check)

    # =========================================================================
    # 步骤 5: 更新状态（fd 映射）
    # =========================================================================
    if syscall.ret is not None:
        object_id = f"file_{syscall.index}_{syscall.ret}"
        state.fd_table[syscall.ret] = object_id
        state_updates.append(f"fd {syscall.ret} → {object_id} ({path})")

    # =========================================================================
    # 步骤 6: 生成 StepTrace
    # =========================================================================
    denied_checks = [c for c in checks if c.result and not c.result.allowed]

    if denied_checks:
        denied = denied_checks[0]
        summary = (
            f"open({path}) 被拒绝：{denied.target_type}:{denied.tclass} {denied.perm} "
            f"denied for {denied.source_type}"
        )
    else:
        summary = f"open({path}) 允许 (flags={flags})"

    return StepTrace(
        syscall=syscall,
        checks=checks,
        state_updates=state_updates,
        summary=summary,
    )


def handle_read(
    syscall: Syscall,
    state: AnalysisState,
    kb: KnowledgeBase
) -> StepTrace:
    """
    处理 read() syscall。

    参数：
    - syscall: Syscall 对象，args 应包含 fd, buf, count
    - state: 当前分析状态
    - kb: 知识库

    返回：
    - StepTrace 对象，包含 AVC 检查结果
    """
    checks: list[AVCCheck] = []
    state_updates: list[str] = []

    # =========================================================================
    # 步骤 1: 读取 syscall 参数
    # =========================================================================
    fd = syscall.args.get("fd")
    count = syscall.args.get("count", 0)

    # =========================================================================
    # 步骤 2: 从 fd_table 找到对应的对象
    # =========================================================================
    if fd is None or fd not in state.fd_table:
        return StepTrace(
            syscall=syscall,
            checks=[],
            state_updates=[],
            summary=f"read() 失败：fd {fd} 不存在于 fd_table 中",
        )

    object_id = state.fd_table[fd]
    state_updates.append(f"read fd {fd} ({object_id}), count={count}")

    # read() 本身不触发新的 AVC 检查，权限在 open() 时已检查
    # 这里只记录状态更新

    return StepTrace(
        syscall=syscall,
        checks=[],  # read 不触发新的 AVC 检查
        state_updates=state_updates,
        summary=f"read(fd={fd}, count={count}) - 权限在 open() 时已检查",
    )


def handle_write(
    syscall: Syscall,
    state: AnalysisState,
    kb: KnowledgeBase
) -> StepTrace:
    """
    处理 write() syscall。

    参数：
    - syscall: Syscall 对象，args 应包含 fd, buf, count
    - state: 当前分析状态
    - kb: 知识库

    返回：
    - StepTrace 对象，包含 AVC 检查结果
    """
    checks: list[AVCCheck] = []
    state_updates: list[str] = []

    # =========================================================================
    # 步骤 1: 读取 syscall 参数
    # =========================================================================
    fd = syscall.args.get("fd")
    count = syscall.args.get("count", 0)
    buf = syscall.args.get("buf", "")

    # =========================================================================
    # 步骤 2: 从 fd_table 找到对应的对象
    # =========================================================================
    if fd is None or fd not in state.fd_table:
        return StepTrace(
            syscall=syscall,
            checks=[],
            state_updates=[],
            summary=f"write() 失败：fd {fd} 不存在于 fd_table 中",
        )

    object_id = state.fd_table[fd]
    state_updates.append(f"write fd {fd} ({object_id}), count={count}")

    # write() 本身不触发新的 AVC 检查，权限在 open() 时已检查

    return StepTrace(
        syscall=syscall,
        checks=[],  # write 不触发新的 AVC 检查
        state_updates=state_updates,
        summary=f"write(fd={fd}, count={count}) - 权限在 open() 时已检查",
    )
