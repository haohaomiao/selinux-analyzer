"""
handlers/dup2_handler.py - dup2 syscall 分析器

功能：
分析 dup2(oldfd, newfd)。

对应 Linux/SELinux 源码逻辑：
============================
syscall: dup2()
  ↓
LSM hook: 无直接对应的 SELinux hook
  
说明：
=====
dup2()  syscall  用于复制文件描述符，在内核中主要是 fd 表操作。
根据 Linux 内核实现，dup2() 不触发 SELinux AVC 检查，因为：
1. 它不创建新对象，只是增加现有对象的引用计数
2. 它不改变访问权限，新 fd 继承原 fd 的权限
3. SELinux 检查点在 open()/socket() 等创建对象时已完成

参考：security/selinux/hooks.c
- 没有 selinux_dup2() 这样的 hook 实现
- LSM hook 列表中没有 dup2 相关的 hook

状态更新：
========
- newfd 指向与 oldfd 相同的 object
- 更新 fd_table[newfd] = fd_table[oldfd]

简化说明：
========
- 不处理 oldfd 无效的情况（真实内核会返回 EBADF）
- 不处理 newfd == oldfd 的特殊情况
- 不记录详细的引用计数变化（分析器不需要）
"""

from __future__ import annotations

from ..models import (
    Syscall,
    AnalysisState,
    AnalysisTrace,
    StepTrace,
    AVCCheck,
    Decision,
)
from ..knowledge.base import KnowledgeBase


def handle_dup2(
    syscall: Syscall,
    state: AnalysisState,
    kb: KnowledgeBase
) -> StepTrace:
    """
    处理 dup2() syscall。
    
    参数：
    - syscall: Syscall 对象，args 应包含 oldfd, newfd
    - state: 当前分析状态
    - kb: 知识库
    
    返回：
    - StepTrace 对象，包含状态更新（无 AVC 检查）
    """
    state_updates: list[str] = []
    
    # =========================================================================
    # 步骤 1: 读取 syscall 参数
    # =========================================================================
    oldfd = syscall.args.get("oldfd")
    newfd = syscall.args.get("newfd")
    
    # =========================================================================
    # 步骤 2: 验证 oldfd 是否存在
    # =========================================================================
    if oldfd is None or oldfd not in state.fd_table:
        return StepTrace(
            syscall=syscall,
            checks=[],
            state_updates=[],
            summary=f"dup2() 失败：oldfd {oldfd} 不存在",
        )
    
    # =========================================================================
    # 步骤 3: 更新 fd 映射
    # dup2() 使 newfd 指向与 oldfd 相同的对象
    # =========================================================================
    object_id = state.fd_table[oldfd]
    
    # 更新 fd_table
    state.fd_table[newfd] = object_id
    state_updates.append(f"fd {newfd} → {object_id} (dup from fd {oldfd})")
    
    # =========================================================================
    # 步骤 4: 生成 StepTrace
    # dup2() 不触发 AVC 检查
    # =========================================================================
    summary = f"dup2({oldfd}, {newfd}) - fd 重映射，无 SELinux 检查"
    
    return StepTrace(
        syscall=syscall,
        checks=[],  # 无 AVC 检查
        state_updates=state_updates,
        summary=summary,
    )
