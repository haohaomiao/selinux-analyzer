"""
handlers/socket_handler.py - socket syscall 分析器

功能：
分析 socket(domain, type, protocol)。

对应 Linux/SELinux 源码逻辑：
============================
syscall: socket()
  ↓
LSM hook: security_socket_create()
  ↓
SELinux hook: selinux_socket_create()
  ↓
具体实现：security/selinux/hooks.c:selinux_socket_create()
  - 调用 socket_type_to_security_class(family, type, protocol) 确定 class
  - 调用 socket_sockcreate_sid() 确定 target sid
  - 调用 avc_has_perm(crsec->sid, newsid, secclass, SOCKET__CREATE, NULL)

AVC 四元组构造逻辑：
==================
- source_type: 当前 task 的 domain（从 state.current_domain 获取）
- target_type: socket 创建后的 target type（简化：与 source_type 相同）
- class: 由 family/type/protocol 决定（如 tcp_socket, udp_socket）
- perm: "create"

状态更新：
========
- 新建 SocketObject
- 将 syscall 返回的 fd 映射到该对象

简化说明：
========
- target_type 简化为与 source_type 相同
  真实内核中，socket_sockcreate_sid() 可能根据 policy 进行 type transition
- 不处理 kern=1 的内核 socket 创建
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
    SocketObject,
)
from knowledge.base import KnowledgeBase


def handle_socket(
    syscall: Syscall,
    state: AnalysisState,
    kb: KnowledgeBase
) -> StepTrace:
    """
    处理 socket() syscall。
    
    参数：
    - syscall: Syscall 对象，args 应包含 family, type, protocol
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
    family = syscall.args.get("family", "AF_INET")
    sock_type = syscall.args.get("type", "SOCK_STREAM")
    protocol = syscall.args.get("protocol", 0)
    
    # =========================================================================
    # 步骤 2: 确定 SELinux socket class 和协议
    # 参考：security/selinux/hooks.c:socket_type_to_security_class()
    # =========================================================================
    selinux_class, proto_str = kb.resolve_socket_class(family, sock_type, protocol)
    
    # =========================================================================
    # 步骤 3: 构造 AVC 四元组
    # 参考：security/selinux/hooks.c:selinux_socket_create()
    #   avc_has_perm(crsec->sid, newsid, secclass, SOCKET__CREATE, NULL)
    # =========================================================================
    source_type = state.current_domain
    # 简化：target_type 与 source_type 相同
    # 真实内核中 socket_sockcreate_sid() 可能根据 policy 进行 type transition
    target_type = source_type
    perm = "create"
    
    # 构造 AVC 检查
    check = AVCCheck(
        syscall_index=syscall.index,
        syscall_name="socket",
        lsm_hook="security_socket_create",
        selinux_hook="selinux_socket_create",
        selinux_impl=(
            f"socket_type_to_security_class({family}, {sock_type}, {protocol}) → {selinux_class}; "
            f"avc_has_perm(source, target, {selinux_class}, SOCKET__CREATE)"
        ),
        source_type=source_type,
        target_type=target_type,
        tclass=selinux_class,
        perm=perm,
        rationale=(
            f"socket() 创建新的 socket。"
            f"根据 Linux 内核 selinux_socket_create() 实现，"
            f"需要检查当前 domain ({source_type}) 是否有权限创建 {selinux_class} 类型的 socket。"
            f"四元组：({source_type}, {target_type}, {selinux_class}, {perm})"
        ),
    )
    
    # =========================================================================
    # 步骤 4: 查询 policy
    # =========================================================================
    check.result = kb.is_allowed(source_type, target_type, selinux_class, perm)
    checks.append(check)
    
    # =========================================================================
    # 步骤 5: 创建 SocketObject 并更新状态
    # 参考：security/selinux/hooks.c:selinux_socket_post_create()
    # =========================================================================
    # 生成唯一的 object_id
    object_id = f"socket_{syscall.index}_{syscall.ret if syscall.ret is not None else 'new'}"
    
    socket_obj = SocketObject(
        id=object_id,
        family=family,
        sock_type=sock_type,
        protocol=proto_str,
        selinux_class=selinux_class,
        created_by_domain=source_type,
    )
    
    # 更新状态
    state.objects[object_id] = socket_obj
    
    # 如果 syscall 有返回值（fd），建立 fd 映射
    if syscall.ret is not None:
        state.fd_table[syscall.ret] = object_id
        state_updates.append(f"fd {syscall.ret} → {object_id} ({selinux_class})")
    
    state_updates.append(f"创建对象：{object_id}")
    
    # =========================================================================
    # 步骤 6: 生成 StepTrace
    # =========================================================================
    allowed = check.result.allowed if check.result else False
    summary = (
        f"socket() 创建 {selinux_class} {'允许' if allowed else '拒绝'}"
        f" (fd={syscall.ret if syscall.ret is not None else 'N/A'})"
    )
    
    return StepTrace(
        syscall=syscall,
        checks=checks,
        state_updates=state_updates,
        summary=summary,
    )
