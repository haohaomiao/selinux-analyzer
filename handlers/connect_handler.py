"""
handlers/connect_handler.py - connect syscall 分析器

功能：
分析 connect(fd, sockaddr, addrlen)。

对应 Linux/SELinux 源码逻辑：
============================
syscall: connect()
  ↓
LSM hook: security_socket_connect()
  ↓
SELinux hook: selinux_socket_connect()
  ↓
具体实现：security/selinux/hooks.c:selinux_socket_connect()
  → selinux_socket_connect_helper()
    1. sock_has_perm(sk, SOCKET__CONNECT)
       → avc_has_perm(current_sid(), sksec->sid, sksec->sclass, SOCKET__CONNECT)
    2. 对于 TCP/SCTP socket，检查 name_connect:
       - sel_netport_sid(protocol, port, &sid) 获取端口 type
       - avc_has_perm(sksec->sid, sid, sksec->sclass, NAME_CONNECT)

AVC 四元组构造逻辑：
==================
Check 1 - Socket connect:
- source_type: 当前 task 的 domain
- target_type: socket 对象的 sid（简化：与创建 domain 相同）
- class: socket 的 class（tcp_socket, udp_socket 等）
- perm: "connect"

Check 2 - Port name_connect (仅 TCP/SCTP):
- source_type: 当前 task 的 domain
- target_type: 端口的 type（从 knowledge.resolve_port_type() 获取）
- class: socket 的 class
- perm: "name_connect"

简化说明：
========
- socket 的 target_type 简化为 created_by_domain
  真实内核中 sksec->sid 可能因 policy 而不同
- 不处理 NetLabel / selinux_netlbl_socket_connect()
- 不处理 AF_UNSPEC 断开连接的特殊情况
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


def handle_connect(
    syscall: Syscall,
    state: AnalysisState,
    kb: KnowledgeBase
) -> StepTrace:
    """
    处理 connect() syscall。
    
    参数：
    - syscall: Syscall 对象，args 应包含 fd, ip, port
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
    fd = syscall.args.get("fd")
    ip = syscall.args.get("ip", "0.0.0.0")
    port = syscall.args.get("port", 0)
    
    # =========================================================================
    # 步骤 2: 从 fd_table 找到对应的 SocketObject
    # =========================================================================
    if fd is None or fd not in state.fd_table:
        # fd 不存在，无法分析
        return StepTrace(
            syscall=syscall,
            checks=[],
            state_updates=[],
            summary=f"connect() 失败：fd {fd} 不存在于 fd_table 中",
        )
    
    object_id = state.fd_table[fd]
    socket_obj = state.objects.get(object_id)
    
    if socket_obj is None or not isinstance(socket_obj, SocketObject):
        return StepTrace(
            syscall=syscall,
            checks=[],
            state_updates=[],
            summary=f"connect() 失败：fd {fd} 对应的对象 {object_id} 不是 SocketObject",
        )
    
    # =========================================================================
    # 步骤 3: Check 1 - Socket connect 权限检查
    # 参考：security/selinux/hooks.c:selinux_socket_connect_helper()
    #   err = sock_has_perm(sk, SOCKET__CONNECT);
    # 参考：sock_has_perm():
    #   avc_has_perm(current_sid(), sksec->sid, sksec->sclass, perms)
    # =========================================================================
    source_type = state.current_domain
    # 简化：socket 的 target_type 使用 created_by_domain
    # 真实内核中 sksec->sid 存储在 socket 的安全结构中
    target_type = socket_obj.created_by_domain or source_type
    tclass = socket_obj.selinux_class
    perm_connect = "connect"
    
    check_connect = AVCCheck(
        syscall_index=syscall.index,
        syscall_name="connect",
        lsm_hook="security_socket_connect",
        selinux_hook="selinux_socket_connect_helper",
        selinux_impl=(
            f"sock_has_perm(sk, SOCKET__CONNECT) → "
            f"avc_has_perm(current_sid(), sksec->sid, {tclass}, SOCKET__CONNECT)"
        ),
        source_type=source_type,
        target_type=target_type,
        tclass=tclass,
        perm=perm_connect,
        rationale=(
            f"connect() 需要检查 socket 的 connect 权限。"
            f"根据 selinux_socket_connect_helper() 实现，"
            f"调用 sock_has_perm() 检查当前 domain 对 socket 的 connect 权限。"
            f"四元组：({source_type}, {target_type}, {tclass}, {perm_connect})"
        ),
    )
    
    check_connect.result = kb.is_allowed(source_type, target_type, tclass, perm_connect)
    checks.append(check_connect)
    
    # =========================================================================
    # 步骤 4: Check 2 - Port name_connect (仅 TCP/SCTP)
    # 参考：security/selinux/hooks.c:selinux_socket_connect_helper()
    #   if (sksec->sclass == SECCLASS_TCP_SOCKET ||
    #       sksec->sclass == SECCLASS_SCTP_SOCKET) {
    #       sel_netport_sid(sk->sk_protocol, snum, &sid);
    #       avc_has_perm(sksec->sid, sid, sksec->sclass, perm);
    #   }
    # =========================================================================
    if tclass in ("tcp_socket", "sctp_socket"):
        # 解析端口类型
        port_type = kb.resolve_port_type(socket_obj.protocol, port)
        if port_type is None:
            port_type = "unlabeled_t"  # 未找到端口类型时的默认值
        perm_name_connect = "name_connect"
        
        check_name_connect = AVCCheck(
            syscall_index=syscall.index,
            syscall_name="connect",
            lsm_hook="security_socket_connect",
            selinux_hook="selinux_socket_connect_helper",
            selinux_impl=(
                f"TCP/SCTP socket 需要 name_connect 检查："
                f"sel_netport_sid({socket_obj.protocol}, {port}) → {port_type}; "
                f"avc_has_perm(sksec->sid, {port_type}, {tclass}, {perm_name_connect})"
            ),
            source_type=source_type,
            target_type=port_type,
            tclass=tclass,
            perm=perm_name_connect,
            rationale=(
                f"connect() 到 {ip}:{port} ({socket_obj.protocol.upper()})。"
                f"根据 selinux_socket_connect_helper() 实现，"
                f"TCP/SCTP socket 需要额外检查端口的 name_connect 权限。"
                f"端口 {port} 解析为 type: {port_type}。"
                f"四元组：({source_type}, {port_type}, {tclass}, {perm_name_connect})"
            ),
        )
        
        check_name_connect.result = kb.is_allowed(
            source_type, port_type, tclass, perm_name_connect
        )
        checks.append(check_name_connect)
        
        state_updates.append(f"目标：{ip}:{port} ({port_type})")
    
    # =========================================================================
    # 步骤 5: 生成 StepTrace
    # =========================================================================
    # 检查是否有被拒绝的 check
    denied_checks = [c for c in checks if c.result and not c.result.allowed]
    
    if denied_checks:
        denied = denied_checks[0]
        summary = (
            f"connect() 被拒绝：{denied.target_type}:{denied.tclass} {denied.perm} "
            f" denied for {denied.source_type}"
        )
    else:
        summary = f"connect() 到 {ip}:{port} 允许"
    
    return StepTrace(
        syscall=syscall,
        checks=checks,
        state_updates=state_updates,
        summary=summary,
    )
