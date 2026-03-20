"""
models.py - 核心数据结构定义

本模块定义所有核心数据类型，确保模块之间使用统一对象，
而不是杂乱 dict。不做业务逻辑，仅定义数据结构。
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Literal


# =============================================================================
# A. Syscall - 表示一个 syscall 实例
# =============================================================================

@dataclass
class Syscall:
    """
    表示一个 syscall 实例。
    
    示例：
        Syscall(
            name="socket",
            args={"family": "AF_INET", "type": "SOCK_STREAM", "protocol": 0},
            ret=3,
            index=0,
        )
    """
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    ret: Any | None = None  # 例如 socket() 返回的 fd
    index: int = 0  # syscall 在序列中的位置
    raw: dict | None = None  # 可选，保留原始输入


# =============================================================================
# B. AnalysisObject - 分析对象基类
# =============================================================================

@dataclass
class AnalysisObject:
    """
    分析对象的抽象基类。
    用于表示 syscall 操作的各种内核对象（socket、file 等）。
    """
    id: str
    kind: str  # 对象类型，如 "socket"、"file" 等


# =============================================================================
# C. SocketObject - Socket 对象
# =============================================================================

@dataclass
class SocketObject(AnalysisObject):
    """
    Socket 对象，当前第一版最重要的对象。
    
    字段说明：
    - protocol 应归一化成 "tcp" / "udp" / "raw" 等
    - selinux_class 是分析阶段直接使用的 class，例如 tcp_socket
    """
    kind: Literal["socket"] = "socket"
    family: str = "AF_INET"
    sock_type: str = "SOCK_STREAM"
    protocol: str = "tcp"  # 归一化后的协议
    selinux_class: str = "tcp_socket"  # SELinux socket class
    created_by_domain: str | None = None  # 创建该 socket 的 domain


# =============================================================================
# D. AnalysisState - 最小符号状态
# =============================================================================

@dataclass
class AnalysisState:
    """
    最小符号状态。
    
    只维护那些：
    - 当前 syscall 无法单独知道；
    - 但后续 syscall 的 SELinux 检查确实依赖的信息。
    
    第一版字段：
    - current_domain: 当前主体 type
    - fd_table: fd -> object_id 映射
    - objects: 对象表
    """
    current_domain: str = "unconfined_t"
    fd_table: dict[int, str] = field(default_factory=dict)  # fd -> object_id
    objects: dict[str, AnalysisObject] = field(default_factory=dict)  # object_id -> AnalysisObject


# =============================================================================
# E. Decision - SELinux 策略判定结果
# =============================================================================

@dataclass
class Decision:
    """
    表示一次 SELinux policy 判定结果。
    
    字段说明：
    - allowed: 是否允许
    - matched_rules: 匹配的规则列表（第一版可留空或简单字符串化）
    - reason: 判定原因说明
    """
    allowed: bool
    matched_rules: list[str] = field(default_factory=list)
    reason: str = ""


# =============================================================================
# F. AVCCheck - SELinux 权限检查
# =============================================================================

@dataclass
class AVCCheck:
    """
    表示一次具体 SELinux 权限检查。
    
    AVC 四元组：(source_type, target_type, class, perm)
    
    字段说明：
    - syscall_index: syscall 在序列中的索引
    - syscall_name: syscall 名称
    - lsm_hook: LSM hook 名称
    - selinux_hook: SELinux hook 名称
    - selinux_impl: SELinux 实现逻辑描述
    - source_type: 源类型（通常是当前 domain）
    - target_type: 目标类型
    - tclass: 目标 class
    - perm: 权限
    - rationale: 说明该四元组为何这样构造
    - result: 判定结果
    """
    syscall_index: int
    syscall_name: str
    source_type: str
    target_type: str
    tclass: str
    perm: str
    lsm_hook: str | None = None
    selinux_hook: str | None = None
    selinux_impl: str | None = None
    rationale: str = ""
    result: Decision | None = None


# =============================================================================
# G. StepTrace - 单个 syscall 的分析结果
# =============================================================================

@dataclass
class StepTrace:
    """
    表示一个 syscall 的分析结果。
    
    字段说明：
    - syscall: 被分析的 syscall
    - checks: 触发的 AVC 检查列表
    - state_updates: 状态更新描述列表
    - summary: 该步骤的摘要
    """
    syscall: Syscall
    checks: list[AVCCheck] = field(default_factory=list)
    state_updates: list[str] = field(default_factory=list)
    summary: str = ""


# =============================================================================
# H. AnalysisTrace - 整条 syscall 序列的分析结果
# =============================================================================

@dataclass
class AnalysisTrace:
    """
    表示整条 syscall 序列分析结果。
    
    字段说明：
    - steps: 每个 syscall 的 StepTrace
    - final_summary: 整体分析摘要
    """
    steps: list[StepTrace] = field(default_factory=list)
    final_summary: str = ""
