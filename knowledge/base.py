"""
knowledge/base.py - 安全知识访问层

本模块封装所有来自外部文件的安全知识访问逻辑，向 handler 提供统一查询接口。
该模块不负责 syscall 语义，仅负责回答：
- 某端口是什么 type
- 某路径是什么 type
- 某四元组是否允许

第一版实现简化版本：
- 不依赖外部 policy 文件
- 使用内置的简化规则表进行演示
- 所有简化都通过注释显式说明
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import re

from ..models import Decision


# =============================================================================
# 简化规则：端口类型映射表
# =============================================================================

# 常见端口类型映射（简化版，用于演示）
# 真实实现应从 policy / port_context 文件中解析
PORT_TYPE_MAP: dict[tuple[str, int], str] = {
    # TCP 端口
    ("tcp", 80): "http_port_t",
    ("tcp", 443): "https_port_t",
    ("tcp", 22): "ssh_port_t",
    ("tcp", 25): "smtp_port_t",
    ("tcp", 53): "dns_port_t",
    ("tcp", 110): "pop_port_t",
    ("tcp", 143): "imap_port_t",
    ("tcp", 3306): "mysqld_port_t",
    ("tcp", 5432): "postgresql_port_t",
    ("tcp", 6379): "redis_port_t",
    ("tcp", 8080): "http_cache_port_t",
    ("tcp", 8443): "https_port_t",
    # UDP 端口
    ("udp", 53): "dns_port_t",
    ("udp", 67): "dhcpc_port_t",
    ("udp", 68): "dhcpc_port_t",
    ("udp", 123): "ntp_port_t",
}

# 默认端口类型（当端口不在映射表中时使用）
# 简化说明：真实 SELinux 策略中，未保留端口通常映射到 unreserved_port_t
DEFAULT_PORT_TYPE = "unreserved_port_t"


# =============================================================================
# 简化规则：策略允许规则表
# =============================================================================

# 简化的 allow 规则
# 格式：(source_type, target_type, tclass, perm) -> allowed
# 真实实现应使用 setools 查询真实 policy
ALLOW_RULES: set[tuple[str, str, str, str]] = {
    # === Socket 创建相关 ===
    # httpd_t 可以创建 tcp_socket
    ("httpd_t", "httpd_t", "tcp_socket", "create"),
    ("httpd_t", "httpd_t", "udp_socket", "create"),
    ("unconfined_t", "unconfined_t", "tcp_socket", "create"),
    ("unconfined_t", "unconfined_t", "udp_socket", "create"),
    
    # === Socket 连接相关 ===
    # httpd_t 可以对 tcp_socket 进行 connect
    ("httpd_t", "httpd_t", "tcp_socket", "connect"),
    ("httpd_t", "httpd_t", "udp_socket", "connect"),
    ("unconfined_t", "unconfined_t", "tcp_socket", "connect"),
    
    # === 端口 name_connect 相关 ===
    # httpd_t 可以连接 http/https 端口
    ("httpd_t", "http_port_t", "tcp_socket", "name_connect"),
    ("httpd_t", "https_port_t", "tcp_socket", "name_connect"),
    ("httpd_t", "http_cache_port_t", "tcp_socket", "name_connect"),
    
    # unconfined_t 几乎可以连接任何端口（简化）
    ("unconfined_t", "unreserved_port_t", "tcp_socket", "name_connect"),
    ("unconfined_t", "http_port_t", "tcp_socket", "name_connect"),
    ("unconfined_t", "https_port_t", "tcp_socket", "name_connect"),
    ("unconfined_t", "ssh_port_t", "tcp_socket", "name_connect"),
}


@dataclass
class KnowledgeBase:
    """
    安全知识库。
    
    启动时加载 policy / fc / port 数据（第一版使用内置简化规则），
    对外暴露统一查询 API。
    
    简化说明：
    - 第一版不解析真实 policy 文件，使用内置规则表
    - 这是为了快速验证分析器架构
    - 真实实现应使用 setools / policy 解析工具
    """
    
    # 当前 domain（可选，用于某些查询的上下文）
    current_domain: str = "unconfined_t"
    
    # 自定义规则（允许运行时添加）
    custom_rules: set[tuple[str, str, str, str]] = field(default_factory=set)
    
    # 自定义端口映射
    custom_port_map: dict[tuple[str, int], str] = field(default_factory=dict)
    
    def is_allowed(
        self,
        source_type: str,
        target_type: str,
        tclass: str,
        perm: str
    ) -> Decision:
        """
        查询 policy 中是否存在允许该四元组的规则。
        
        参数：
        - source_type: 源类型（通常是当前 domain）
        - target_type: 目标类型
        - tclass: 目标 class
        - perm: 权限
        
        返回：
        - Decision 对象，包含 allowed 字段和原因说明
        
        简化说明：
        - 第一版只查 allow 规则，不做复杂 constraint 判定
        - 不区分 allow 和 allowxperm
        - 不处理 type_transition / type_change
        """
        # 构建查询键
        query = (source_type, target_type, tclass, perm)
        
        # 检查是否在允许规则中
        # 优先级：自定义规则 > 内置规则
        if query in self.custom_rules:
            return Decision(
                allowed=True,
                matched_rules=[str(query)],
                reason=f"Matched custom rule: {source_type} -> {target_type}:{tclass} {perm}"
            )
        
        if query in ALLOW_RULES:
            return Decision(
                allowed=True,
                matched_rules=[str(query)],
                reason=f"Matched built-in rule: {source_type} -> {target_type}:{tclass} {perm}"
            )
        
        # 未找到允许规则，默认拒绝
        return Decision(
            allowed=False,
            matched_rules=[],
            reason=f"No allow rule found for {source_type} -> {target_type}:{tclass} {perm}"
        )
    
    def resolve_port_type(self, proto: str, port: int) -> str:
        """
        根据协议和端口号，解析端口对应的 SELinux target type。
        
        参数：
        - proto: "tcp" / "udp"
        - port: 端口号（整数）
        
        返回：
        - 例如 "http_port_t" / "unreserved_port_t"
        
        简化说明：
        - 第一版使用内置端口映射表，不从 policy 解析
        - 未映射的端口返回 DEFAULT_PORT_TYPE
        - 真实实现应查询 policy 中的 port_context
        """
        # 优先级：自定义映射 > 内置映射 > 默认
        key = (proto.lower(), port)
        
        if key in self.custom_port_map:
            return self.custom_port_map[key]
        
        if key in PORT_TYPE_MAP:
            return PORT_TYPE_MAP[key]
        
        # 返回默认端口类型
        return DEFAULT_PORT_TYPE
    
    def resolve_path_type(self, path: str) -> str:
        """
        解析路径在 file_contexts 中对应的 type。
        
        参数：
        - path: 文件路径
        
        返回：
        - 例如 "shell_exec_t" / "httpd_exec_t"
        
        简化说明：
        - 第一版仅实现简单的前缀匹配
        - 真实实现应解析 file_contexts 并使用正则匹配
        - 未匹配的路径返回 default_t
        """
        # 简化的路径类型映射（用于演示）
        PATH_TYPE_MAP = {
            "/bin/": "bin_t",
            "/usr/bin/": "bin_t",
            "/sbin/": "sbin_t",
            "/usr/sbin/": "sbin_t",
            "/etc/": "etc_t",
            "/var/log/": "var_log_t",
            "/tmp/": "tmp_t",
            "/home/": "user_home_t",
            "/root/": "admin_home_t",
            "/var/www/": "httpd_sys_content_t",
            "/usr/share/httpd/": "httpd_sys_content_t",
        }
        
        # 简单前缀匹配
        for prefix, type_label in PATH_TYPE_MAP.items():
            if path.startswith(prefix):
                return type_label
        
        # 默认类型
        return "default_t"
    
    def resolve_socket_class(
        self,
        family: str,
        sock_type: str,
        protocol: str | int = 0
    ) -> tuple[str, str]:
        """
        把 socket 参数归一化成 SELinux class 和协议字符串。
        
        参数：
        - family: 地址族，如 "AF_INET"
        - sock_type: socket 类型，如 "SOCK_STREAM"
        - protocol: 协议号或名称
        
        返回：
        - (selinux_class, protocol_str)
        - 例如 ("tcp_socket", "tcp")
        
        简化说明：
        - 基于 Linux 内核 socket_type_to_security_class() 逻辑简化
        - 只处理常见组合，未识别的返回 generic_socket
        """
        # 协议号到名称的映射（简化版）
        PROTO_MAP = {
            0: "tcp",  # 0 通常表示默认，对于 SOCK_STREAM 是 TCP
            6: "tcp",
            17: "udp",
            132: "sctp",
        }
        
        # 处理协议号
        if isinstance(protocol, int):
            proto_str = PROTO_MAP.get(protocol, "unknown")
        else:
            proto_str = protocol.lower()
        
        # 根据 family + type + protocol 确定 SELinux class
        # 参考 Linux 内核 socket_type_to_security_class() 实现
        
        if family == "AF_INET" or family == "AF_INET6":
            if sock_type == "SOCK_STREAM":
                if proto_str == "tcp" or protocol == 6:
                    return "tcp_socket", "tcp"
                elif proto_str == "sctp" or protocol == 132:
                    return "sctp_socket", "sctp"
            elif sock_type == "SOCK_DGRAM":
                if proto_str == "udp" or protocol == 17:
                    return "udp_socket", "udp"
            elif sock_type == "SOCK_RAW":
                return "rawip_socket", "raw"
        
        # 默认/未知情况
        return "socket", proto_str if proto_str != "unknown" else "unknown"
    
    def add_custom_rule(
        self,
        source_type: str,
        target_type: str,
        tclass: str,
        perm: str
    ) -> None:
        """
        添加自定义规则（用于测试或覆盖）。
        """
        self.custom_rules.add((source_type, target_type, tclass, perm))
    
    def add_custom_port_mapping(self, proto: str, port: int, type_label: str) -> None:
        """
        添加自定义端口映射（用于测试或覆盖）。
        """
        self.custom_port_map[(proto.lower(), port)] = type_label
