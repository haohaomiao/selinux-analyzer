"""
knowledge/base.py - 安全知识访问层

本模块封装所有来自外部文件的安全知识访问逻辑，向 handler 提供统一查询接口。
该模块不负责 syscall 语义，仅负责回答：
- 某端口是什么 type
- 某路径是什么 type
- 某四元组是否允许

实现说明：
- 使用 setools 查询真实 SELinux policy
- 内建 file_contexts 解析器查询路径类型
- 解析 portcon 文件查询端口类型
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import re
import os

from models import Decision


# =============================================================================
# FileKind 枚举
# =============================================================================

class FileKind:
    """文件类型枚举"""
    ANY = "any"
    FILE = "file"
    DIR = "dir"
    LINK = "link"
    SOCK = "sock"
    FIFO = "fifo"
    BLK = "blk"
    CHR = "chr"


# file_contexts flags -> FileKind
_FLAG_TO_KIND = {
    "-f": FileKind.FILE,
    "--": FileKind.FILE,
    "-d": FileKind.DIR,
    "-l": FileKind.LINK,
    "-s": FileKind.SOCK,
    "-p": FileKind.FIFO,
    "-b": FileKind.BLK,
    "-c": FileKind.CHR,
}


# =============================================================================
# FileContexts 解析器
# =============================================================================

@dataclass(frozen=True)
class FCRule:
    """file_contexts 规则"""
    order: int
    regex_raw: str
    regex: re.Pattern
    kind: str
    context: str
    sel_type: str
    literal_prefix_len: int

    def matches(self, path: str, kind_hint: str) -> bool:
        if self.kind != FileKind.ANY and kind_hint != FileKind.ANY and self.kind != kind_hint:
            return False
        return self.regex.match(path) is not None


class FileContexts:
    """
    解析和查询 file_contexts 文件。
    """

    def __init__(self, rules: list[FCRule]):
        self._rules = rules

    @staticmethod
    def load(fc_path: str, encoding: str = "utf-8") -> "FileContexts":
        """从文件加载 file_contexts"""
        rules: list[FCRule] = []
        order = 0

        with open(fc_path, "r", encoding=encoding, errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue

                # 移除行内注释
                if "#" in line:
                    line = line.split("#", 1)[0].strip()

                parts = line.split()
                if len(parts) < 2:
                    continue

                regex_raw = parts[0]
                flag = None
                ctx = None

                if len(parts) >= 3 and (parts[1].startswith("-") or parts[1] == "--"):
                    flag = parts[1]
                    ctx = parts[2]
                else:
                    ctx = parts[1]

                # 解析 type
                if ctx == "<<none>>":
                    continue
                ctx_fields = ctx.split(":")
                if len(ctx_fields) < 3:
                    continue
                sel_type = ctx_fields[2]

                kind = FileKind.ANY
                if flag:
                    kind = _FLAG_TO_KIND.get(flag, FileKind.ANY)

                # 编译正则（添加锚点）
                anchored = f"^{regex_raw}$"
                try:
                    comp = re.compile(anchored)
                except re.error:
                    continue

                # 计算字面前缀长度（用于特异性排序）
                lp = 0
                escaped = False
                for ch in regex_raw:
                    if escaped:
                        lp += 1
                        escaped = False
                        continue
                    if ch == "\\":
                        escaped = True
                        continue
                    if ch in ".^$*+?{}[]\\|()":
                        break
                    lp += 1

                rules.append(
                    FCRule(
                        order=order,
                        regex_raw=regex_raw,
                        regex=comp,
                        kind=kind,
                        context=ctx,
                        sel_type=sel_type,
                        literal_prefix_len=lp,
                    )
                )
                order += 1

        return FileContexts(rules)

    def lookup(self, path: str, kind_hint: str = FileKind.ANY) -> FCRule | None:
        """查找最佳匹配规则"""
        best: FCRule | None = None
        best_key = None

        for r in self._rules:
            if not r.matches(path, kind_hint):
                continue

            # 特异性排序：字面前缀越长越优先，正则越长越优先，顺序越小越优先
            key = (r.literal_prefix_len, len(r.regex_raw), -r.order)
            if best is None or key > best_key:
                best = r
                best_key = key

        return best

    def lookup_type(self, path: str, kind_hint: str = FileKind.ANY) -> str | None:
        """查找路径对应的 type"""
        r = self.lookup(path, kind_hint=kind_hint)
        return r.sel_type if r else None


# =============================================================================
# PortContextIndex 解析器
# =============================================================================

def _parse_port_tokens(tokens: list[str]) -> list[int]:
    """解析端口列表，支持范围表示法（如 80-90）"""
    ports: list[int] = []
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            start_s, end_s = tok.split("-", 1)
            try:
                start = int(start_s)
                end = int(end_s)
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            ports.extend(range(start, end + 1))
        else:
            try:
                ports.append(int(tok))
            except ValueError:
                continue
    return ports


@dataclass
class PortContextIndex:
    """
    解析 portcon 文件，提供 proto/port -> type 映射查询。
    """
    _map: dict[tuple[str, int], list[str]] = field(default_factory=dict, repr=False)

    def __repr__(self):
        return f"PortContextIndex({len(self._map)} entries)"

    @staticmethod
    def load(path: str) -> "PortContextIndex":
        idx = PortContextIndex()
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                if line.lower().startswith("selinux port type"):
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                ty = parts[0]
                proto = parts[1].lower()
                ports_str = " ".join(parts[2:])
                port_tokens = [t.strip() for t in ports_str.split(",")]
                for p in _parse_port_tokens(port_tokens):
                    key = (proto, p)
                    idx._map.setdefault(key, []).append(ty)
        return idx

    def lookup(self, proto: str, port: int) -> list[str]:
        return self._map.get((proto.lower(), port), [])


# =============================================================================
# KnowledgeBase 主类
# =============================================================================

@dataclass
class KnowledgeBase:
    """
    安全知识库。

    启动时加载 policy / fc / port 数据，
    对外暴露统一查询 API。

    使用真实数据源：
    - policy: 使用 setools 解析二进制 policy 文件
    - fc: 内建解析器解析 file_contexts 文本文件
    - portcon: 解析 portcon 文本文件获取端口类型
    """

    # 当前 domain（可选，用于某些查询的上下文）
    current_domain: str = "unconfined_t"

    # setools policy 对象
    _policy: Any = field(default=None, repr=False)

    # file_contexts 索引
    _fc_index: FileContexts | None = field(default=None, repr=False)

    # port context 索引
    _port_index: PortContextIndex | None = field(default=None, repr=False)

    # 自定义规则（允许运行时添加）
    custom_rules: set[tuple[str, str, str, str]] = field(default_factory=set)

    # 自定义端口映射
    custom_port_map: dict[tuple[str, int], str] = field(default_factory=dict)

    @classmethod
    def load(
        cls,
        policy_path: str | None = None,
        fc_path: str | None = None,
        portcon_path: str | None = None,
        current_domain: str = "unconfined_t"
    ) -> "KnowledgeBase":
        """
        从文件加载知识库。

        参数：
        - policy_path: SELinux policy 文件路径（如 policy.30）
        - fc_path: file_contexts 文件路径
        - portcon_path: port context 文件路径
        - current_domain: 默认当前 domain

        返回：
        - 初始化好的 KnowledgeBase 实例
        """
        kb = cls(current_domain=current_domain)

        # 加载 policy
        if policy_path:
            policy_path = os.path.abspath(policy_path)
            if os.path.exists(policy_path):
                try:
                    from setools import SELinuxPolicy
                    kb._policy = SELinuxPolicy(policy_path)
                except ImportError:
                    print(f"警告：无法导入 setools，policy 查询将不可用")
                except Exception as e:
                    print(f"警告：加载 policy 文件失败：{e}")

        # 加载 file_contexts
        if fc_path:
            fc_path = os.path.abspath(fc_path)
            if os.path.exists(fc_path):
                try:
                    kb._fc_index = FileContexts.load(fc_path)
                except Exception as e:
                    print(f"警告：加载 file_contexts 文件失败：{e}")

        # 加载 port context
        if portcon_path:
            portcon_path = os.path.abspath(portcon_path)
            if os.path.exists(portcon_path):
                try:
                    kb._port_index = PortContextIndex.load(portcon_path)
                except Exception as e:
                    print(f"警告：加载 portcon 文件失败：{e}")

        return kb

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
        """
        # 构建查询键
        query = (source_type, target_type, tclass, perm)

        # 检查自定义规则
        if query in self.custom_rules:
            return Decision(
                allowed=True,
                matched_rules=[str(query)],
                reason=f"Matched custom rule: {source_type} -> {target_type}:{tclass} {perm}"
            )

        # 使用 setools 查询 policy
        if self._policy is None:
            return Decision(
                allowed=False,
                matched_rules=[],
                reason=f"Policy not loaded; cannot check {source_type} -> {target_type}:{tclass} {perm}"
            )

        try:
            from setools import TERuleQuery

            q = TERuleQuery(self._policy)
            try:
                q.ruletype = ["allow"]
            except Exception:
                q.ruletype = "allow"

            q.source = source_type
            q.target = target_type
            q.tclass = [tclass]
            try:
                q.perms = {perm}
            except Exception:
                q.perms = [perm]

            rules: list[str] = []
            try:
                for r in q.results():
                    rules.append(str(r))
                    if len(rules) >= 5:
                        break
            except Exception:
                all_rules = list(q)
                rules = [str(r) for r in all_rules[:5]]

            if rules:
                return Decision(
                    allowed=True,
                    matched_rules=rules,
                    reason=f"Found {len(rules)} allow rule(s): {source_type} -> {target_type}:{tclass} {perm}"
                )

        except ImportError:
            return Decision(
                allowed=False,
                matched_rules=[],
                reason=f"setools not available; cannot check {source_type} -> {target_type}:{tclass} {perm}"
            )
        except Exception as e:
            return Decision(
                allowed=False,
                matched_rules=[],
                reason=f"Policy query failed: {e}"
            )

        # 未找到允许规则，默认拒绝
        return Decision(
            allowed=False,
            matched_rules=[],
            reason=f"No allow rule found for {source_type} -> {target_type}:{tclass} {perm}"
        )

    def resolve_port_type(self, proto: str, port: int) -> str | None:
        """
        根据协议和端口号，解析端口对应的 SELinux target type。
        """
        # 优先级：自定义映射 > portcon > 默认
        key = (proto.lower(), port)

        if key in self.custom_port_map:
            return self.custom_port_map[key]

        if self._port_index:
            types = self._port_index.lookup(proto, port)
            if types:
                return types[0]

        return None

    def resolve_path_type(self, path: str, kind_hint: str = FileKind.ANY) -> str | None:
        """
        解析路径在 file_contexts 中对应的 type。
        """
        if self._fc_index is None:
            return None

        return self._fc_index.lookup_type(path, kind_hint=kind_hint)

    def resolve_socket_class(
        self,
        family: str,
        sock_type: str,
        protocol: str | int = 0
    ) -> tuple[str, str]:
        """
        把 socket 参数归一化成 SELinux class 和协议字符串。
        """
        PROTO_MAP = {
            0: "tcp",
            6: "tcp",
            17: "udp",
            132: "sctp",
        }

        if isinstance(protocol, int):
            proto_str = PROTO_MAP.get(protocol, "unknown")
        else:
            proto_str = str(protocol).lower()

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

        return "socket", proto_str if proto_str != "unknown" else "unknown"

    def add_custom_rule(
        self,
        source_type: str,
        target_type: str,
        tclass: str,
        perm: str
    ) -> None:
        """添加自定义规则"""
        self.custom_rules.add((source_type, target_type, tclass, perm))

    def add_custom_port_mapping(self, proto: str, port: int, type_label: str) -> None:
        """添加自定义端口映射"""
        self.custom_port_map[(proto.lower(), port)] = type_label

    def get_policy(self) -> Any | None:
        """获取底层 policy 对象（用于高级查询）"""
        return self._policy
