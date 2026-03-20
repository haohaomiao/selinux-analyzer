"""
engine.py - 主流程驱动层

功能：
顺序驱动整个 SELinux syscall 分析过程。

数据流：
=======
1. 接收 syscall 序列
2. 初始化 AnalysisState
3. 遍历 syscall：
   - 根据 syscall 名称分发到对应 handler
   - 收集 StepTrace
   - 更新状态
4. 汇总 AnalysisTrace
5. 生成整体 summary

简化说明：
========
- 第一版只支持 socket/connect/dup2
- 不支持的 syscall 会生成警告 step
- handler 直接导入，不使用动态加载
"""

from __future__ import annotations

from .models import (
    Syscall,
    AnalysisState,
    AnalysisTrace,
    StepTrace,
)
from .knowledge.base import KnowledgeBase
from .handlers.socket_handler import handle_socket
from .handlers.connect_handler import handle_connect
from .handlers.dup2_handler import handle_dup2


# Handler 注册表
# 格式：syscall_name -> handler 函数
HANDLER_REGISTRY = {
    "socket": handle_socket,
    "connect": handle_connect,
    "dup2": handle_dup2,
}


class AnalyzerEngine:
    """
    SELinux syscall 分析引擎。
    
    用法：
    ====
    kb = KnowledgeBase()
    engine = AnalyzerEngine(kb)
    trace = engine.analyze(syscalls, current_domain="httpd_t")
    """
    
    def __init__(self, kb: KnowledgeBase):
        """
        初始化分析引擎。
        
        参数：
        - kb: KnowledgeBase 实例
        """
        self.kb = kb
        self.handler_registry = HANDLER_REGISTRY.copy()
    
    def analyze(
        self,
        syscalls: list[Syscall],
        current_domain: str = "unconfined_t"
    ) -> AnalysisTrace:
        """
        分析 syscall 序列。
        
        参数：
        - syscalls: Syscall 对象列表
        - current_domain: 当前进程的 SELinux domain
        
        返回：
        - AnalysisTrace 对象，包含完整的分析轨迹
        """
        # 初始化状态
        state = AnalysisState(current_domain=current_domain)
        
        # 存储所有步骤的 trace
        steps: list[StepTrace] = []
        
        # 跟踪是否有拒绝发生
        denied_at_step: int | None = None
        denied_summary: str | None = None
        
        # =====================================================================
        # 主循环：遍历每个 syscall
        # =====================================================================
        for syscall in syscalls:
            # 确保 syscall 的 index 正确
            syscall.index = len(steps)
            
            # 分发到对应的 handler
            handler = self.handler_registry.get(syscall.name)
            
            if handler is None:
                # 不支持的 syscall
                step_trace = StepTrace(
                    syscall=syscall,
                    checks=[],
                    state_updates=[],
                    summary=f"不支持的 syscall: {syscall.name}",
                )
            else:
                # 调用 handler
                step_trace = handler(syscall, state, self.kb)
            
            # 记录步骤
            steps.append(step_trace)
            
            # 检查是否有拒绝
            for check in step_trace.checks:
                if check.result and not check.result.allowed:
                    if denied_at_step is None:
                        denied_at_step = syscall.index
                        denied_summary = step_trace.summary
            
            # 更新 syscall 返回值（如果 handler 没有设置）
            # 这允许后续 syscall 使用正确的 fd
        
        # =====================================================================
        # 生成最终摘要
        # =====================================================================
        if denied_at_step is not None:
            final_summary = (
                f"分析完成：在步骤 {denied_at_step} 检测到 SELinux 拒绝。"
                f" {denied_summary}"
            )
        else:
            final_summary = (
                f"分析完成：所有 {len(steps)} 个 syscall 均未检测到 SELinux 拒绝。"
            )
        
        return AnalysisTrace(
            steps=steps,
            final_summary=final_summary,
        )
    
    def register_handler(self, name: str, handler) -> None:
        """
        注册自定义 handler（用于扩展支持的 syscall）。
        
        参数：
        - name: syscall 名称
        - handler: handler 函数，签名应为 (Syscall, AnalysisState, KnowledgeBase) -> StepTrace
        """
        self.handler_registry[name] = handler
