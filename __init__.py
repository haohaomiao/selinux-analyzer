# SELinux Syscall Trace Analyzer
# 一个轻量的、面向 syscall 序列的 SELinux 静态分析器

from .engine import AnalyzerEngine
from .knowledge.base import KnowledgeBase
from .models import Syscall, AnalysisState, AnalysisTrace

__version__ = "0.1.0"
__all__ = [
    "AnalyzerEngine",
    "KnowledgeBase",
    "Syscall",
    "AnalysisState",
    "AnalysisTrace",
]
