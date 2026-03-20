#!/usr/bin/env python3
"""
tests/test_analyzer.py - SELinux Analyzer 测试套件

运行测试：
python -m pytest tests/test_analyzer.py -v
或：
python -m unittest tests/test_analyzer.py
"""

import unittest
import sys
from pathlib import Path

# 添加父目录到路径以便导入
sys.path.insert(0, str(Path(__file__).parent.parent))

from selinux_trace_analyzer.models import (
    Syscall,
    AnalysisState,
    SocketObject,
    AVCCheck,
    Decision,
    StepTrace,
    AnalysisTrace,
)
from selinux_trace_analyzer.knowledge.base import KnowledgeBase
from selinux_trace_analyzer.engine import AnalyzerEngine
from selinux_trace_analyzer.handlers.socket_handler import handle_socket
from selinux_trace_analyzer.handlers.connect_handler import handle_connect
from selinux_trace_analyzer.handlers.dup2_handler import handle_dup2


class TestModels(unittest.TestCase):
    """测试数据模型。"""
    
    def test_syscall_creation(self):
        """测试 Syscall 创建。"""
        syscall = Syscall(
            name="socket",
            args={"family": "AF_INET", "type": "SOCK_STREAM", "protocol": 0},
            ret=3,
            index=0,
        )
        self.assertEqual(syscall.name, "socket")
        self.assertEqual(syscall.ret, 3)
        self.assertEqual(syscall.args["family"], "AF_INET")
    
    def test_socket_object(self):
        """测试 SocketObject 创建。"""
        sock = SocketObject(
            id="socket_1",
            family="AF_INET",
            sock_type="SOCK_STREAM",
            protocol="tcp",
            selinux_class="tcp_socket",
            created_by_domain="httpd_t",
        )
        self.assertEqual(sock.id, "socket_1")
        self.assertEqual(sock.selinux_class, "tcp_socket")
        self.assertEqual(sock.kind, "socket")
    
    def test_analysis_state(self):
        """测试 AnalysisState。"""
        state = AnalysisState(current_domain="httpd_t")
        self.assertEqual(state.current_domain, "httpd_t")
        self.assertEqual(len(state.fd_table), 0)
        self.assertEqual(len(state.objects), 0)


class TestKnowledgeBase(unittest.TestCase):
    """测试 KnowledgeBase。"""
    
    def setUp(self):
        self.kb = KnowledgeBase()
    
    def test_resolve_port_type_known(self):
        """测试已知端口类型解析。"""
        self.assertEqual(self.kb.resolve_port_type("tcp", 80), "http_port_t")
        self.assertEqual(self.kb.resolve_port_type("tcp", 443), "https_port_t")
        self.assertEqual(self.kb.resolve_port_type("tcp", 22), "ssh_port_t")
    
    def test_resolve_port_type_unknown(self):
        """测试未知端口类型解析（应返回默认）。"""
        self.assertEqual(self.kb.resolve_port_type("tcp", 4444), "unreserved_port_t")
        self.assertEqual(self.kb.resolve_port_type("tcp", 9999), "unreserved_port_t")
    
    def test_resolve_socket_class_tcp(self):
        """测试 TCP socket class 解析。"""
        cls, proto = self.kb.resolve_socket_class("AF_INET", "SOCK_STREAM", 0)
        self.assertEqual(cls, "tcp_socket")
        self.assertEqual(proto, "tcp")
    
    def test_resolve_socket_class_udp(self):
        """测试 UDP socket class 解析。"""
        cls, proto = self.kb.resolve_socket_class("AF_INET", "SOCK_DGRAM", 17)
        self.assertEqual(cls, "udp_socket")
        self.assertEqual(proto, "udp")
    
    def test_is_allowed_socket_create(self):
        """测试 socket create 权限检查。"""
        result = self.kb.is_allowed("httpd_t", "httpd_t", "tcp_socket", "create")
        self.assertTrue(result.allowed)
    
    def test_is_allowed_name_connect_http(self):
        """测试 HTTP 端口 name_connect 允许。"""
        result = self.kb.is_allowed("httpd_t", "http_port_t", "tcp_socket", "name_connect")
        self.assertTrue(result.allowed)
    
    def test_is_allowed_name_connect_unreserved(self):
        """测试未保留端口 name_connect 拒绝。"""
        result = self.kb.is_allowed("httpd_t", "unreserved_port_t", "tcp_socket", "name_connect")
        self.assertFalse(result.allowed)
    
    def test_custom_rule(self):
        """测试自定义规则。"""
        self.kb.add_custom_rule("httpd_t", "unreserved_port_t", "tcp_socket", "name_connect")
        result = self.kb.is_allowed("httpd_t", "unreserved_port_t", "tcp_socket", "name_connect")
        self.assertTrue(result.allowed)


class TestSocketHandler(unittest.TestCase):
    """测试 socket handler。"""
    
    def setUp(self):
        self.kb = KnowledgeBase()
        self.state = AnalysisState(current_domain="httpd_t")
    
    def test_handle_socket_tcp(self):
        """测试 TCP socket 创建。"""
        syscall = Syscall(
            name="socket",
            args={"family": "AF_INET", "type": "SOCK_STREAM", "protocol": 0},
            ret=3,
            index=0,
        )
        trace = handle_socket(syscall, self.state, self.kb)
        
        # 检查有 AVC 检查
        self.assertEqual(len(trace.checks), 1)
        check = trace.checks[0]
        
        # 检查四元组
        self.assertEqual(check.source_type, "httpd_t")
        self.assertEqual(check.tclass, "tcp_socket")
        self.assertEqual(check.perm, "create")
        
        # 检查允许
        self.assertTrue(check.result.allowed)
        
        # 检查状态更新
        self.assertEqual(len(self.state.fd_table), 1)
        self.assertEqual(self.state.fd_table[3].startswith("socket_"), True)
    
    def test_handle_socket_udp(self):
        """测试 UDP socket 创建。"""
        syscall = Syscall(
            name="socket",
            args={"family": "AF_INET", "type": "SOCK_DGRAM", "protocol": 17},
            ret=4,
            index=0,
        )
        trace = handle_socket(syscall, self.state, self.kb)
        
        check = trace.checks[0]
        self.assertEqual(check.tclass, "udp_socket")


class TestConnectHandler(unittest.TestCase):
    """测试 connect handler。"""
    
    def setUp(self):
        self.kb = KnowledgeBase()
        self.state = AnalysisState(current_domain="httpd_t")
        
        # 先创建一个 socket
        socket_syscall = Syscall(
            name="socket",
            args={"family": "AF_INET", "type": "SOCK_STREAM", "protocol": 0},
            ret=3,
            index=0,
        )
        handle_socket(socket_syscall, self.state, self.kb)
    
    def test_handle_connect_http_allowed(self):
        """测试 HTTP 连接允许。"""
        syscall = Syscall(
            name="connect",
            args={"fd": 3, "ip": "93.184.216.34", "port": 80},
            index=1,
        )
        trace = handle_connect(syscall, self.state, self.kb)
        
        # 应该有 2 个检查：socket connect + name_connect
        self.assertEqual(len(trace.checks), 2)
        
        # 检查 name_connect 允许（80 端口是 http_port_t）
        name_connect_check = trace.checks[1]
        self.assertEqual(name_connect_check.target_type, "http_port_t")
        self.assertTrue(name_connect_check.result.allowed)
    
    def test_handle_connect_unreserved_denied(self):
        """测试未保留端口连接拒绝。"""
        syscall = Syscall(
            name="connect",
            args={"fd": 3, "ip": "10.0.0.1", "port": 4444},
            index=1,
        )
        trace = handle_connect(syscall, self.state, self.kb)
        
        # 检查 name_connect 拒绝
        name_connect_check = trace.checks[1]
        self.assertEqual(name_connect_check.target_type, "unreserved_port_t")
        self.assertFalse(name_connect_check.result.allowed)
        
        # 检查摘要包含拒绝信息
        self.assertIn("拒绝", trace.summary)


class TestDup2Handler(unittest.TestCase):
    """测试 dup2 handler。"""
    
    def setUp(self):
        self.kb = KnowledgeBase()
        self.state = AnalysisState(current_domain="httpd_t")
        
        # 先创建一个 socket
        socket_syscall = Syscall(
            name="socket",
            args={"family": "AF_INET", "type": "SOCK_STREAM", "protocol": 0},
            ret=3,
            index=0,
        )
        handle_socket(socket_syscall, self.state, self.kb)
    
    def test_handle_dup2(self):
        """测试 fd 重映射。"""
        syscall = Syscall(
            name="dup2",
            args={"oldfd": 3, "newfd": 0},
            index=1,
        )
        trace = handle_dup2(syscall, self.state, self.kb)
        
        # 无 AVC 检查
        self.assertEqual(len(trace.checks), 0)
        
        # 检查 fd 映射更新
        self.assertEqual(self.state.fd_table[0], self.state.fd_table[3])
    
    def test_handle_dup2_invalid_fd(self):
        """测试无效 fd。"""
        syscall = Syscall(
            name="dup2",
            args={"oldfd": 999, "newfd": 0},
            index=1,
        )
        trace = handle_dup2(syscall, self.state, self.kb)
        
        # 无状态更新
        self.assertEqual(len(trace.state_updates), 0)
        self.assertIn("失败", trace.summary)


class TestAnalyzerEngine(unittest.TestCase):
    """测试分析引擎。"""
    
    def test_full_reverse_shell_analysis(self):
        """测试完整的 reverse shell 分析。"""
        kb = KnowledgeBase()
        engine = AnalyzerEngine(kb)
        
        syscalls = [
            Syscall(name="socket", args={"family": "AF_INET", "type": "SOCK_STREAM", "protocol": 0}, ret=3, index=0),
            Syscall(name="connect", args={"fd": 3, "ip": "10.0.0.1", "port": 4444}, index=1),
            Syscall(name="dup2", args={"oldfd": 3, "newfd": 0}, index=2),
        ]
        
        trace = engine.analyze(syscalls, current_domain="httpd_t")
        
        # 检查步骤数
        self.assertEqual(len(trace.steps), 3)
        
        # 检查有拒绝
        self.assertIn("拒绝", trace.final_summary)
        
        # 检查 connect 步骤有拒绝
        connect_step = trace.steps[1]
        self.assertFalse(connect_step.checks[1].result.allowed)


if __name__ == "__main__":
    unittest.main()
