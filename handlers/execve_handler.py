"""
handlers/execve_handler.py - execve syscall 分析器

功能：
分析 execve(path, argv, envp)。

对应 Linux/SELinux 源码逻辑：
============================
syscall: execve()
  ↓
LSM hook: security_bprm_creds_for_exec()
  ↓
SELinux hook: selinux_bprm_creds_for_exec()
  ↓
具体实现：security/selinux/hooks.c:selinux_bprm_creds_for_exec()
  - 调用 selinux_file_has_perm(bprm->file, FILE__EXECUTE)
  - 检查 domain transition:
    - selinux_compute_av(current_sid(), new_sid, process, PROCESS__TRANSITION)
    - 检查 entrypoint: file_type:entrypoint 权限
    - 检查 execute_no_trans

AVC 四元组构造逻辑：
==================
Check 1 - File execute:
- source_type: 当前 task 的 domain
- target_type: 执行文件的 type（从 file_contexts 解析）
- class: file
- perm: execute

Check 2 - Domain transition (可选):
- source_type: 当前 domain
- target_type: 新 domain（如果有 type_transition）
- class: process
- perm: transition

Check 3 - Entrypoint (可选):
- source_type: 新 domain
- target_type: 执行文件的 type
- class: file
- perm: entrypoint

简化说明：
========
- 第一版主要检查 execute 权限
- domain transition 需要复杂的 policy 查询，暂时简化
- 不处理 no_new_privs 等特殊情况
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


def handle_execve(
    syscall: Syscall,
    state: AnalysisState,
    kb: KnowledgeBase
) -> StepTrace:
    """
    处理 execve() syscall。

    参数：
    - syscall: Syscall 对象，args 应包含 path, argv, envp
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
    path = syscall.args.get("path", "")
    argv = syscall.args.get("argv", [])
    envp = syscall.args.get("envp")

    # =========================================================================
    # 步骤 2: 解析执行文件的 type
    # 使用 file_contexts 查询
    # =========================================================================
    file_type = kb.resolve_path_type(path, kind_hint=FileKind.FILE)
    
    if not file_type:
        # 未找到 file_contexts 匹配，使用默认类型
        file_type = "unlabeled_t"
        state_updates.append(f"警告：无法从 file_contexts 解析 {path} 的类型，使用 {file_type}")
    else:
        state_updates.append(f"文件 {path} -> {file_type}")

    # =========================================================================
    # 步骤 3: Check 1 - File execute 权限检查
    # 参考：security/selinux/hooks.c:selinux_bprm_creds_for_exec()
    #   err = selinux_file_has_perm(bprm->file, FILE__EXECUTE);
    # =========================================================================
    source_type = state.current_domain
    perm_execute = "execute"

    check_execute = AVCCheck(
        syscall_index=syscall.index,
        syscall_name="execve",
        lsm_hook="security_bprm_creds_for_exec",
        selinux_hook="selinux_bprm_creds_for_exec",
        selinux_impl=(
            f"selinux_file_has_perm(bprm->file, FILE__EXECUTE) → "
            f"avc_has_perm(current_sid(), file_sid, file, {perm_execute})"
        ),
        source_type=source_type,
        target_type=file_type,
        tclass="file",
        perm=perm_execute,
        rationale=(
            f"execve({path}) 需要检查执行文件的 execute 权限。"
            f"根据 selinux_bprm_creds_for_exec() 实现，"
            f"需要检查当前 domain ({source_type}) 是否有权限执行 {file_type} 类型的文件。"
            f"四元组：({source_type}, {file_type}, file, {perm_execute})"
        ),
    )

    check_execute.result = kb.is_allowed(source_type, file_type, "file", perm_execute)
    checks.append(check_execute)

    # =========================================================================
    # 步骤 4: Check 2 - execute_no_trans (如果有 domain transition)
    # 在某些情况下，execve 不会导致 domain transition，
    # 此时需要 execute_no_trans 权限
    # =========================================================================
    perm_execute_no_trans = "execute_no_trans"

    check_execute_no_trans = AVCCheck(
        syscall_index=syscall.index,
        syscall_name="execve",
        lsm_hook="security_bprm_creds_for_exec",
        selinux_hook="selinux_bprm_creds_for_exec",
        selinux_impl=(
            f"avc_has_perm(current_sid(), file_sid, file, {perm_execute_no_trans})"
        ),
        source_type=source_type,
        target_type=file_type,
        tclass="file",
        perm=perm_execute_no_trans,
        rationale=(
            f"execve() 在不发生 domain transition 时，"
            f"需要 execute_no_trans 权限。"
            f"四元组：({source_type}, {file_type}, file, {perm_execute_no_trans})"
        ),
    )

    check_execute_no_trans.result = kb.is_allowed(
        source_type, file_type, "file", perm_execute_no_trans
    )
    checks.append(check_execute_no_trans)

    # =========================================================================
    # 步骤 5: Check 3 - entrypoint (如果发生 domain transition)
    # 如果 execve 导致 domain transition，新 domain 需要 entrypoint 权限
    # 这需要查询 policy 中的 type_transition 规则
    # =========================================================================
    # 尝试查询是否有 type_transition 规则
    policy = kb.get_policy()
    new_domain = None
    
    if policy:
        try:
            from setools import TypeTransitionRuleQuery
            
            q = TypeTransitionRuleQuery(policy)
            q.source = source_type
            q.target = file_type
            q.tclass = "file"
            
            transitions = list(q.results())
            if transitions:
                # 找到 transition 规则
                for t in transitions[:1]:  # 取第一个
                    if hasattr(t, 'default_type'):
                        new_domain = str(t.default_type)
                    elif hasattr(t, 'default'):
                        new_domain = str(t.default)
                    break
                
                if new_domain:
                    state_updates.append(f"检测到 domain transition: {source_type} -> {new_domain}")
                    
                    # 检查 entrypoint 权限
                    check_entrypoint = AVCCheck(
                        syscall_index=syscall.index,
                        syscall_name="execve",
                        lsm_hook="security_bprm_creds_for_exec",
                        selinux_hook="selinux_bprm_creds_for_exec",
                        selinux_impl=(
                            f"type_transition {source_type} {file_type}:file -> {new_domain}; "
                            f"avc_has_perm({new_domain}, {file_type}, file, entrypoint)"
                        ),
                        source_type=new_domain,
                        target_type=file_type,
                        tclass="file",
                        perm="entrypoint",
                        rationale=(
                            f"Domain transition 到 {new_domain} 需要 entrypoint 权限。"
                            f"四元组：({new_domain}, {file_type}, file, entrypoint)"
                        ),
                    )
                    
                    check_entrypoint.result = kb.is_allowed(
                        new_domain, file_type, "file", "entrypoint"
                    )
                    checks.append(check_entrypoint)
                    
                    # 检查 process transition 权限
                    check_transition = AVCCheck(
                        syscall_index=syscall.index,
                        syscall_name="execve",
                        lsm_hook="security_bprm_creds_for_exec",
                        selinux_hook="selinux_bprm_creds_for_exec",
                        selinux_impl=(
                            f"avc_has_perm({source_type}, {new_domain}, process, transition)"
                        ),
                        source_type=source_type,
                        target_type=new_domain,
                        tclass="process",
                        perm="transition",
                        rationale=(
                            f"Domain transition 需要 process transition 权限。"
                            f"四元组：({source_type}, {new_domain}, process, transition)"
                        ),
                    )
                    
                    check_transition.result = kb.is_allowed(
                        source_type, new_domain, "process", "transition"
                    )
                    checks.append(check_transition)
                    
        except Exception as e:
            # 查询失败，忽略
            pass

    # =========================================================================
    # 步骤 6: 生成 StepTrace
    # =========================================================================
    denied_checks = [c for c in checks if c.result and not c.result.allowed]

    if denied_checks:
        denied = denied_checks[0]
        summary = (
            f"execve({path}) 被拒绝：{denied.target_type}:{denied.tclass} {denied.perm} "
            f"denied for {denied.source_type}"
        )
    else:
        summary = f"execve({path}) 允许"

    return StepTrace(
        syscall=syscall,
        checks=checks,
        state_updates=state_updates,
        summary=summary,
    )
