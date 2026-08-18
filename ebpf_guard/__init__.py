"""
Kernel-Agent-eBPF: Ring-0 Kernel Syscall Telemetry & Sandbox Guard for AI Agents.
"""

from ebpf_guard.core import (
    CryptographicKernelAuditLedger,
    KernelAgentGuard,
    KernelSyscallReceipt,
    GENESIS_HASH,
)

__all__ = [
    "CryptographicKernelAuditLedger",
    "KernelAgentGuard",
    "KernelSyscallReceipt",
    "GENESIS_HASH",
]

__version__ = "1.0.0"
