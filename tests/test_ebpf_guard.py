import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ebpf_guard.core import KernelAgentGuard, GENESIS_HASH


class TestKernelAgentEBPF(unittest.TestCase):
    def setUp(self):
        self.guard = KernelAgentGuard()
        self.guard.enroll_agent_process(pid=4092, task_id='agent_task_alpha')

    def test_benign_syscall_and_cryptographic_ledger(self):
        # 1. Allowed file open in sandbox
        allowed, receipt = self.guard.evaluate_syscall_event(
            pid=4092,
            syscall_name='sys_enter_openat',
            target_path='/tmp/data_input.json'
        )
        self.assertTrue(allowed)
        self.assertEqual(receipt.status, 'AUTHORIZED_KERNEL_SYSCALL')
        self.assertNotEqual(receipt.signature_hash, GENESIS_HASH)

        # 2. Cryptographic ledger integrity check
        is_valid, err = self.guard.ledger.verify_chain_integrity()
        self.assertTrue(is_valid, f'Kernel ledger chain broken: {err}')

    def test_sandbox_escape_attempt_quarantine(self):
        # Malicious attempt to read host secrets
        allowed, receipt = self.guard.evaluate_syscall_event(
            pid=4092,
            syscall_name='sys_enter_openat',
            target_path='/etc/shadow'
        )
        self.assertFalse(allowed)
        self.assertEqual(receipt.status, 'QUARANTINED_SANDBOX_ESCAPE_ATTEMPT')

    def test_forbidden_syscall_quarantine(self):
        # Kernel privilege escalation probe
        allowed, receipt = self.guard.evaluate_syscall_event(
            pid=4092,
            syscall_name='ptrace',
            target_path=''
        )
        self.assertFalse(allowed)
        self.assertEqual(receipt.status, 'QUARANTINED_FORBIDDEN_SYSCALL')


if __name__ == '__main__':
    unittest.main()
