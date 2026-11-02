"""seccomp-фильтр для bwrap (команда seccomp)."""

import os
import struct
import sys


# Запрещённые системные вызовы (x86_64): отладка чужих процессов, ядро и модули, eBPF/perf,
# io_uring, новый API монтирования, ключи ядра, часы и т. п. Остальное разрешено.
SECCOMP_DENY_X86_64 = {
    "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
    "kexec_load": 246, "kexec_file_load": 320, "bpf": 321, "perf_event_open": 298,
    "userfaultfd": 323, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    "keyctl": 250, "add_key": 248, "request_key": 249,
    "mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161,
    "swapon": 167, "swapoff": 168, "reboot": 169,
    "init_module": 175, "finit_module": 313, "delete_module": 176,
    "acct": 163, "settimeofday": 164, "adjtimex": 159, "clock_settime": 227, "clock_adjtime": 305,
    "iopl": 172, "ioperm": 173, "open_by_handle_at": 304, "lookup_dcookie": 212, "quotactl": 179,
    "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
    "fspick": 433, "mount_setattr": 442,
    "syslog": 103, "pidfd_getfd": 438, "kcmp": 312, "process_madvise": 440,
}


def seccomp_program_x86_64(deny=None):
    """Классический BPF-фильтр для bwrap --seccomp: запрещённые вызовы возвращают EPERM,
    чужая архитектура и x32-вызовы убивают процесс."""
    nums = sorted((deny or SECCOMP_DENY_X86_64).values())
    kill, allow, eperm = 0x80000000, 0x7FFF0000, 0x00050001
    ins = [(0x20, 0, 0, 4),                     # A = архитектура
           (0x15, 1, 0, 0xC000003E),            # x86_64? пропускаем «убить»
           (0x06, 0, 0, kill),
           (0x20, 0, 0, 0),                     # A = номер вызова
           (0x35, 0, 1, 0x40000000),            # номер >= x32? иначе пропускаем «убить»
           (0x06, 0, 0, kill)]
    n = len(nums)
    ins += [(0x15, n - j, 0, nr) for j, nr in enumerate(nums)]
    ins += [(0x06, 0, 0, allow), (0x06, 0, 0, eperm)]
    return b"".join(struct.pack("=HBBI", *i) for i in ins)


def cmd_seccomp(a):
    if os.uname().machine != "x86_64":
        print("seccomp-фильтр поддерживается только на x86_64", file=sys.stderr)
        sys.exit(3)
    unknown = [n for n in a.allow if n not in SECCOMP_DENY_X86_64]
    if unknown:
        print("неизвестные системные вызовы для --allow: " + ", ".join(unknown), file=sys.stderr)
        sys.exit(2)
    deny = {k: v for k, v in SECCOMP_DENY_X86_64.items() if k not in a.allow}
    sys.stdout.buffer.write(seccomp_program_x86_64(deny))
