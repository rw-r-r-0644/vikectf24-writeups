#!/bin/python3
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.posix.syscall import ql_syscall_fstat, ql_syscall_newfstatat
from qiling.os.posix.const import AT_EMPTY_PATH
from qiling.extensions import pipe
from pwnlib.util.packing import unpack
import struct

LOC_AFTER_FLAG_READ = 0x4040d5
LOG_AFTER_PRINT_VERDICT = 0x4040ee

FILTER_IN_MEM_RANGES = [
    # in principle these may vary, but in practice in Qiling they are deterministic
    (0x000000000000400000, 0x0000000000004d7000),   # ./challenge
#    (0x000000f80000000000, 0x000000f80000018000),   # heap (see initial dynamic analysis)
]
FILTER_OUT_MEM_RANGES = [
    (0x004cfcc0, 0x004cfcc0+0x680),                 # ignore reads/writes to gcState
]


# enable/disable logging
logging_enabled = False
def enable_logging(ql: Qiling) -> None:
    global logging_enabled
    if logging_enabled:
        return
    else:
        logging_enabled = True

    ##################################################
    # Enable these as necessary:
    ##################################################

    # Print current memory map
    #print_memory_map(ql)
    # Log the disassembly of all executed instructions
    #ql.verbose = QL_VERBOSE.DISASM
    # Log memory reads
    #ql.hook_mem_read(log_mem_read)
    # Log memory writes
    #ql.hook_mem_write(log_mem_write)

    ##################################################

def disable_logging(ql: Qiling) -> None:
    global logging_enabled
    if logging_enabled:
        ql.clear_hooks()
        ql.verbose = QL_VERBOSE.DEFAULT
        logging_enabled = False


# log interesting mem writes/reads
def should_log_mem_access(addr):
    return any(s <= addr <= e for s,e in FILTER_IN_MEM_RANGES) \
        and not any(s <= addr <= e for s,e in FILTER_OUT_MEM_RANGES)

encode_chr = lambda v: f"'{chr(v)}' = {v:#x}" if 32 <= v < 127 else f"{v:#x}"
def log_mem_write(ql: Qiling, access: int, addr: int, size: int, value: int) -> None:
    if should_log_mem_access(addr) and size <= 8:
        pc = ql.arch.regs.arch_pc
        ql.log.info(f'MEMWR@{pc:#016x}     *{addr:#x} <-- ' + encode_chr(value))

def log_mem_read(ql: Qiling, access: int, addr: int, size: int, value: int) -> None:
    if should_log_mem_access(addr) and size <= 8:
        pc = ql.arch.regs.arch_pc
        value = unpack(ql.mem.read(addr, size), size*8, endianness='little', sign=False)
        ql.log.info(f'MEMRD@{pc:#016x}     *{addr:#x} --> {encode_chr(value)}')


# print current memory map
def print_memory_map(ql: Qiling) -> None:
    ql.log.info(f'MEMORY MAP@{ql.arch.regs.arch_pc:#016x}:')
    for info_line in ql.mem.get_formatted_mapinfo():
        ql.log.info(info_line)


# newfstatat monkeypatching
def fix_newfstatat(ql: Qiling, dirfd: int, path: int, buf_ptr: int, flags: int):
    if flags & AT_EMPTY_PATH and not ql.os.utils.read_cstring(path):
        return ql_syscall_fstat(ql, dirfd, buf_ptr)
    return ql_syscall_newfstatat(ql, dirfd, path, buf_ptr, flags)


ql = Qiling([r'rootfs/challenge'], r'rootfs', verbose=QL_VERBOSE.DEBUG)
ql.os.set_syscall('newfstatat', fix_newfstatat)

ql.os.stdin = pipe.SimpleInStream(0) # to avoid typing test flag every time
ql.os.stdin.write(b'vikeCTF{ABCDEFGHIJKLMNOPQRSTUVW}\n')

ql.hook_address(enable_logging, LOC_AFTER_FLAG_READ)
ql.hook_address(disable_logging, LOG_AFTER_PRINT_VERDICT)

ql.run()
