#!/bin/python3
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.posix.syscall import ql_syscall_fstat, ql_syscall_newfstatat
from qiling.os.posix.const import AT_EMPTY_PATH
from qiling.extensions import pipe
from pwnlib.util.packing import unpack
from collections import namedtuple
import struct

LOC_AFTER_FLAG_READ = 0x4040d5
LOG_AFTER_PRINT_VERDICT = 0x4040ee
FILTER_IN_HEADER_TYPE = [0x5f]
ADDR_HEAP_START = 0x000000f80000000000
ADDR_HEAP_END = 0x000000f80000018000

MemWrite = namedtuple('MemWrite', ['addr', 'value', 'pc'])
SeqItem = namedtuple('SeqItem', ['addr', 'value', 'nextptr', 'header', 'pc'])

# read entire linked-list sequence
def read_full_seq(ql, addr):
    try:
        seq = []
        while addr != 1:
            val, addr = struct.unpack('QQ', ql.mem.read(addr, 16))
            seq.append(val)
    except UcError as ex:
        return []
    return seq

# list to string (print as ascii when possible)
def lst_to_str(lst):
    out = [f"'{chr(v)}'" if 32 <= v < 127 else hex(v) for v in lst]
    return '[' + ','.join(out) + ']'

# print sequence writes and full sequence
def print_seq(ql, seq):
    if len(seq) == 0:
        return
    pc, addr, header = seq[-1].pc, seq[0].addr, seq[0].header
    ql.log.info(f'SEQWR@{pc:#016x}     {addr:#x} <-- ' \
        f'{lst_to_str([i.value for i in seq])} :: {header:#x}')
    ql.log.info(f'        IN {lst_to_str(read_full_seq(ql, addr))}')

# check if 3-writes group could be an item of a sequence
def get_seq_item(fifo3):
    l3 = sorted(fifo3, key=lambda m: m.addr)
    if not (all(l3[i].addr == l3[0].addr + 8*i for i in (1,2)) and
        (l3[0].value in FILTER_IN_HEADER_TYPE and l3[1].value < 256) and
        (l3[2].value == 1 or ADDR_HEAP_START <= l3[2].value <= ADDR_HEAP_END)):
        return None
    fifo3.clear()
    return SeqItem(l3[1].addr, l3[1].value, l3[2].value, l3[0].value, l3[0].pc)

# log sequence writes
cur_seq, wr_fifo3 = [], []
def log_mem_write(ql: Qiling, access: int, addr: int, size: int, value: int) -> None:
    pc = ql.arch.regs.arch_pc

    wr_fifo3.append(MemWrite(addr, value, ql.arch.regs.arch_pc))
    if len(wr_fifo3) < 3:
        return

    # check if 3-write group is a sequence item
    seq_item = get_seq_item(wr_fifo3)
    if seq_item is None:
        wr_fifo3.pop(0)
        return

    # check if we should start a new sequence
    if len(cur_seq) > 0 and seq_item.nextptr != cur_seq[0].addr:
        print_seq(ql, cur_seq)
        cur_seq.clear()

    cur_seq.insert(0, seq_item)


# enable/disable logging
logging_enabled = False
def enable_logging(ql: Qiling) -> None:
    global logging_enabled
    if not logging_enabled:
        ql.hook_mem_write(log_mem_write, begin=ADDR_HEAP_START, end=ADDR_HEAP_END)
        logging_enabled = True

def disable_logging(ql: Qiling) -> None:
    global logging_enabled
    if logging_enabled:
        ql.clear_hooks()
        ql.verbose = QL_VERBOSE.DEFAULT
        logging_enabled = False

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
