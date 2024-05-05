---
title: tcache之攻击mp_及源码分析
date: 2021-09-08 18:48:54
tags:
---

## tcache之攻击mp_
>如果程序强迫只能申请大块的chunk，通过largebin attack，或unsortedbin attack,能将变量修改成较大的值,却难以申请到libc，而本文描述的方法会强制大块的申请也通过tcache进行get，put，这样也就可利用tcache的攻击手法，去申请libc空间

tip:下面源代码来源于glibc2.31
```c
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)

# define MAYBE_INIT_TCACHE() \
  if (__glibc_unlikely (tcache == NULL)) \
    tcache_init();

static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}

void *
__libc_malloc (size_t bytes)
{
  ...
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  // -------------------------check---------------------------------
  if (tc_idx < mp_.tcache_bins
  // -------------------------check---------------------------------
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
  ...//省略的逻辑是通过_int_malloc进行申请的部分
}
libc_hidden_def (__libc_malloc)
```
* 探究下mp_从何而来

```c
# define TCACHE_FILL_COUNT 7
# define TCACHE_MAX_BINS		0x40
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

static struct malloc_par mp_ =
{
  .top_pad = DEFAULT_TOP_PAD,
  .n_mmaps_max = DEFAULT_MMAP_MAX,
  .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
  .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
  .arena_test = NARENAS_FROM_NCORES (1)
#if USE_TCACHE
  ,
  .tcache_count = TCACHE_FILL_COUNT,
  .tcache_bins = TCACHE_MAX_BINS,
  .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
  .tcache_unsorted_limit = 0 /* No limit.  */
#endif
};

//pwndbg> p &mp_
//$2 = (struct malloc_par *) 0x7f41c16bb280 <mp_>

```
* 探究下tcache从何而来

```c
static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
    return;

  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }


  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }

}
```
一些重要的结构体
```c
# define TCACHE_MAX_BINS		64
# define USE_TCACHE 1

typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];//glibc2.27是char型的
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```
当修改过mp_.tcache_bins时free相应chunk一样会进入tcache_put.
### 思路
`不能使用tcache` -> `通过large_bin attack修改mp_.tcache_bins` -> `free相应chunk` -> `修改tcache的相应entries -> malloc`
这个方法是在研究祥云杯2021的一道题pwdPro总结的方法.

